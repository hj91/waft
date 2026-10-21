// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	cfg      *Config
	log      *slog.Logger
	store    *PGStore
	broker   *RedisBroker
	hub      *Hub
	files    *FileManager
	limiter  *RedisRateLimiter
	upgrader websocket.Upgrader

	cookieName string
}

func NewServer(cfg *Config, log *slog.Logger, store *PGStore, broker *RedisBroker, hub *Hub, files *FileManager) *Server {
	s := &Server{
		cfg:     cfg,
		log:     log,
		store:   store,
		broker:  broker,
		hub:     hub,
		files:   files,
		limiter: &RedisRateLimiter{client: broker.client, log: log},
	}
	s.cookieName = "waft_session"
	if cfg.CookieSecure {
		s.cookieName = "__Host-waft_session" // browser enforces Secure, Path=/ and no Domain
	}
	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		// Cookie-authenticated upgrades must come from an allowed origin (prevents
		// cross-site WebSocket hijacking). Bearer-token clients are not browsers.
		CheckOrigin: func(r *http.Request) bool {
			return bearerToken(r) != "" || s.originAllowed(r)
		},
	}
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v2/auth/config", s.handleAuthConfig)
	mux.HandleFunc("POST /v2/auth/register", s.csrf(s.handleRegister))
	mux.HandleFunc("POST /v2/auth/login", s.csrf(s.handleLogin))
	mux.HandleFunc("POST /v2/auth/logout", s.csrf(s.handleLogout))

	// Account
	mux.HandleFunc("GET /v2/me", s.authed(s.handleMe))
	mux.HandleFunc("PATCH /v2/me", s.authed(s.handleUpdateMe))
	mux.HandleFunc("PUT /v2/me/e2ee-check", s.authed(s.handleSetE2EECheck))
	mux.HandleFunc("POST /v2/me/password", s.authed(s.handleChangePassword))
	mux.HandleFunc("POST /v2/me/delete", s.authed(s.handleDeleteAccount))
	mux.HandleFunc("POST /v2/auth/logout-all", s.authed(s.handleLogoutAll))
	mux.HandleFunc("GET /v2/sessions", s.authed(s.handleListSessions))
	mux.HandleFunc("DELETE /v2/sessions/{id}", s.authed(s.handleDeleteSession))
	mux.HandleFunc("GET /v2/tokens", s.authed(s.handleListTokens))
	mux.HandleFunc("POST /v2/tokens", s.authed(s.handleCreateToken))
	mux.HandleFunc("DELETE /v2/tokens/{id}", s.authed(s.handleDeleteToken))
	mux.HandleFunc("GET /v2/audit", s.authed(s.handleAudit))

	// Messaging
	mux.HandleFunc("GET /v2/stream", s.authed(s.handleStream))
	mux.HandleFunc("GET /v2/pushes", s.authed(s.handleListPushes))
	mux.HandleFunc("POST /v2/pushes", s.authed(s.handleCreatePush))
	mux.HandleFunc("GET /v2/devices", s.authed(s.handleListDevices))
	mux.HandleFunc("PATCH /v2/devices/{id}", s.authed(s.handleRenameDevice))
	mux.HandleFunc("DELETE /v2/devices/{id}", s.authed(s.handleDeleteDevice))

	// Files
	mux.HandleFunc("GET /v2/files", s.authed(s.files.HandleList))
	mux.HandleFunc("POST /v2/files", s.authed(s.files.HandleInitSession))
	mux.HandleFunc("HEAD /v2/files/{id}", s.authed(s.files.HandleHead))
	mux.HandleFunc("PATCH /v2/files/{id}", s.authed(s.files.HandlePatch))
	mux.HandleFunc("GET /v2/files/{id}", s.authed(s.files.HandleDownload))
	mux.HandleFunc("DELETE /v2/files/{id}", s.authed(s.files.HandleDelete))

	// Web app (embedded, so the binary is self-contained)
	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})

	return s.recoverer(s.requestLog(s.securityHeaders(mux)))
}

// --- Middleware ---

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Waft-Node", s.cfg.NodeID)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "+
			"img-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'; "+
			"form-action 'self'; frame-ancestors 'none'")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Hijack keeps WebSocket upgrades working through the recorder.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	r.status = http.StatusSwitchingProtocols
	return hj.Hijack()
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		level := slog.LevelDebug
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelInfo
		}
		s.log.Log(r.Context(), level, "http",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.bytes, "dur_ms", time.Since(start).Milliseconds(), "ip", s.clientIP(r))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic in handler", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// csrf protects unauthenticated state-changing endpoints (login, register, logout).
// The custom header cannot be sent cross-origin without a CORS preflight, which this
// server never grants, and the Origin header must match.
func (s *Server) csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Waft-CSRF") == "" || !s.originAllowed(r) {
			writeError(w, http.StatusForbidden, "cross-site request blocked")
			return
		}
		h(w, r)
	}
}

// authed resolves the caller and applies CSRF rules to cookie-authenticated requests.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.log.Error("authentication backend error", "err", err)
				writeError(w, http.StatusServiceUnavailable, "authentication unavailable")
				return
			}
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if p.CredKind == "session" {
			unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			if !s.originAllowed(r) || (unsafe && r.Header.Get("X-Waft-CSRF") == "") {
				writeError(w, http.StatusForbidden, "cross-site request blocked")
				return
			}
		}
		h(w, r, p)
	}
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func (s *Server) authenticate(r *http.Request) (*Principal, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if tok := bearerToken(r); tok != "" {
		if !strings.HasPrefix(tok, apiTokenPrefix) {
			return nil, ErrNotFound
		}
		u, tokenID, err := s.store.LookupAPIToken(ctx, digestSecret(tok))
		if err != nil {
			return nil, err
		}
		if u.Disabled {
			return nil, ErrNotFound
		}
		return &Principal{User: u, CredKind: "token", CredID: "t:" + tokenID}, nil
	}

	c, err := r.Cookie(s.cookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNotFound
	}
	digest := digestSecret(c.Value)
	u, err := s.store.LookupSession(ctx, digest)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrNotFound
	}
	return &Principal{User: u, CredKind: "session", CredID: sessionCredID(digest)}, nil
}

func sessionCredID(digest []byte) string {
	return fmt.Sprintf("s:%x", digest[:8])
}

// originAllowed accepts requests without an Origin header (non-browser clients), the
// server's own origin, and any origin listed in -allowed-origins.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	o := strings.ToLower(strings.TrimRight(origin, "/"))
	for _, allowed := range s.cfg.AllowedOrigins {
		if o == allowed {
			return true
		}
	}
	return false
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes a size-limited JSON body into dst.
func readJSON(w http.ResponseWriter, r *http.Request, dst any, max int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "unexpected data after JSON body")
		return false
	}
	return true
}

// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "node_id": s.cfg.NodeID})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status, code := map[string]string{"node_id": s.cfg.NodeID, "postgres": "ok", "redis": "ok"}, http.StatusOK
	if err := s.store.Ping(ctx); err != nil {
		status["postgres"], code = "down", http.StatusServiceUnavailable
	}
	if err := s.broker.Ping(ctx); err != nil {
		status["redis"], code = "down", http.StatusServiceUnavailable
	}
	writeJSON(w, code, status)
}
