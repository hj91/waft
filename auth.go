// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/hj91/waft/pkg/e2ee"
)

const authBodyLimit = 16 << 10

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func normaliseEmail(raw string) (string, bool) {
	email := strings.TrimSpace(raw)
	if len(email) > 254 {
		return "", false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || !strings.Contains(email[strings.LastIndex(email, "@"):], ".") {
		return "", false
	}
	return strings.ToLower(email), true
}

// issueSession creates a session row and sets the cookie.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, userID string) error {
	secret, digest, err := newSecret()
	if err != nil {
		return err
	}
	if err := s.store.CreateSession(r.Context(), digest, userID, s.cfg.SessionTTL, r.UserAgent(), s.clientIP(r)); err != nil {
		return err
	}
	s.setSessionCookie(w, secret, int(s.cfg.SessionTTL.Seconds()))
	return nil
}

type meResponse struct {
	*User
	StorageUsed  int64 `json:"storage_used"`
	StorageQuota int64 `json:"storage_quota"`
	MaxFileSize  int64 `json:"max_file_size"`
	MaxDevices   int   `json:"max_devices"`
	KDFIter      int   `json:"kdf_iterations"`
	RequireE2EE  bool  `json:"require_e2ee"`
}

func (s *Server) meFor(ctx context.Context, u *User) meResponse {
	used, _ := s.store.StorageUsed(ctx, u.ID)
	return meResponse{
		User:         u,
		StorageUsed:  used,
		StorageQuota: s.cfg.UserQuota,
		MaxFileSize:  s.cfg.MaxFileSize,
		MaxDevices:   s.cfg.MaxDevicesPerUser,
		KDFIter:      e2ee.KDFIterations,
		RequireE2EE:  s.cfg.RequireE2EE,
	}
}

func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"allow_signup":        s.cfg.AllowSignup,
		"min_password_length": minPasswordLen,
		"require_e2ee":        s.cfg.RequireE2EE,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowSignup {
		writeError(w, http.StatusForbidden, "registration is disabled on this server")
		return
	}
	ip := s.clientIP(r)
	if !s.limiter.Allow(r.Context(), "register:ip:"+ip, 10, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "too many registrations from this address; try later")
		return
	}
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	email, ok := normaliseEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "a valid email address is required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	display := cleanLabel(req.DisplayName, 64)
	if display == "" {
		display = email[:strings.Index(email, "@")]
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	salt, err := newE2EESalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	u, err := s.store.CreateUser(r.Context(), email, display, hash, salt)
	if errors.Is(err, ErrConflict) {
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}
	if err != nil {
		s.log.Error("create user failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.store.Audit(r.Context(), u.ID, "account.created", ip, r.UserAgent(), "")
	if err := s.issueSession(w, r, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.log.Info("account created", "user", u.ID, "role", u.Role)
	writeJSON(w, http.StatusCreated, s.meFor(r.Context(), u))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	ip := s.clientIP(r)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !s.limiter.Allow(r.Context(), "login:ip:"+ip, 30, 15*time.Minute) ||
		!s.limiter.Allow(r.Context(), "login:email:"+email, 20, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts; wait 15 minutes")
		return
	}

	u, err := s.store.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	hash := dummyHash
	if u != nil {
		hash = u.PasswordHash
	}
	ok, rehash, _ := verifyPassword(req.Password, hash)
	if u == nil || !ok || u.Disabled {
		uid := ""
		if u != nil {
			uid = u.ID
		}
		s.store.Audit(r.Context(), uid, "login.failed", ip, r.UserAgent(), "")
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if rehash {
		if h, err := hashPassword(req.Password); err == nil {
			s.store.RehashPassword(r.Context(), u.ID, h)
		}
	}
	s.limiter.Reset(r.Context(), "login:email:"+email)
	if err := s.issueSession(w, r, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.store.Audit(r.Context(), u.ID, "login.succeeded", ip, r.UserAgent(), "")
	writeJSON(w, http.StatusOK, s.meFor(r.Context(), u))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.cookieName); err == nil && c.Value != "" {
		digest := digestSecret(c.Value)
		if u, err := s.store.LookupSession(r.Context(), digest); err == nil {
			s.hub.RevokeCredential(r.Context(), u.ID, sessionCredID(digest))
			s.store.Audit(r.Context(), u.ID, "logout", s.clientIP(r), r.UserAgent(), "")
		}
		_ = s.store.DeleteSession(r.Context(), digest)
	}
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.store.DeleteUserSessions(r.Context(), p.User.ID, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.hub.RevokeCredential(r.Context(), p.User.ID, "s:*")
	s.store.Audit(r.Context(), p.User.ID, "logout.all", s.clientIP(r), r.UserAgent(), "")
	if p.CredKind == "session" {
		s.setSessionCookie(w, "", -1)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, s.meFor(r.Context(), p.User))
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	name := cleanLabel(req.DisplayName, 64)
	if name == "" {
		writeError(w, http.StatusBadRequest, "display_name required")
		return
	}
	if err := s.store.UpdateProfile(r.Context(), p.User.ID, name); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	p.User.DisplayName = name
	writeJSON(w, http.StatusOK, s.meFor(r.Context(), p.User))
}

func (s *Server) handleSetE2EECheck(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Check string `json:"check"`
		Force bool   `json:"force"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	if req.Check == "" || len(req.Check) > 512 {
		writeError(w, http.StatusBadRequest, "check required")
		return
	}
	set, err := s.store.SetE2EECheck(r.Context(), p.User.ID, req.Check, req.Force)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !set {
		writeError(w, http.StatusConflict, "a key check is already set; pass force to replace it")
		return
	}
	if req.Force {
		s.store.Audit(r.Context(), p.User.ID, "e2ee.key_check_replaced", s.clientIP(r), r.UserAgent(), "")
	}
	w.WriteHeader(http.StatusNoContent)
}

// requirePassword re-verifies the account password for sensitive operations.
func (s *Server) requirePassword(w http.ResponseWriter, r *http.Request, p *Principal, password string) bool {
	if !s.limiter.Allow(r.Context(), "reauth:user:"+p.User.ID, 10, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts; wait 15 minutes")
		return false
	}
	ok, _, _ := verifyPassword(password, p.User.PasswordHash)
	if !ok {
		s.store.Audit(r.Context(), p.User.ID, "reauth.failed", s.clientIP(r), r.UserAgent(), "")
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return false
	}
	return true
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	if !s.requirePassword(w, r, p, req.Current) {
		return
	}
	if err := validatePassword(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := hashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.UpdatePassword(r.Context(), p.User.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Every other browser session is signed out; API tokens are separate credentials and
	// are managed explicitly on the tokens page.
	var keep []byte
	if p.CredKind == "session" {
		if c, err := r.Cookie(s.cookieName); err == nil {
			keep = digestSecret(c.Value)
		}
	}
	_ = s.store.DeleteUserSessions(r.Context(), p.User.ID, keep)
	if keep != nil {
		s.hub.RevokeCredential(r.Context(), p.User.ID, "s:*!"+sessionCredID(keep))
	} else {
		s.hub.RevokeCredential(r.Context(), p.User.ID, "s:*")
	}
	s.store.Audit(r.Context(), p.User.ID, "password.changed", s.clientIP(r), r.UserAgent(), "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	if !s.requirePassword(w, r, p, req.Password) {
		return
	}
	fileIDs, err := s.store.DeleteUser(r.Context(), p.User.ID)
	if err != nil {
		s.log.Error("delete account failed", "user", p.User.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	for _, id := range fileIDs {
		s.files.removeFromDisk(p.User.ID, id)
	}
	s.files.removeUserDir(p.User.ID)
	s.hub.RevokeCredential(r.Context(), p.User.ID, "*")
	s.log.Info("account deleted", "user", p.User.ID, "files", len(fileIDs))
	if p.CredKind == "session" {
		s.setSessionCookie(w, "", -1)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, p *Principal) {
	list, err := s.store.ListSessions(r.Context(), p.User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	for i := range list {
		list[i].Current = p.CredKind == "session" && "s:"+list[i].ID == p.CredID
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if len(id) != 16 {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	ok, err := s.store.DeleteSessionByID(r.Context(), p.User.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	s.hub.RevokeCredential(r.Context(), p.User.ID, "s:"+id)
	s.store.Audit(r.Context(), p.User.ID, "session.revoked", s.clientIP(r), r.UserAgent(), id)
	w.WriteHeader(http.StatusNoContent)
}

// --- API tokens ---

const maxTokensPerUser = 50

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, p *Principal) {
	list, err := s.store.ListAPITokens(r.Context(), p.User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if list == nil {
		list = []APIToken{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	// Tokens can only be minted from an interactive session, never by another token.
	if p.CredKind != "session" {
		writeError(w, http.StatusForbidden, "API tokens can only be created from a signed-in browser session")
		return
	}
	var req struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if !readJSON(w, r, &req, authBodyLimit) {
		return
	}
	name := cleanLabel(req.Name, 64)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > 3650 {
		writeError(w, http.StatusBadRequest, "expires_in_days must be 0 (never) to 3650")
		return
	}
	if n, err := s.store.CountAPITokens(r.Context(), p.User.ID); err != nil || n >= maxTokensPerUser {
		writeError(w, http.StatusConflict, "token limit reached; revoke unused tokens first")
		return
	}
	secret, _, err := newSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token := apiTokenPrefix + secret
	var expires int64
	if req.ExpiresInDays > 0 {
		expires = time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour).UnixMilli()
	}
	t, err := s.store.CreateAPIToken(r.Context(), p.User.ID, name, digestSecret(token), token[:len(apiTokenPrefix)+6], expires)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.store.Audit(r.Context(), p.User.ID, "token.created", s.clientIP(r), r.UserAgent(), name)
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "info": t})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	ok, err := s.store.DeleteAPIToken(r.Context(), p.User.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	s.hub.RevokeCredential(r.Context(), p.User.ID, "t:"+id)
	s.store.Audit(r.Context(), p.User.ID, "token.revoked", s.clientIP(r), r.UserAgent(), id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p *Principal) {
	list, err := s.store.ListAudit(r.Context(), p.User.ID, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if list == nil {
		list = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, list)
}
