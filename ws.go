// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 25 * time.Second
	pingPeriod     = (pongWait * 7) / 10 // 17.5s, strictly below pongWait
	maxMessageSize = 128 * 1024
	sendBufSize    = 256

	// Inbound flood control per connection: sustained rate and burst.
	inboundRate  = 20.0
	inboundBurst = 40.0
)

type ClientConn struct {
	hub         *Hub
	conn        *websocket.Conn
	userID      string
	credID      string
	deviceID    string
	nickname    string
	platform    string
	remoteIP    string
	connectedAt int64

	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeCode int
	closeText string

	mu       sync.Mutex
	lastSeq  int64
	syncing  bool
	again    bool
	dirtyMax int64

	tokens   float64
	tokensAt time.Time
}

func (c *ClientConn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// closeWith shuts the connection down once. The send channel is never closed (writers
// select on done instead), which removes the send-on-closed-channel panic of v1.
func (c *ClientConn) closeWith(code int, reason string) {
	c.closeOnce.Do(func() {
		c.closeCode, c.closeText = code, reason
		close(c.done)
		// Best effort close frame; the write pump may be blocked, so use a control write.
		_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = c.conn.Close()
		go c.hub.Unregister(c)
	})
}

// allowInbound is a token bucket guarding against a client flooding the database.
func (c *ClientConn) allowInbound() bool {
	now := time.Now()
	c.tokens += now.Sub(c.tokensAt).Seconds() * inboundRate
	if c.tokens > inboundBurst {
		c.tokens = inboundBurst
	}
	c.tokensAt = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

func (c *ClientConn) sendControl(t EnvelopeType, body string) {
	raw, _ := json.Marshal(Envelope{Type: t, Body: body, CreatedAt: nowMs()})
	select {
	case c.send <- raw:
	default:
	}
}

func (c *ClientConn) readPump(s *Server) {
	defer c.closeWith(1000, "")

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				s.log.Debug("unexpected websocket close", "device", c.deviceID, "err", err)
			}
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))

		var in Envelope
		if err := json.Unmarshal(message, &in); err != nil {
			c.sendControl(TypeError, "malformed frame")
			continue
		}
		if in.Type == TypeHeartbeat {
			c.sendControl(TypeHeartbeat, "pong")
			continue
		}
		if !c.allowInbound() {
			c.sendControl(TypeError, "rate limited")
			continue
		}
		if err := s.sanitizeClientEvent(&in, c.deviceID); err != nil {
			c.sendControl(TypeError, err.Error())
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = c.hub.PublishAndPersist(ctx, c.userID, &in)
		cancel()
		if err != nil {
			s.log.Error("persist event failed", "user", c.userID, "device", c.deviceID, "err", err)
			c.sendControl(TypeError, "event not stored; retry")
		}
	}
}

func (c *ClientConn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.closeWith(1006, "write failed")
	}()

	hb, _ := json.Marshal(Envelope{Type: TypeHeartbeat, Body: "ping"})
	for {
		select {
		case <-c.done:
			return
		case message := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
			// Application heartbeat for clients (browsers) that cannot see ping frames.
			if err := c.conn.WriteMessage(websocket.TextMessage, hb); err != nil {
				return
			}
		}
	}
}

var errInvalidEvent = errors.New("invalid event")

// sanitizeClientEvent validates and normalises an event originated by a client. The
// server owns seq_id, created_at and source_device; clients cannot forge control frames.
func (s *Server) sanitizeClientEvent(e *Envelope, sourceDevice string) error {
	if !clientWritable[e.Type] {
		return errors.New("event type not allowed")
	}
	e.SeqID = 0
	e.Cursor = 0
	e.CreatedAt = nowMs()
	e.SourceDevice = sourceDevice
	e.FileID, e.FileName, e.FileSize, e.FileSHA256 = "", "", 0, ""
	if e.TargetDevice == "" {
		e.TargetDevice = "*"
	}
	if e.TargetDevice != "*" && !validDeviceID(e.TargetDevice) {
		return errors.New("invalid target_device")
	}
	if len(e.Ciphertext) > 96*1024 || len(e.Notification) > 256 || len(e.AppName) > 256 {
		return errors.New("field too large")
	}
	plaintext := e.Title != "" || e.Body != "" || e.URL != ""
	if s.cfg.RequireE2EE {
		if plaintext {
			return errors.New("server requires end-to-end encryption; send ciphertext only")
		}
		if e.Ciphertext == "" && e.Type != TypeDismiss {
			return errors.New("ciphertext required")
		}
		e.AppName = "" // app names are metadata too; carry them inside the ciphertext
	}
	if len(e.Title) > 1024 || len(e.Body) > 16*1024 || len(e.URL) > 4096 {
		return errors.New("field too large")
	}
	if !utf8.ValidString(e.Title + e.Body + e.URL + e.AppName + e.Notification) {
		return errInvalidEvent
	}
	return nil
}

// validDeviceID allows 1-64 characters from [A-Za-z0-9._:-].
func validDeviceID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id == "*" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == ':':
		default:
			return false
		}
	}
	return true
}

func cleanLabel(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// handleStream upgrades an authenticated request to the event stream:
//
//	GET /v2/stream?device_id=..&nickname=..&platform=..&last_seq=N
//
// Browsers authenticate with the session cookie (Origin is checked to stop cross-site
// WebSocket hijacking); CLI and daemons send "Authorization: Bearer <token>".
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, p *Principal) {
	q := r.URL.Query()
	deviceID := strings.TrimSpace(q.Get("device_id"))
	if !validDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "device_id must be 1-64 chars of [A-Za-z0-9._:-]")
		return
	}
	nickname := cleanLabel(q.Get("nickname"), 64)
	if nickname == "" {
		nickname = deviceID
	}
	platform := cleanLabel(q.Get("platform"), 32)
	if platform == "" {
		platform = "unknown"
	}
	lastSeq, _ := strconv.ParseInt(q.Get("last_seq"), 10, 64)
	if lastSeq < 0 {
		lastSeq = 0
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade has already written the HTTP error
	}

	c := &ClientConn{
		hub:         s.hub,
		conn:        conn,
		userID:      p.User.ID,
		credID:      p.CredID,
		deviceID:    deviceID,
		nickname:    nickname,
		platform:    platform,
		remoteIP:    s.clientIP(r),
		connectedAt: nowMs(),
		send:        make(chan []byte, sendBufSize),
		done:        make(chan struct{}),
		lastSeq:     lastSeq,
		syncing:     true, // live events are held back until the initial replay completes
		tokens:      inboundBurst,
		tokensAt:    time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = s.hub.Register(ctx, c)
	cancel()
	if err != nil {
		code, msg := 1011, "registration failed"
		if errors.Is(err, ErrDeviceLimit) {
			code, msg = 4003, "device limit reached; remove a device in settings"
		}
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, msg), time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}

	go c.writePump()
	go c.readPump(s)
	// Registered (and subscribed) before the snapshot is read, so nothing committed after
	// the snapshot can be missed: it either arrives live or marks the connection dirty.
	c.mu.Lock()
	c.startSyncLocked(true)
	c.mu.Unlock()
}
