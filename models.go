// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

// --- Wire protocol ---

type EnvelopeType string

const (
	TypePush         EnvelopeType = "push"
	TypeClip         EnvelopeType = "clip"
	TypeMirror       EnvelopeType = "mirror"
	TypeFile         EnvelopeType = "file"
	TypeDismiss      EnvelopeType = "dismiss"
	TypePresence     EnvelopeType = "presence"
	TypeSyncComplete EnvelopeType = "sync_complete"
	TypeHeartbeat    EnvelopeType = "heartbeat"
	TypeError        EnvelopeType = "error"

	// typeRevoke is an internal cluster control message. It is never persisted or sent to
	// clients. Body carries the credential ID to disconnect, or "*" for every connection
	// of the account.
	typeRevoke EnvelopeType = "_revoke"
	// typeEvict tells other nodes that SourceDevice reconnected at CreatedAt (internal).
	typeEvict EnvelopeType = "_evict"
)

// clientWritable lists the event types a client may originate. "file" events are only
// produced by the server after a verified upload; control types are server-only.
var clientWritable = map[EnvelopeType]bool{
	TypePush:    true,
	TypeClip:    true,
	TypeMirror:  true,
	TypeDismiss: true,
}

// Envelope is the frame exchanged over WebSocket and REST. seq_id is a per-account
// monotonic sequence: every account has its own gap-free numbering starting at 1.
type Envelope struct {
	SeqID        int64        `json:"seq_id"`
	Type         EnvelopeType `json:"type"`
	SourceDevice string       `json:"source_device"`
	TargetDevice string       `json:"target_device"` // "*" for all of the account's devices
	Ciphertext   string       `json:"ciphertext,omitempty"`
	Title        string       `json:"title,omitempty"`
	Body         string       `json:"body,omitempty"`
	URL          string       `json:"url,omitempty"`
	AppName      string       `json:"app_name,omitempty"`
	Notification string       `json:"notification_id,omitempty"`
	FileID       string       `json:"file_id,omitempty"`
	FileName     string       `json:"file_name,omitempty"`
	FileSize     int64        `json:"file_size,omitempty"`
	FileSHA256   string       `json:"file_sha256,omitempty"`
	Cursor       int64        `json:"cursor,omitempty"` // sync_complete only: authoritative resume cursor
	CreatedAt    int64        `json:"created_at"`
}

// visibleTo reports whether a device should receive the event.
func (e *Envelope) visibleTo(deviceID string) bool {
	return e.TargetDevice == "*" || e.TargetDevice == deviceID || e.SourceDevice == deviceID
}

type DeviceInfo struct {
	DeviceID  string `json:"device_id"`
	Nickname  string `json:"nickname"`
	Platform  string `json:"platform"`
	Online    bool   `json:"online"`
	LastSeen  int64  `json:"last_seen"`
	Connected int64  `json:"connected_at,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// --- Accounts ---

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Role         string `json:"role"`
	E2EESalt     string `json:"e2ee_salt"`
	E2EECheck    string `json:"e2ee_check"`
	CreatedAt    int64  `json:"created_at"`
	Disabled     bool   `json:"-"`
	PasswordHash string `json:"-"`
}

type APIToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

type SessionInfo struct {
	ID         string `json:"id"` // first 16 hex chars of the hashed token; safe to show
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
	ExpiresAt  int64  `json:"expires_at"`
	UserAgent  string `json:"user_agent"`
	IP         string `json:"ip"`
	Current    bool   `json:"current"`
}

// Principal is the authenticated caller of a request.
type Principal struct {
	User     *User
	CredKind string // "session" | "token"
	CredID   string // session ID (short hash) or token UUID
}
