// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	statusUploading = "UPLOADING"
	statusCompleted = "COMPLETED"
	chunkLeaseTTL   = 2 * time.Minute
	chunkReadWindow = 90 * time.Second
)

var (
	fileIDPattern = regexp.MustCompile(`^f_[0-9a-f]{24}$`)
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type FileSession struct {
	FileID         string `json:"file_id"`
	FileName       string `json:"file_name"`
	MimeType       string `json:"mime_type"`
	SourceDevice   string `json:"source_device"`
	TargetDevice   string `json:"target_device"`
	TotalSize      int64  `json:"total_size"`
	BytesWritten   int64  `json:"bytes_written"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	CiphertextMeta string `json:"ciphertext_meta,omitempty"`
	Status         string `json:"status"`
	CreatedAt      int64  `json:"created_at"`
}

type FileManager struct {
	storageDir string
	store      *PGStore
	hub        *Hub
	cfg        *Config
	log        *slog.Logger
}

func NewFileManager(cfg *Config, store *PGStore, hub *Hub, log *slog.Logger) (*FileManager, error) {
	if err := os.MkdirAll(cfg.UploadDir, 0o750); err != nil {
		return nil, err
	}
	return &FileManager{storageDir: cfg.UploadDir, store: store, hub: hub, cfg: cfg, log: log}, nil
}

func generateFileID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "f_" + hex.EncodeToString(b)
}

// diskPath is <uploads>/<user-uuid>/<file-id>.bin. Both parts are validated before use.
func (fm *FileManager) diskPath(userID, fileID string) string {
	return filepath.Join(fm.storageDir, filepath.Base(userID), filepath.Base(fileID)+".bin")
}

func (fm *FileManager) removeFromDisk(userID, fileID string) {
	if err := os.Remove(fm.diskPath(userID, fileID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		fm.log.Warn("file removal failed", "file", fileID, "err", err)
	}
}

func (fm *FileManager) removeUserDir(userID string) {
	_ = os.Remove(filepath.Join(fm.storageDir, filepath.Base(userID))) // only if empty
}

const fileColumns = `file_id, file_name, mime_type, source_device, target_device,
	total_size, bytes_written, expected_sha256, actual_sha256, ciphertext_meta, status, created_at`

func scanFile(row pgx.Row) (*FileSession, error) {
	var s FileSession
	err := row.Scan(&s.FileID, &s.FileName, &s.MimeType, &s.SourceDevice, &s.TargetDevice,
		&s.TotalSize, &s.BytesWritten, &s.ExpectedSHA256, &s.ActualSHA256, &s.CiphertextMeta, &s.Status, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &s, err
}

// loadSession only ever returns files owned by the caller; another account's file ID
// is indistinguishable from a missing one.
func (fm *FileManager) loadSession(ctx context.Context, userID, fileID string) (*FileSession, error) {
	if !fileIDPattern.MatchString(fileID) {
		return nil, ErrNotFound
	}
	return scanFile(fm.store.pool.QueryRow(ctx, `SELECT `+fileColumns+` FROM file_transfers WHERE file_id = $1 AND user_id = $2`, fileID, userID))
}

// POST /v2/files
func (fm *FileManager) HandleInitSession(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req FileSession
	if !readJSON(w, r, &req, 64<<10) {
		return
	}
	req.FileName = cleanLabel(strings.NewReplacer("/", "_", "\\", "_").Replace(req.FileName), 200)
	if req.FileName == "" || req.TotalSize <= 0 {
		writeError(w, http.StatusBadRequest, "file_name and total_size > 0 required")
		return
	}
	if req.TotalSize > fm.cfg.MaxFileSize {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds the %d byte limit", fm.cfg.MaxFileSize))
		return
	}
	if req.SourceDevice == "" {
		req.SourceDevice = "api"
	}
	if req.TargetDevice == "" {
		req.TargetDevice = "*"
	}
	if !validDeviceID(req.SourceDevice) || (req.TargetDevice != "*" && !validDeviceID(req.TargetDevice)) {
		writeError(w, http.StatusBadRequest, "invalid source_device or target_device")
		return
	}
	req.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(req.ExpectedSHA256))
	if req.ExpectedSHA256 != "" && !shaPattern.MatchString(req.ExpectedSHA256) {
		writeError(w, http.StatusBadRequest, "expected_sha256 must be 64 hex characters")
		return
	}
	if len(req.CiphertextMeta) > 8<<10 {
		writeError(w, http.StatusBadRequest, "ciphertext_meta too large")
		return
	}
	if fm.cfg.RequireE2EE && req.CiphertextMeta == "" {
		writeError(w, http.StatusBadRequest, "server requires end-to-end encryption; ciphertext_meta missing")
		return
	}
	// Content is served only as an opaque download; a client-chosen type is never trusted.
	req.MimeType = "application/octet-stream"
	req.FileID = generateFileID()
	req.Status = statusUploading
	req.BytesWritten = 0
	req.CreatedAt = nowMs()

	userDir := filepath.Join(fm.storageDir, filepath.Base(p.User.ID))
	if err := os.MkdirAll(userDir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "storage unavailable")
		return
	}

	// Reserve quota and create the row atomically.
	tx, err := fm.store.pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(r.Context(), `
		UPDATE user_counters SET storage_used = storage_used + $2
		WHERE user_id = $1 AND ($3::bigint = 0 OR storage_used + $2::bigint <= $3::bigint)`, p.User.ID, req.TotalSize, fm.cfg.UserQuota)
	if err != nil {
		fm.log.Error("quota reservation failed", "user", p.User.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusInsufficientStorage, "storage quota exceeded; delete files or wait for retention cleanup")
		return
	}
	if _, err := tx.Exec(r.Context(), `
		INSERT INTO file_transfers (
			file_id, user_id, file_name, mime_type, source_device, target_device,
			total_size, bytes_written, expected_sha256, ciphertext_meta, status, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9,$10,$11,$11)`,
		req.FileID, p.User.ID, req.FileName, req.MimeType, req.SourceDevice, req.TargetDevice,
		req.TotalSize, req.ExpectedSHA256, req.CiphertextMeta, req.Status, req.CreatedAt); err != nil {
		fm.log.Error("file session insert failed", "user", p.User.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f, err := os.OpenFile(fm.diskPath(p.User.ID, req.FileID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		fm.log.Error("staging file create failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to allocate staging file")
		return
	}
	_ = f.Close()
	if err := tx.Commit(r.Context()); err != nil {
		fm.removeFromDisk(p.User.ID, req.FileID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Upload-Offset", "0")
	w.Header().Set("Location", "/v2/files/"+req.FileID)
	writeJSON(w, http.StatusCreated, req)
}

// HEAD /v2/files/{id}
func (fm *FileManager) HandleHead(w http.ResponseWriter, r *http.Request, p *Principal) {
	sess, err := fm.loadSession(r.Context(), p.User.ID, r.PathValue("id"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(sess.BytesWritten, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(sess.TotalSize, 10))
	w.Header().Set("Upload-Status", sess.Status)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// acquireChunkLease takes a short, cluster-wide write lease on an upload. Unlike the v1
// in-memory mutex this works across nodes, and unlike a held row lock it does not pin a
// database connection while a slow client trickles bytes in.
func (fm *FileManager) acquireChunkLease(ctx context.Context, userID, fileID string) (*FileSession, string, error) {
	lease := make([]byte, 8)
	_, _ = rand.Read(lease)
	token := hex.EncodeToString(lease)
	now := nowMs()
	sess, err := scanFile(fm.store.pool.QueryRow(ctx, `
		UPDATE file_transfers SET lock_token = $3, lock_until = $4, updated_at = $5
		WHERE file_id = $1 AND user_id = $2 AND status = 'UPLOADING' AND lock_until < $5
		RETURNING `+fileColumns, fileID, userID, token, now+chunkLeaseTTL.Milliseconds(), now))
	return sess, token, err
}

// PATCH /v2/files/{id}   headers: Upload-Offset: N   body: raw bytes
func (fm *FileManager) HandlePatch(w http.ResponseWriter, r *http.Request, p *Principal) {
	fileID := r.PathValue("id")
	if !fileIDPattern.MatchString(fileID) {
		writeError(w, http.StatusNotFound, "file session not found")
		return
	}
	sess, lease, err := fm.acquireChunkLease(r.Context(), p.User.ID, fileID)
	if errors.Is(err, ErrNotFound) {
		// Missing, completed, or another writer holds the lease: report the real state.
		cur, lerr := fm.loadSession(r.Context(), p.User.ID, fileID)
		switch {
		case lerr != nil:
			writeError(w, http.StatusNotFound, "file session not found")
		case cur.Status == statusCompleted:
			w.Header().Set("Upload-Offset", strconv.FormatInt(cur.BytesWritten, 10))
			w.WriteHeader(http.StatusNoContent)
		case cur.Status != statusUploading:
			writeError(w, http.StatusGone, "upload failed verification; start a new one")
		default:
			w.Header().Set("Upload-Offset", strconv.FormatInt(cur.BytesWritten, 10))
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusLocked, "another request is writing this file")
		}
		return
	}
	if err != nil {
		fm.log.Error("chunk lease failed", "file", fileID, "err", err)
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}
	released := false
	release := func(bytesWritten int64) {
		released = true
		_, _ = fm.store.pool.Exec(context.Background(), `
			UPDATE file_transfers SET bytes_written = $3, lock_token = '', lock_until = 0, updated_at = $4
			WHERE file_id = $1 AND lock_token = $2`, fileID, lease, bytesWritten, nowMs())
	}
	defer func() {
		if !released {
			release(sess.BytesWritten)
		}
	}()

	clientOffset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || clientOffset != sess.BytesWritten {
		w.Header().Set("Upload-Offset", strconv.FormatInt(sess.BytesWritten, 10))
		writeJSON(w, http.StatusConflict, map[string]any{"error": "offset mismatch", "server_offset": sess.BytesWritten})
		return
	}

	// Bound how long one chunk may take so a stalled client cannot hold the lease.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(chunkReadWindow))

	path := fm.diskPath(p.User.ID, fileID)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o640)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "staging file missing")
		return
	}
	if _, err := f.Seek(sess.BytesWritten, io.SeekStart); err != nil {
		_ = f.Close()
		writeError(w, http.StatusInternalServerError, "seek failed")
		return
	}
	want := sess.TotalSize - sess.BytesWritten
	if want > fm.cfg.MaxChunkSize {
		want = fm.cfg.MaxChunkSize
	}
	written, copyErr := io.CopyN(f, r.Body, want)
	if written > 0 {
		if err := f.Sync(); err != nil {
			written = 0 // not durable; make the client resend
		}
	}
	_ = f.Close()
	sess.BytesWritten += written

	if copyErr != nil && copyErr != io.EOF {
		release(sess.BytesWritten)
		fm.log.Info("chunk interrupted", "file", fileID, "received", written, "offset", sess.BytesWritten, "err", copyErr)
		w.Header().Set("Upload-Offset", strconv.FormatInt(sess.BytesWritten, 10))
		writeError(w, http.StatusRequestTimeout, "stream interrupted; resume from Upload-Offset")
		return
	}

	if sess.BytesWritten < sess.TotalSize {
		release(sess.BytesWritten)
		w.Header().Set("Upload-Offset", strconv.FormatInt(sess.BytesWritten, 10))
		writeJSON(w, http.StatusOK, sess)
		return
	}

	// Complete: verify the stored bytes end to end.
	actual, err := computeFileSHA256(path)
	if err != nil {
		release(sess.BytesWritten)
		writeError(w, http.StatusInternalServerError, "checksum computation failed")
		return
	}
	if sess.ExpectedSHA256 != "" && sess.ExpectedSHA256 != actual {
		released = true
		_, _ = fm.store.pool.Exec(context.Background(), `
			WITH bad AS (
				UPDATE file_transfers SET status = 'CORRUPTED', actual_sha256 = $2, bytes_written = $3,
					lock_token = '', lock_until = 0, updated_at = $4
				WHERE file_id = $1 RETURNING user_id, total_size
			)
			UPDATE user_counters c SET storage_used = GREATEST(0, c.storage_used - bad.total_size)
			FROM bad WHERE c.user_id = bad.user_id`, fileID, actual, sess.BytesWritten, nowMs())
		fm.removeFromDisk(p.User.ID, fileID)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"error": "SHA-256 mismatch", "expected": sess.ExpectedSHA256, "actual": actual})
		return
	}

	released = true
	tag, err := fm.store.pool.Exec(context.Background(), `
		UPDATE file_transfers SET status = 'COMPLETED', actual_sha256 = $3, bytes_written = $4,
			lock_token = '', lock_until = 0, updated_at = $5
		WHERE file_id = $1 AND lock_token = $2`, fileID, lease, actual, sess.BytesWritten, nowMs())
	if err != nil || tag.RowsAffected() != 1 {
		writeError(w, http.StatusInternalServerError, "could not finalise upload; retry")
		return
	}
	sess.ActualSHA256 = actual
	sess.Status = statusCompleted

	env := Envelope{
		Type:         TypeFile,
		SourceDevice: sess.SourceDevice,
		TargetDevice: sess.TargetDevice,
		Ciphertext:   sess.CiphertextMeta,
		URL:          "/v2/files/" + sess.FileID,
		FileID:       sess.FileID,
		FileName:     sess.FileName,
		FileSize:     sess.TotalSize,
		FileSHA256:   actual,
	}
	if !fm.cfg.RequireE2EE {
		env.Title = fmt.Sprintf("File: %s (%d bytes)", sess.FileName, sess.TotalSize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := fm.hub.PublishAndPersist(ctx, p.User.ID, &env); err != nil {
		fm.log.Error("file event not stored", "file", fileID, "err", err)
	}
	cancel()

	w.Header().Set("Upload-Offset", strconv.FormatInt(sess.BytesWritten, 10))
	writeJSON(w, http.StatusOK, sess)
}

// GET /v2/files/{id}   (supports Range)
func (fm *FileManager) HandleDownload(w http.ResponseWriter, r *http.Request, p *Principal) {
	fileID := r.PathValue("id")
	sess, err := fm.loadSession(r.Context(), p.User.ID, fileID)
	if err != nil || sess.Status != statusCompleted {
		writeError(w, http.StatusNotFound, "file not ready or not found")
		return
	}
	f, err := os.Open(fm.diskPath(p.User.ID, fileID))
	if err != nil {
		writeError(w, http.StatusNotFound, "file missing on disk")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, asciiFileName(sess.FileName)))
	w.Header().Set("X-Content-SHA256", sess.ActualSHA256)
	w.Header().Set("Cache-Control", "private, no-store")
	http.ServeContent(w, r, "", time.UnixMilli(sess.CreatedAt), f)
}

// GET /v2/files?limit=N   lists the account's recent files.
func (fm *FileManager) HandleList(w http.ResponseWriter, r *http.Request, p *Principal) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := fm.store.pool.Query(r.Context(), `SELECT `+fileColumns+` FROM file_transfers
		WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`, p.User.ID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FileSession, error) {
		s, err := scanFile(row)
		if err != nil {
			return FileSession{}, err
		}
		return *s, nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if list == nil {
		list = []FileSession{}
	}
	writeJSON(w, http.StatusOK, list)
}

// DELETE /v2/files/{id}
func (fm *FileManager) HandleDelete(w http.ResponseWriter, r *http.Request, p *Principal) {
	fileID := r.PathValue("id")
	if !fileIDPattern.MatchString(fileID) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	tag, err := fm.store.pool.Exec(r.Context(), `
		WITH gone AS (
			DELETE FROM file_transfers WHERE file_id = $1 AND user_id = $2 AND lock_until < $3
			RETURNING user_id, total_size
		)
		UPDATE user_counters c SET storage_used = GREATEST(0, c.storage_used - gone.total_size)
		FROM gone WHERE c.user_id = gone.user_id`, fileID, p.User.ID, nowMs())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "file not found or busy")
		return
	}
	fm.removeFromDisk(p.User.ID, fileID)
	w.WriteHeader(http.StatusNoContent)
}

func asciiFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 0x20 && r < 0x7f && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "download.bin"
	}
	return b.String()
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
