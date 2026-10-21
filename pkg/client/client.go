// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

// Package client is the shared Waft v2 API client used by the waft CLI and waftd daemon.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hj91/waft/pkg/e2ee"
)

// Client talks to a Waft server with an API token.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Me mirrors GET /v2/me.
type Me struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	E2EESalt    string `json:"e2ee_salt"`
	E2EECheck   string `json:"e2ee_check"`
	MaxFileSize int64  `json:"max_file_size"`
}

// Device mirrors an entry of GET /v2/devices.
type Device struct {
	DeviceID string `json:"device_id"`
	Nickname string `json:"nickname"`
	Platform string `json:"platform"`
	Online   bool   `json:"online"`
	LastSeen int64  `json:"last_seen"`
}

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Status, e.Message) }

// ResolveSecret returns the first non-empty value of: flag, file named by fileFlag, env var.
// Secrets passed as flags are visible in the process list, so files or env are preferred.
func ResolveSecret(flagVal, fileFlag, envKey string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if fileFlag != "" {
		b, err := os.ReadFile(fileFlag)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(envKey)), nil
}

// New validates the base URL and token.
func New(baseURL, token string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, errors.New("server URL must start with http:// or https://")
	}
	if !strings.HasPrefix(token, "gpt_") {
		return nil, errors.New("an API token (gpt_...) is required; create one in the web app under Settings > API tokens")
	}
	return &Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}, nil
}

// WSURL converts the base URL to the WebSocket endpoint.
func (c *Client) WSURL(path string) string {
	u := c.BaseURL
	if strings.HasPrefix(u, "https://") {
		u = "wss://" + strings.TrimPrefix(u, "https://")
	} else {
		u = "ws://" + strings.TrimPrefix(u, "http://")
	}
	return u + path
}

// AuthHeader returns headers carrying the bearer token.
func (c *Client) AuthHeader() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+c.Token)
	return h
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "waft-client/2")
	return req, nil
}

// Do sends a request and returns the response; non-2xx statuses become *APIError.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(raw, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return resp, &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	return resp, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Me(ctx context.Context) (*Me, error) {
	var me Me
	return &me, c.doJSON(ctx, http.MethodGet, "/v2/me", nil, &me)
}

func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var d []Device
	return d, c.doJSON(ctx, http.MethodGet, "/v2/devices", nil, &d)
}

// DeriveKey derives the account key from the passphrase and the account salt, and checks
// it against the account's stored key-check (setting one if the account has none yet).
func (c *Client) DeriveKey(ctx context.Context, passphrase string) (*e2ee.Key, *Me, error) {
	me, err := c.Me(ctx)
	if err != nil {
		return nil, nil, err
	}
	salt, err := e2ee.DecodeSalt(me.E2EESalt)
	if err != nil {
		return nil, nil, err
	}
	key, err := e2ee.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	if me.E2EECheck == "" {
		if check, err := key.NewKeyCheck(); err == nil {
			_ = c.doJSON(ctx, http.MethodPut, "/v2/me/e2ee-check", map[string]any{"check": check}, nil)
		}
	} else if !key.VerifyKeyCheck(me.E2EECheck) {
		return nil, nil, errors.New("E2EE passphrase does not match the one used by your other devices")
	}
	return key, me, nil
}

// Envelope is the subset of the wire frame clients send and receive.
type Envelope struct {
	SeqID        int64  `json:"seq_id"`
	Type         string `json:"type"`
	SourceDevice string `json:"source_device"`
	TargetDevice string `json:"target_device"`
	Ciphertext   string `json:"ciphertext,omitempty"`
	Body         string `json:"body,omitempty"`
	URL          string `json:"url,omitempty"`
	FileID       string `json:"file_id,omitempty"`
	FileName     string `json:"file_name,omitempty"`
	FileSize     int64  `json:"file_size,omitempty"`
	FileSHA256   string `json:"file_sha256,omitempty"`
	Cursor       int64  `json:"cursor,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

// Push sends an encrypted event over REST.
func (c *Client) Push(ctx context.Context, key *e2ee.Key, typ, source, target string, p e2ee.SecretPayload) (*Envelope, error) {
	ct, err := key.Seal(p)
	if err != nil {
		return nil, err
	}
	var out Envelope
	err = c.doJSON(ctx, http.MethodPost, "/v2/pushes", Envelope{
		Type: typ, SourceDevice: source, TargetDevice: target, Ciphertext: ct,
	}, &out)
	return &out, err
}

// UploadFile encrypts a file to a temporary GPF1 file and uploads it resumably.
// progress may be nil.
func (c *Client) UploadFile(ctx context.Context, key *e2ee.Key, path, source, target string, progress func(done, total int64)) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}

	// Plaintext digest for the receiver's end-to-end check.
	ph := sha256.New()
	if _, err := io.Copy(ph, src); err != nil {
		return err
	}
	plainSHA := hex.EncodeToString(ph.Sum(nil))
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "waft-upload-*.gpf")
	if err != nil {
		return err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	ch := sha256.New()
	if err := key.EncryptStream(io.MultiWriter(tmp, ch), src, info.Size()); err != nil {
		return err
	}
	cipherSHA := hex.EncodeToString(ch.Sum(nil))
	cipherSize := e2ee.EncryptedSize(info.Size())

	name := filepath.Base(path)
	meta, err := key.Seal(e2ee.SecretPayload{
		Title:      "File: " + name,
		FileName:   name,
		FileSHA256: plainSHA,
		FileSize:   info.Size(),
		MimeType:   "application/octet-stream",
	})
	if err != nil {
		return err
	}

	var sess struct {
		FileID string `json:"file_id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v2/files", map[string]any{
		"file_name":       "encrypted.gpf",
		"source_device":   source,
		"target_device":   target,
		"total_size":      cipherSize,
		"expected_sha256": cipherSHA,
		"ciphertext_meta": meta,
	}, &sess); err != nil {
		return err
	}

	const chunk = 4 << 20
	buf := make([]byte, chunk)
	var offset int64
	failures := 0
	for offset < cipherSize {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := tmp.ReadAt(buf, offset)
		if n == 0 && err != nil {
			return err
		}
		req, _ := c.newRequest(ctx, http.MethodPatch, "/v2/files/"+sess.FileID, bytes.NewReader(buf[:n]))
		req.Header.Set("Content-Type", "application/offset+octet-stream")
		req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
		resp, err := c.Do(req)
		if err == nil {
			offset, _ = strconv.ParseInt(resp.Header.Get("Upload-Offset"), 10, 64)
			_ = resp.Body.Close()
			failures = 0
			if progress != nil {
				progress(offset, cipherSize)
			}
			continue
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnprocessableEntity || apiErr.Status == http.StatusGone ||
			apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusNotFound) {
			return err // not recoverable by retrying
		}
		failures++
		if failures > 20 {
			return fmt.Errorf("upload aborted after repeated failures: %w", err)
		}
		time.Sleep(time.Duration(failures) * 500 * time.Millisecond)
		head, _ := c.newRequest(ctx, http.MethodHead, "/v2/files/"+sess.FileID, nil)
		if hr, herr := c.Do(head); herr == nil {
			offset, _ = strconv.ParseInt(hr.Header.Get("Upload-Offset"), 10, 64)
			_ = hr.Body.Close()
		}
	}
	return nil
}

// DownloadFile fetches an encrypted file, decrypts it into destDir under a unique,
// sanitised name and verifies the plaintext digest. It returns the final path.
func (c *Client) DownloadFile(ctx context.Context, key *e2ee.Key, fileURL, cipherSHA string, meta e2ee.SecretPayload, destDir string) (string, error) {
	if !strings.HasPrefix(fileURL, "/v2/files/") {
		return "", errors.New("unexpected file URL")
	}
	req, err := c.newRequest(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return "", err
	}
	dl := &http.Client{} // no overall timeout for large files; ctx bounds it
	resp, err := dl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{Status: resp.StatusCode, Message: "download failed"}
	}

	tmp, err := os.CreateTemp(destDir, ".waft-*.part")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	ch := sha256.New()
	ph := sha256.New()
	if _, err := key.DecryptStream(io.MultiWriter(tmp, ph), io.TeeReader(resp.Body, ch)); err != nil {
		return "", err
	}
	if cipherSHA != "" && !strings.EqualFold(hex.EncodeToString(ch.Sum(nil)), cipherSHA) {
		return "", errors.New("ciphertext digest mismatch")
	}
	if meta.FileSHA256 != "" && !strings.EqualFold(hex.EncodeToString(ph.Sum(nil)), meta.FileSHA256) {
		return "", errors.New("plaintext digest mismatch")
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	final := UniquePath(destDir, SafeFileName(meta.FileName))
	if err := os.Rename(tmpName, final); err != nil {
		return "", err
	}
	ok = true
	return final, nil
}

// SafeFileName strips directories and characters that are unsafe on common filesystems.
func SafeFileName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, ". ")
	if name == "" {
		name = "waft-file"
	}
	if len(name) > 180 {
		name = name[:180]
	}
	return name
}

// UniquePath returns dir/name, adding " (n)" before the extension if it already exists.
func UniquePath(dir, name string) string {
	p := filepath.Join(dir, name)
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, i, ext))
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p
		}
	}
}
