// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

// Command waftd is the headless Linux daemon: desktop notifications (notify-send),
// bidirectional clipboard sync (wl-clipboard or xclip) and verified file downloads.
//
//	WAFT_SERVER=https://push.example.com WAFT_TOKEN=gpt_... WAFT_KEY='passphrase' waftd
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/hj91/waft/pkg/client"
	"github.com/hj91/waft/pkg/e2ee"
)

const (
	readWatchdogTimeout = 30 * time.Second
	clipPollInterval    = 1500 * time.Millisecond
	maxClipBytes        = 32 << 10
)

type Daemon struct {
	api          *client.Client
	key          *e2ee.Key
	deviceID     string
	nickname     string
	stateFile    string
	downloadDir  string
	syncClip     bool
	autoDownload bool

	clipMu       sync.Mutex
	lastClipHash string

	writeMu    sync.Mutex
	activeConn *websocket.Conn
}

func main() {
	home, _ := os.UserHomeDir()
	host, _ := os.Hostname()

	server := flag.String("server", envOr("WAFT_SERVER", "http://localhost:8080"), "Waft server URL (WAFT_SERVER)")
	tokenFile := flag.String("token-file", "", "File containing the API token (else WAFT_TOKEN)")
	keyFile := flag.String("key-file", "", "File containing the E2EE passphrase (else WAFT_KEY)")
	deviceID := flag.String("id", envOr("WAFT_DEVICE", sanitizeID(host+"-linux")), "Unique device_id (WAFT_DEVICE)")
	nickname := flag.String("name", host+" (Linux)", "Human-readable nickname")
	stateDir := flag.String("state-dir", filepath.Join(home, ".local", "share", "waft"), "Directory for the resume cursor")
	downloadDir := flag.String("dl", filepath.Join(home, "Downloads", "Waft"), "Directory for incoming files")
	syncClip := flag.Bool("clipboard", true, "Enable bidirectional clipboard sync")
	autoDownload := flag.Bool("autodownload", true, "Automatically download, decrypt and verify incoming files")
	flag.Parse()

	token, err := client.ResolveSecret("", *tokenFile, "WAFT_TOKEN")
	if err != nil {
		log.Fatalf("[DAEMON] %v", err)
	}
	pass, err := client.ResolveSecret("", *keyFile, "WAFT_KEY")
	if err != nil || pass == "" {
		log.Fatalf("[DAEMON] E2EE passphrase required (WAFT_KEY or -key-file)")
	}
	api, err := client.New(*server, token)
	if err != nil {
		log.Fatalf("[DAEMON] %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Key derivation needs the account salt; retry while the server is unreachable.
	var key *e2ee.Key
	var me *client.Me
	for attempt := 1; ; attempt++ {
		key, me, err = api.DeriveKey(ctx, pass)
		if err == nil {
			break
		}
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 401 || strings.Contains(err.Error(), "passphrase does not match") {
			log.Fatalf("[DAEMON] %v", err)
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("[DAEMON] waiting for server: %v", err)
		time.Sleep(time.Duration(min(attempt, 6)) * 2 * time.Second)
	}

	_ = os.MkdirAll(*stateDir, 0o700)
	_ = os.MkdirAll(*downloadDir, 0o700)

	d := &Daemon{
		api:      api,
		key:      key,
		deviceID: *deviceID,
		nickname: *nickname,
		// One cursor per account and device, so switching accounts never reuses a cursor.
		stateFile:    filepath.Join(*stateDir, fmt.Sprintf("cursor-%s-%s.seq", me.ID, sanitizeID(*deviceID))),
		downloadDir:  *downloadDir,
		syncClip:     *syncClip,
		autoDownload: *autoDownload,
	}
	log.Printf("[DAEMON] signed in as %s; device %s", me.Email, d.deviceID)

	if d.syncClip {
		go d.clipboardPollLoop(ctx)
	}
	d.superviseConnection(ctx)
}

func (d *Daemon) loadCursor() int64 {
	raw, err := os.ReadFile(d.stateFile)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return v
}

// saveCursor persists the cursor atomically. force allows moving backwards, which the
// server requests through sync_complete after a database restore.
func (d *Daemon) saveCursor(seq int64, force bool) {
	if !force && seq <= d.loadCursor() {
		return
	}
	tmp := d.stateFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600); err == nil {
		_ = os.Rename(tmp, d.stateFile)
	}
}

func (d *Daemon) superviseConnection(ctx context.Context) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		connectedAt := time.Now()
		err := d.runSession(ctx)
		if ctx.Err() != nil {
			return
		}
		var ce *websocket.CloseError
		if errors.As(err, &ce) && (ce.Code == 4001 || ce.Code == 4003) {
			log.Fatalf("[DAEMON] server closed the session permanently: %s", ce.Text)
		}
		if time.Since(connectedAt) > 30*time.Second {
			attempt = 0
		}
		attempt++
		backoff := time.Duration(1<<min(attempt, 5)) * time.Second
		wait := backoff/2 + time.Duration(rand.Int63n(int64(backoff/2)+1)) // equal jitter
		log.Printf("[DAEMON] link broken (%v); reconnecting in %v", err, wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (d *Daemon) runSession(ctx context.Context) error {
	lastSeq := d.loadCursor()
	u, err := url.Parse(d.api.WSURL("/v2/stream"))
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("device_id", d.deviceID)
	q.Set("nickname", d.nickname)
	q.Set("platform", "linux-daemon")
	q.Set("last_seq", strconv.FormatInt(lastSeq, 10))
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, resp, err := dialer.DialContext(ctx, u.String(), d.api.AuthHeader())
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			log.Fatalf("[DAEMON] token rejected by server (revoked or expired)")
		}
		return err
	}
	d.writeMu.Lock()
	d.activeConn = conn
	d.writeMu.Unlock()
	defer func() {
		d.writeMu.Lock()
		if d.activeConn == conn {
			d.activeConn = nil
		}
		d.writeMu.Unlock()
		_ = conn.Close()
	}()

	_ = conn.SetReadDeadline(time.Now().Add(readWatchdogTimeout))
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readWatchdogTimeout))
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})
	log.Printf("[DAEMON] connected (last_seq=%d)", lastSeq)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(readWatchdogTimeout))

		var env client.Envelope
		if err := json.Unmarshal(msg, &env); err != nil {
			continue
		}
		switch env.Type {
		case "heartbeat", "presence":
			continue
		case "error":
			log.Printf("[DAEMON] server: %s", env.Body)
			continue
		case "sync_complete":
			d.saveCursor(env.Cursor, true)
			log.Printf("[DAEMON] sync complete: %s (cursor=%d)", env.Body, env.Cursor)
			continue
		}
		if env.SeqID > 0 {
			d.saveCursor(env.SeqID, false)
		}
		if env.SourceDevice == d.deviceID {
			continue
		}
		var secret e2ee.SecretPayload
		if env.Ciphertext != "" {
			secret, err = d.key.Open(env.Ciphertext)
			if err != nil {
				log.Printf("[DAEMON] cannot decrypt event #%d: %v", env.SeqID, err)
				continue
			}
		}
		d.handleIncomingEvent(ctx, env, secret)
	}
}

func (d *Daemon) handleIncomingEvent(ctx context.Context, env client.Envelope, s e2ee.SecretPayload) {
	switch env.Type {
	case "push", "mirror":
		title := s.Title
		if title == "" {
			title = "Waft from " + env.SourceDevice
		}
		body := s.Body
		if s.URL != "" {
			body = strings.TrimSpace(body + "\n" + s.URL)
		}
		notifyDesktop(title, body)
	case "clip":
		if d.syncClip && s.Body != "" {
			d.applyRemoteClipboard(s.Body)
		}
	case "file":
		name := client.SafeFileName(s.FileName)
		log.Printf("[DAEMON] incoming file %q (%d bytes)", name, s.FileSize)
		if d.autoDownload && env.URL != "" {
			go d.downloadAndVerify(ctx, env, s)
		} else {
			notifyDesktop("Incoming file", name)
		}
	}
}

func (d *Daemon) downloadAndVerify(ctx context.Context, env client.Envelope, s e2ee.SecretPayload) {
	path, err := d.api.DownloadFile(ctx, d.key, env.URL, env.FileSHA256, s, d.downloadDir)
	if err != nil {
		log.Printf("[DAEMON] download of %q failed: %v", s.FileName, err)
		notifyDesktop("File transfer failed", client.SafeFileName(s.FileName)+": "+err.Error())
		return
	}
	log.Printf("[DAEMON] verified and saved %s", path)
	notifyDesktop("File received (verified)", path)
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (d *Daemon) applyRemoteClipboard(text string) {
	d.clipMu.Lock()
	d.lastClipHash = hashString(text)
	d.clipMu.Unlock()

	if _, err := exec.LookPath("wl-copy"); err == nil {
		cmd := exec.Command("wl-copy")
		cmd.Stdin = strings.NewReader(text)
		_ = cmd.Run()
		return
	}
	if _, err := exec.LookPath("xclip"); err == nil {
		cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = strings.NewReader(text)
		_ = cmd.Run()
	}
}

func readSystemClipboard() (string, error) {
	if _, err := exec.LookPath("wl-paste"); err == nil {
		if out, err := exec.Command("wl-paste", "--no-newline").Output(); err == nil {
			return string(out), nil
		}
	}
	if _, err := exec.LookPath("xclip"); err == nil {
		if out, err := exec.Command("xclip", "-selection", "clipboard", "-o").Output(); err == nil {
			return string(out), nil
		}
	}
	return "", errors.New("no clipboard utility found")
}

func (d *Daemon) clipboardPollLoop(ctx context.Context) {
	ticker := time.NewTicker(clipPollInterval)
	defer ticker.Stop()
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		text, err := readSystemClipboard()
		if err != nil || text == "" || len(text) > maxClipBytes {
			continue
		}
		h := hashString(text)
		d.clipMu.Lock()
		changed := h != d.lastClipHash
		d.lastClipHash = h
		d.clipMu.Unlock()
		// The clipboard content present at start-up is not broadcast; only later copies are.
		if !changed || first {
			first = false
			continue
		}
		ct, err := d.key.Seal(e2ee.SecretPayload{Title: "Clipboard", Body: text})
		if err != nil {
			continue
		}
		frame, _ := json.Marshal(client.Envelope{Type: "clip", TargetDevice: "*", Ciphertext: ct})
		d.writeMu.Lock()
		if conn := d.activeConn; conn != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = conn.WriteMessage(websocket.TextMessage, frame)
		}
		d.writeMu.Unlock()
	}
}

func notifyDesktop(title, body string) {
	if _, err := exec.LookPath("notify-send"); err == nil {
		// "--" ends option parsing, so remote text starting with "-" is never a flag.
		_ = exec.Command("notify-send", "-a", "Waft", "--", title, body).Run()
		return
	}
	log.Printf("[NOTIFY] %s: %s", title, body)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func sanitizeID(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			return r
		}
		return '-'
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
