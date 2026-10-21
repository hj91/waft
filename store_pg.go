// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationLockKey   int64 = 0x476F507573684D31 // "WaftM1"
	maintenanceLockKey int64 = 0x476F507573684D32 // "WaftM2"
	nodeLeaseTTL             = 15 * time.Second
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrDeviceLimit   = errors.New("device limit reached")
	ErrQuotaExceeded = errors.New("storage quota exceeded")
)

type PGStore struct {
	pool   *pgxpool.Pool
	nodeID string
	log    *slog.Logger
}

func NewPGStore(ctx context.Context, dsn string, maxConns int, nodeID string, log *slog.Logger) (*PGStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres DSN: %w", err)
	}
	cfg.MaxConns = int32(maxConns)
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 5 * time.Second
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = "waft-" + nodeID

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initial postgres ping failed: %w", err)
	}

	s := &PGStore{pool: pool, nodeID: nodeID, log: log}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	return s, nil
}

func (s *PGStore) Close() { s.pool.Close() }

func (s *PGStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// --- Schema migrations (versioned, serialised across nodes by an advisory lock) ---

var migrations = []string{
	// v1: multi-tenant schema. A single-user v1 deployment keeps its old tables under legacy_v1_*.
	`
	DO $$
	DECLARE t TEXT;
	BEGIN
		FOREACH t IN ARRAY ARRAY['devices','events','file_transfers'] LOOP
			IF EXISTS (SELECT 1 FROM information_schema.tables
			           WHERE table_schema = current_schema() AND table_name = t)
			   AND NOT EXISTS (SELECT 1 FROM information_schema.columns
			           WHERE table_schema = current_schema() AND table_name = t AND column_name = 'user_id') THEN
				EXECUTE format('ALTER TABLE %I RENAME TO %I', t, 'legacy_v1_' || t);
			END IF;
		END LOOP;
	END $$;

	CREATE TABLE IF NOT EXISTS cluster_nodes (
		node_id      TEXT PRIMARY KEY,
		heartbeat_at BIGINT NOT NULL
	);

	CREATE TABLE users (
		id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		email               TEXT NOT NULL,
		display_name        TEXT NOT NULL DEFAULT '',
		password_hash       TEXT NOT NULL,
		role                TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
		e2ee_salt           TEXT NOT NULL,
		e2ee_check          TEXT NOT NULL DEFAULT '',
		disabled            BOOLEAN NOT NULL DEFAULT FALSE,
		created_at          BIGINT NOT NULL,
		updated_at          BIGINT NOT NULL,
		password_changed_at BIGINT NOT NULL
	);
	CREATE UNIQUE INDEX users_email_uq ON users (lower(email));

	-- Hot counters live apart from users so per-event updates stay small (HOT updates).
	CREATE TABLE user_counters (
		user_id      UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		last_seq     BIGINT NOT NULL DEFAULT 0,
		storage_used BIGINT NOT NULL DEFAULT 0
	) WITH (fillfactor = 70);

	CREATE TABLE sessions (
		token_hash   BYTEA PRIMARY KEY,
		user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at   BIGINT NOT NULL,
		last_seen_at BIGINT NOT NULL,
		expires_at   BIGINT NOT NULL,
		user_agent   TEXT NOT NULL DEFAULT '',
		ip           TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX sessions_user_idx ON sessions (user_id);
	CREATE INDEX sessions_expiry_idx ON sessions (expires_at);

	CREATE TABLE api_tokens (
		id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name         TEXT NOT NULL,
		token_hash   BYTEA NOT NULL UNIQUE,
		prefix       TEXT NOT NULL,
		created_at   BIGINT NOT NULL,
		last_used_at BIGINT NOT NULL DEFAULT 0,
		expires_at   BIGINT NOT NULL DEFAULT 0
	);
	CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

	CREATE TABLE devices (
		user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_id      TEXT NOT NULL,
		nickname       TEXT NOT NULL,
		platform       TEXT NOT NULL,
		online         BOOLEAN NOT NULL DEFAULT FALSE,
		connected_node TEXT,
		connected_at   BIGINT NOT NULL DEFAULT 0,
		remote_ip      TEXT NOT NULL DEFAULT '',
		last_seen      BIGINT NOT NULL,
		created_at     BIGINT NOT NULL,
		PRIMARY KEY (user_id, device_id)
	);
	CREATE INDEX devices_node_idx ON devices (connected_node) WHERE online;

	CREATE TABLE events (
		user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		seq_id          BIGINT NOT NULL,
		type            TEXT NOT NULL,
		source_device   TEXT NOT NULL,
		target_device   TEXT NOT NULL,
		ciphertext      TEXT NOT NULL DEFAULT '',
		title           TEXT NOT NULL DEFAULT '',
		body            TEXT NOT NULL DEFAULT '',
		url             TEXT NOT NULL DEFAULT '',
		app_name        TEXT NOT NULL DEFAULT '',
		notification_id TEXT NOT NULL DEFAULT '',
		file_id         TEXT NOT NULL DEFAULT '',
		file_name       TEXT NOT NULL DEFAULT '',
		file_size       BIGINT NOT NULL DEFAULT 0,
		file_sha256     TEXT NOT NULL DEFAULT '',
		created_at      BIGINT NOT NULL,
		PRIMARY KEY (user_id, seq_id)
	);
	CREATE INDEX events_created_brin ON events USING brin (created_at);

	CREATE TABLE file_transfers (
		file_id         TEXT PRIMARY KEY,
		user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		file_name       TEXT NOT NULL,
		mime_type       TEXT NOT NULL DEFAULT 'application/octet-stream',
		source_device   TEXT NOT NULL,
		target_device   TEXT NOT NULL,
		total_size      BIGINT NOT NULL,
		bytes_written   BIGINT NOT NULL DEFAULT 0,
		expected_sha256 TEXT NOT NULL DEFAULT '',
		actual_sha256   TEXT NOT NULL DEFAULT '',
		ciphertext_meta TEXT NOT NULL DEFAULT '',
		status          TEXT NOT NULL DEFAULT 'UPLOADING',
		lock_token      TEXT NOT NULL DEFAULT '',
		lock_until      BIGINT NOT NULL DEFAULT 0,
		created_at      BIGINT NOT NULL,
		updated_at      BIGINT NOT NULL
	);
	CREATE INDEX file_transfers_user_idx ON file_transfers (user_id, created_at DESC);
	CREATE INDEX file_transfers_status_idx ON file_transfers (status, updated_at);

	CREATE TABLE audit_log (
		id         BIGSERIAL PRIMARY KEY,
		user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
		action     TEXT NOT NULL,
		ip         TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		detail     TEXT NOT NULL DEFAULT '',
		created_at BIGINT NOT NULL
	);
	CREATE INDEX audit_log_user_idx ON audit_log (user_id, id DESC);
	`,
}

func (s *PGStore) migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INT PRIMARY KEY, applied_at BIGINT NOT NULL)`); err != nil {
		return err
	}
	var current int
	if err := conn.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for v := current + 1; v <= len(migrations); v++ {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, migrations[v-1]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration v%d: %w", v, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, v, nowMs()); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.log.Info("schema migration applied", "version", v)
	}
	return nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// --- Cluster lease ---

// StartNodeLeaseLoop renews this node's lease and sweeps devices pinned to dead nodes.
// onSwept receives the accounts whose presence changed so their devices can be told.
func (s *PGStore) StartNodeLeaseLoop(ctx context.Context, onSwept func(userIDs []string)) {
	ticker := time.NewTicker(nodeLeaseTTL / 3)
	defer ticker.Stop()

	s.renewLeaseAndSweep(ctx, onSwept)
	for {
		select {
		case <-ctx.Done():
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = s.pool.Exec(cleanupCtx, `
				UPDATE devices SET online = FALSE, connected_node = NULL, last_seen = $2
				WHERE connected_node = $1`, s.nodeID, nowMs())
			_, _ = s.pool.Exec(cleanupCtx, `DELETE FROM cluster_nodes WHERE node_id = $1`, s.nodeID)
			cancel()
			return
		case <-ticker.C:
			s.renewLeaseAndSweep(ctx, onSwept)
		}
	}
}

func (s *PGStore) renewLeaseAndSweep(ctx context.Context, onSwept func([]string)) {
	now := nowMs()
	cutoff := now - nodeLeaseTTL.Milliseconds()

	opCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if _, err := s.pool.Exec(opCtx, `
		INSERT INTO cluster_nodes (node_id, heartbeat_at) VALUES ($1, $2)
		ON CONFLICT (node_id) DO UPDATE SET heartbeat_at = EXCLUDED.heartbeat_at`, s.nodeID, now); err != nil {
		s.log.Warn("node lease renewal failed", "err", err)
		return
	}

	// SET expressions see the old row, so the subquery still reads the dead node's last heartbeat.
	rows, err := s.pool.Query(opCtx, `
		UPDATE devices d
		SET online = FALSE, connected_node = NULL,
		    last_seen = COALESCE((SELECT c.heartbeat_at FROM cluster_nodes c WHERE c.node_id = d.connected_node), $2)
		WHERE d.online AND d.connected_node IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM cluster_nodes c WHERE c.node_id = d.connected_node AND c.heartbeat_at >= $1)
		RETURNING d.user_id::text`, cutoff, now)
	if err != nil {
		s.log.Warn("orphan sweep failed", "err", err)
		return
	}
	seen := map[string]bool{}
	var users []string
	for rows.Next() {
		var uid string
		if rows.Scan(&uid) == nil && !seen[uid] {
			seen[uid] = true
			users = append(users, uid)
		}
	}
	rows.Close()
	if len(users) > 0 {
		s.log.Info("swept devices of dead nodes", "accounts", len(users))
		if onSwept != nil {
			onSwept(users)
		}
	}
	_, _ = s.pool.Exec(opCtx, `DELETE FROM cluster_nodes WHERE heartbeat_at < $1`, now-10*nodeLeaseTTL.Milliseconds())
}

// --- Users ---

const userColumns = `u.id::text, u.email, u.display_name, u.role, u.e2ee_salt, u.e2ee_check, u.created_at, u.disabled, u.password_hash`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.E2EESalt, &u.E2EECheck, &u.CreatedAt, &u.Disabled, &u.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// CreateUser inserts a new account. The very first account becomes an admin.
func (s *PGStore) CreateUser(ctx context.Context, email, displayName, passwordHash, salt string) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := nowMs()
	u, err := scanUser(tx.QueryRow(ctx, `
		INSERT INTO users AS u (email, display_name, password_hash, role, e2ee_salt, created_at, updated_at, password_changed_at)
		VALUES ($1, $2, $3, CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'user' ELSE 'admin' END, $4, $5, $5, $5)
		RETURNING `+userColumns, email, displayName, passwordHash, salt, now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_counters (user_id) VALUES ($1)`, u.ID); err != nil {
		return nil, err
	}
	return u, tx.Commit(ctx)
}

func (s *PGStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE lower(u.email) = lower($1)`, email))
}

func (s *PGStore) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id = $1`, id))
}

func (s *PGStore) UpdatePassword(ctx context.Context, userID, hash string) error {
	now := nowMs()
	_, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = $3, updated_at = $3 WHERE id = $1`, userID, hash, now)
	return err
}

// RehashPassword silently upgrades a hash created with weaker parameters.
func (s *PGStore) RehashPassword(ctx context.Context, userID, hash string) {
	_, _ = s.pool.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, hash)
}

func (s *PGStore) UpdateProfile(ctx context.Context, userID, displayName string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET display_name = $2, updated_at = $3 WHERE id = $1`, userID, displayName, nowMs())
	return err
}

// SetE2EECheck stores the passphrase key-check value. Without force it only fills an empty slot.
func (s *PGStore) SetE2EECheck(ctx context.Context, userID, check string, force bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET e2ee_check = $2, updated_at = $3
		WHERE id = $1 AND ($4 OR e2ee_check = '')`, userID, check, nowMs(), force)
	return tag.RowsAffected() == 1, err
}

// DeleteUser removes an account and everything it owns. Returns the file IDs that were on disk.
func (s *PGStore) DeleteUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT file_id FROM file_transfers WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	return ids, err
}

func (s *PGStore) StorageUsed(ctx context.Context, userID string) (int64, error) {
	var used int64
	err := s.pool.QueryRow(ctx, `SELECT storage_used FROM user_counters WHERE user_id = $1`, userID).Scan(&used)
	return used, err
}

// --- Sessions ---

func (s *PGStore) CreateSession(ctx context.Context, tokenHash []byte, userID string, ttl time.Duration, ua, ip string) error {
	now := nowMs()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $3, $4, $5, $6)`, tokenHash, userID, now, now+ttl.Milliseconds(), truncate(ua, 300), ip)
	return err
}

// LookupSession resolves a session token hash to its user. Last-seen is refreshed at most
// once every five minutes so authenticated traffic does not turn into a write per request.
func (s *PGStore) LookupSession(ctx context.Context, tokenHash []byte) (*User, error) {
	now := nowMs()
	var lastSeen int64
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT `+userColumns+`, s.last_seen_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.E2EESalt, &u.E2EECheck, &u.CreatedAt, &u.Disabled, &u.PasswordHash, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if now-lastSeen > 5*60*1000 {
		_, _ = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1`, tokenHash, now)
	}
	return &u, nil
}

func (s *PGStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteSessionByID removes one of the user's sessions by its displayed short ID.
func (s *PGStore) DeleteSessionByID(ctx context.Context, userID, shortID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM sessions WHERE user_id = $1 AND left(encode(token_hash, 'hex'), 16) = $2`, userID, shortID)
	return tag.RowsAffected() > 0, err
}

// DeleteUserSessions removes every session of a user except the one given (may be nil).
func (s *PGStore) DeleteUserSessions(ctx context.Context, userID string, except []byte) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM sessions WHERE user_id = $1 AND ($2::bytea IS NULL OR token_hash <> $2)`, userID, except)
	return err
}

func (s *PGStore) ListSessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT left(encode(token_hash, 'hex'), 16), created_at, last_seen_at, expires_at, user_agent, ip
		FROM sessions WHERE user_id = $1 AND expires_at > $2 ORDER BY last_seen_at DESC`, userID, nowMs())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SessionInfo, error) {
		var si SessionInfo
		err := r.Scan(&si.ID, &si.CreatedAt, &si.LastSeenAt, &si.ExpiresAt, &si.UserAgent, &si.IP)
		return si, err
	})
}

// --- API tokens ---

func (s *PGStore) CreateAPIToken(ctx context.Context, userID, name string, tokenHash []byte, prefix string, expiresAt int64) (*APIToken, error) {
	t := APIToken{Name: name, Prefix: prefix, CreatedAt: nowMs(), ExpiresAt: expiresAt}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_hash, prefix, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`, userID, name, tokenHash, prefix, t.CreatedAt, expiresAt).Scan(&t.ID)
	return &t, err
}

// LookupAPIToken resolves a token hash. last_used_at is refreshed at most once a minute.
func (s *PGStore) LookupAPIToken(ctx context.Context, tokenHash []byte) (*User, string, error) {
	now := nowMs()
	var tokenID string
	var lastUsed int64
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT `+userColumns+`, t.id::text, t.last_used_at
		FROM api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND (t.expires_at = 0 OR t.expires_at > $2)`, tokenHash, now).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.E2EESalt, &u.E2EECheck, &u.CreatedAt, &u.Disabled, &u.PasswordHash, &tokenID, &lastUsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if now-lastUsed > 60*1000 {
		_, _ = s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2 WHERE id = $1`, tokenID, now)
	}
	return &u, tokenID, nil
}

func (s *PGStore) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, prefix, created_at, last_used_at, expires_at
		FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIToken, error) {
		var t APIToken
		err := r.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt)
		return t, err
	})
}

func (s *PGStore) DeleteAPIToken(ctx context.Context, userID, tokenID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_tokens WHERE user_id = $1 AND id::text = $2`, userID, tokenID)
	return tag.RowsAffected() > 0, err
}

func (s *PGStore) CountAPITokens(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// --- Audit log ---

func (s *PGStore) Audit(ctx context.Context, userID, action, ip, ua, detail string) {
	var uid any
	if userID != "" {
		uid = userID
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (user_id, action, ip, user_agent, detail, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, uid, action, ip, truncate(ua, 300), truncate(detail, 500), nowMs()); err != nil {
		s.log.Warn("audit write failed", "action", action, "err", err)
	}
}

type AuditEntry struct {
	Action    string `json:"action"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Detail    string `json:"detail"`
	CreatedAt int64  `json:"created_at"`
}

func (s *PGStore) ListAudit(ctx context.Context, userID string, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT action, ip, user_agent, detail, created_at FROM audit_log
		WHERE user_id = $1 ORDER BY id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var a AuditEntry
		err := r.Scan(&a.Action, &a.IP, &a.UserAgent, &a.Detail, &a.CreatedAt)
		return a, err
	})
}

// --- Devices ---

// SetDeviceOnline registers or refreshes a device. New devices are refused once the
// account has maxDevices registered devices.
func (s *PGStore) SetDeviceOnline(ctx context.Context, userID string, d DeviceInfo, maxDevices int) error {
	now := nowMs()
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO devices (user_id, device_id, nickname, platform, online, connected_node, connected_at, remote_ip, last_seen, created_at)
		SELECT $1, $2, $3, $4, TRUE, $5, $6, $7, $8, $8
		WHERE EXISTS (SELECT 1 FROM devices WHERE user_id = $1 AND device_id = $2)
		   OR (SELECT count(*) FROM devices WHERE user_id = $1) < $9
		ON CONFLICT (user_id, device_id) DO UPDATE SET
			nickname       = EXCLUDED.nickname,
			platform       = EXCLUDED.platform,
			online         = TRUE,
			connected_node = EXCLUDED.connected_node,
			connected_at   = EXCLUDED.connected_at,
			remote_ip      = EXCLUDED.remote_ip,
			last_seen      = EXCLUDED.last_seen`,
		userID, d.DeviceID, d.Nickname, d.Platform, s.nodeID, d.Connected, d.RemoteIP, now, maxDevices)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceLimit
	}
	return nil
}

func (s *PGStore) SetDeviceOffline(ctx context.Context, userID, deviceID string, connectedAt int64) {
	// connected_at guards against a late disconnect overwriting a newer session of the
	// same device that has already registered (possibly on another node).
	_, _ = s.pool.Exec(ctx, `
		UPDATE devices SET online = FALSE, connected_node = NULL, last_seen = $1
		WHERE user_id = $2 AND device_id = $3 AND connected_node = $4 AND connected_at = $5`,
		nowMs(), userID, deviceID, s.nodeID, connectedAt)
}

func (s *PGStore) ListDevices(ctx context.Context, userID string) ([]DeviceInfo, error) {
	now := nowMs()
	cutoff := now - nodeLeaseTTL.Milliseconds()
	rows, err := s.pool.Query(ctx, `
		SELECT d.device_id, d.nickname, d.platform,
		       COALESCE(d.online AND c.heartbeat_at >= $2, FALSE) AS is_online,
		       d.last_seen, d.connected_at, d.remote_ip, d.created_at
		FROM devices d
		LEFT JOIN cluster_nodes c ON d.connected_node = c.node_id
		WHERE d.user_id = $1
		ORDER BY is_online DESC, d.last_seen DESC`, userID, cutoff)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (DeviceInfo, error) {
		var d DeviceInfo
		err := r.Scan(&d.DeviceID, &d.Nickname, &d.Platform, &d.Online, &d.LastSeen, &d.Connected, &d.RemoteIP, &d.CreatedAt)
		if d.Online {
			d.LastSeen = now
		}
		return d, err
	})
	if out == nil {
		out = []DeviceInfo{}
	}
	return out, err
}

func (s *PGStore) DeleteDevice(ctx context.Context, userID, deviceID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE user_id = $1 AND device_id = $2`, userID, deviceID)
	return tag.RowsAffected() > 0, err
}

func (s *PGStore) RenameDevice(ctx context.Context, userID, deviceID, nickname string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET nickname = $3 WHERE user_id = $1 AND device_id = $2`, userID, deviceID, nickname)
	return tag.RowsAffected() > 0, err
}

// --- Events ---

// AppendEvent allocates the next per-account sequence number and stores the event in one
// statement. The counter row lock serialises writers of the same account only, so commit
// order equals sequence order per account while different accounts never contend.
func (s *PGStore) AppendEvent(ctx context.Context, userID string, env *Envelope) error {
	if env.CreatedAt == 0 {
		env.CreatedAt = nowMs()
	}
	err := s.pool.QueryRow(ctx, `
		WITH seq AS (
			UPDATE user_counters SET last_seq = last_seq + 1 WHERE user_id = $1 RETURNING last_seq
		)
		INSERT INTO events (
			user_id, seq_id, type, source_device, target_device, ciphertext,
			title, body, url, app_name, notification_id,
			file_id, file_name, file_size, file_sha256, created_at
		)
		SELECT $1, seq.last_seq, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15 FROM seq
		RETURNING seq_id`,
		userID, env.Type, env.SourceDevice, env.TargetDevice, env.Ciphertext,
		env.Title, env.Body, env.URL, env.AppName, env.Notification,
		env.FileID, env.FileName, env.FileSize, env.FileSHA256, env.CreatedAt,
	).Scan(&env.SeqID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

const eventColumns = `seq_id, type, source_device, target_device, ciphertext,
	title, body, url, app_name, notification_id,
	file_id, file_name, file_size, file_sha256, created_at`

func collectEvents(rows pgx.Rows) ([]Envelope, error) {
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Envelope, error) {
		var e Envelope
		err := r.Scan(&e.SeqID, &e.Type, &e.SourceDevice, &e.TargetDevice, &e.Ciphertext,
			&e.Title, &e.Body, &e.URL, &e.AppName, &e.Notification,
			&e.FileID, &e.FileName, &e.FileSize, &e.FileSHA256, &e.CreatedAt)
		return e, err
	})
	if out == nil {
		out = []Envelope{}
	}
	return out, err
}

// FetchDelta returns up to limit events of the account after afterSeq that are visible to
// deviceID ("*" returns all), together with the account head sequence read from the same
// snapshot. When fewer than limit events come back, the caller may advance to head.
func (s *PGStore) FetchDelta(ctx context.Context, userID string, afterSeq int64, deviceID string, limit int) ([]Envelope, int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var head int64
	if err := tx.QueryRow(ctx, `SELECT last_seq FROM user_counters WHERE user_id = $1`, userID).Scan(&head); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT `+eventColumns+` FROM events
		WHERE user_id = $1 AND seq_id > $2
		  AND ($3 = '*' OR target_device = '*' OR target_device = $3 OR source_device = $3)
		ORDER BY seq_id ASC
		LIMIT $4`, userID, afterSeq, deviceID, limit)
	if err != nil {
		return nil, 0, err
	}
	events, err := collectEvents(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, head, tx.Commit(ctx)
}

// --- Maintenance (one node at a time) ---

type MaintenanceResult struct {
	ExpiredSessions int64
	PrunedEvents    int64
	ExpiredFiles    []FileRef
}

type FileRef struct {
	UserID string
	FileID string
}

// RunMaintenance performs retention work if no other node is doing it right now.
func (s *PGStore) RunMaintenance(ctx context.Context, eventRetention, fileRetention, staleUpload time.Duration) (*MaintenanceResult, bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, maintenanceLockKey).Scan(&got); err != nil || !got {
		return nil, false, err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, maintenanceLockKey) }()

	now := nowMs()
	res := &MaintenanceResult{}

	tag, err := conn.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return nil, true, err
	}
	res.ExpiredSessions = tag.RowsAffected()
	_, _ = conn.Exec(ctx, `DELETE FROM api_tokens WHERE expires_at > 0 AND expires_at <= $1`, now)
	_, _ = conn.Exec(ctx, `DELETE FROM audit_log WHERE created_at < $1`, now-365*24*3600*1000)

	if eventRetention > 0 {
		cutoff := now - eventRetention.Milliseconds()
		for {
			tag, err := conn.Exec(ctx, `
				DELETE FROM events WHERE ctid IN (
					SELECT ctid FROM events WHERE created_at < $1 LIMIT 5000)`, cutoff)
			if err != nil {
				return res, true, err
			}
			res.PrunedEvents += tag.RowsAffected()
			if tag.RowsAffected() < 5000 || ctx.Err() != nil {
				break
			}
		}
	}

	// Expired completed files and abandoned or corrupted uploads release their quota.
	var fileCutoff int64 = -1
	if fileRetention > 0 {
		fileCutoff = now - fileRetention.Milliseconds()
	}
	rows, err := conn.Query(ctx, `
		WITH gone AS (
			DELETE FROM file_transfers
			WHERE (status = 'COMPLETED' AND created_at < $1)
			   OR (status <> 'COMPLETED' AND updated_at < $2)
			RETURNING user_id, file_id, total_size
		), released AS (
			UPDATE user_counters c SET storage_used = GREATEST(0, c.storage_used - g.total)
			FROM (SELECT user_id, SUM(total_size) AS total FROM gone GROUP BY user_id) g
			WHERE c.user_id = g.user_id
		)
		SELECT user_id::text, file_id FROM gone`, fileCutoff, now-staleUpload.Milliseconds())
	if err != nil {
		return res, true, err
	}
	res.ExpiredFiles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (FileRef, error) {
		var f FileRef
		err := r.Scan(&f.UserID, &f.FileID)
		return f, err
	})
	return res, true, err
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
