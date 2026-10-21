// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every server tunable. Each flag can also be set through the
// environment variable shown in its help text (flags win over environment).
type Config struct {
	Addr      string
	NodeID    string
	PGDSN     string
	PGMaxConn int

	RedisAddr string
	RedisPass string
	RedisDB   int

	UploadDir string

	AllowSignup    bool
	CookieSecure   bool
	TrustProxy     bool
	AllowedOrigins []string
	RequireE2EE    bool

	SessionTTL        time.Duration
	EventRetention    time.Duration
	FileRetention     time.Duration
	StaleUploadTTL    time.Duration
	MaxFileSize       int64
	UserQuota         int64
	MaxDevicesPerUser int
	MaxChunkSize      int64

	LogLevel  string
	LogFormat string
}

func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

var flagErrHelp = flag.ErrHelp

func loadConfig(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("waft-server", flag.ContinueOnError)

	fs.StringVar(&c.Addr, "addr", envString("WAFT_ADDR", ":8080"), "HTTP/WS listen address (WAFT_ADDR)")
	fs.StringVar(&c.NodeID, "node-id", envString("WAFT_NODE_ID", ""), "Unique cluster node ID (WAFT_NODE_ID)")
	fs.StringVar(&c.PGDSN, "pg", envString("WAFT_PG_DSN", "postgres://waft:waft@localhost:5432/waft?sslmode=disable"), "PostgreSQL DSN (WAFT_PG_DSN)")
	fs.IntVar(&c.PGMaxConn, "pg-max-conns", envInt("WAFT_PG_MAX_CONNS", 30), "PostgreSQL pool size per node (WAFT_PG_MAX_CONNS)")
	fs.StringVar(&c.RedisAddr, "redis", envString("WAFT_REDIS_ADDR", "localhost:6379"), "Redis host:port (WAFT_REDIS_ADDR)")
	fs.StringVar(&c.RedisPass, "redis-pass", envString("WAFT_REDIS_PASSWORD", ""), "Redis password (WAFT_REDIS_PASSWORD)")
	fs.IntVar(&c.RedisDB, "redis-db", envInt("WAFT_REDIS_DB", 0), "Redis logical DB (WAFT_REDIS_DB)")
	fs.StringVar(&c.UploadDir, "uploads", envString("WAFT_UPLOAD_DIR", "./uploads"), "Shared directory for file storage (WAFT_UPLOAD_DIR)")

	fs.BoolVar(&c.AllowSignup, "allow-signup", envBool("WAFT_ALLOW_SIGNUP", true), "Allow public self-registration (WAFT_ALLOW_SIGNUP)")
	fs.BoolVar(&c.CookieSecure, "cookie-secure", envBool("WAFT_COOKIE_SECURE", true), "Mark session cookies Secure; disable only for plain-HTTP local testing (WAFT_COOKIE_SECURE)")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", envBool("WAFT_TRUST_PROXY", false), "Trust X-Real-IP / X-Forwarded-For from the reverse proxy (WAFT_TRUST_PROXY)")
	origins := fs.String("allowed-origins", envString("WAFT_ALLOWED_ORIGINS", ""), "Comma-separated extra allowed browser origins; same-host is always allowed (WAFT_ALLOWED_ORIGINS)")
	fs.BoolVar(&c.RequireE2EE, "require-e2ee", envBool("WAFT_REQUIRE_E2EE", true), "Reject events that carry plaintext title/body/url (WAFT_REQUIRE_E2EE)")

	fs.DurationVar(&c.SessionTTL, "session-ttl", envDuration("WAFT_SESSION_TTL", 30*24*time.Hour), "Web session lifetime (WAFT_SESSION_TTL)")
	fs.DurationVar(&c.EventRetention, "event-retention", envDuration("WAFT_EVENT_RETENTION", 30*24*time.Hour), "Delete events older than this; 0 keeps forever (WAFT_EVENT_RETENTION)")
	fs.DurationVar(&c.FileRetention, "file-retention", envDuration("WAFT_FILE_RETENTION", 7*24*time.Hour), "Delete completed files older than this; 0 keeps forever (WAFT_FILE_RETENTION)")
	fs.DurationVar(&c.StaleUploadTTL, "stale-upload-ttl", envDuration("WAFT_STALE_UPLOAD_TTL", 24*time.Hour), "Abort uploads idle longer than this (WAFT_STALE_UPLOAD_TTL)")
	fs.Int64Var(&c.MaxFileSize, "max-file-size", envInt64("WAFT_MAX_FILE_SIZE", 2<<30), "Maximum size of one file in bytes (WAFT_MAX_FILE_SIZE)")
	fs.Int64Var(&c.UserQuota, "user-quota", envInt64("WAFT_USER_QUOTA", 10<<30), "Per-account file storage quota in bytes; 0 means unlimited (WAFT_USER_QUOTA)")
	fs.IntVar(&c.MaxDevicesPerUser, "max-devices", envInt("WAFT_MAX_DEVICES", 50), "Maximum registered devices per account (WAFT_MAX_DEVICES)")
	fs.Int64Var(&c.MaxChunkSize, "max-chunk", envInt64("WAFT_MAX_CHUNK", 16<<20), "Maximum bytes accepted per PATCH request (WAFT_MAX_CHUNK)")

	fs.StringVar(&c.LogLevel, "log-level", envString("WAFT_LOG_LEVEL", "info"), "debug|info|warn|error (WAFT_LOG_LEVEL)")
	fs.StringVar(&c.LogFormat, "log-format", envString("WAFT_LOG_FORMAT", "json"), "json|text (WAFT_LOG_FORMAT)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			c.AllowedOrigins = append(c.AllowedOrigins, strings.ToLower(o))
		}
	}

	if c.NodeID == "" {
		host, _ := os.Hostname()
		c.NodeID = fmt.Sprintf("%s-%d", host, os.Getpid())
	}

	switch {
	case c.PGMaxConn < 4:
		return nil, errors.New("pg-max-conns must be at least 4")
	case c.MaxFileSize <= 0:
		return nil, errors.New("max-file-size must be positive")
	case c.MaxChunkSize < 64<<10:
		return nil, errors.New("max-chunk must be at least 64 KiB")
	case c.MaxDevicesPerUser < 1:
		return nil, errors.New("max-devices must be at least 1")
	case c.SessionTTL < time.Hour:
		return nil, errors.New("session-ttl must be at least 1h")
	}
	return c, nil
}
