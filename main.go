// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

// Command waft-server is a multi-tenant, end-to-end encrypted device messaging bus:
// pushes, universal clipboard, notification mirroring and resumable file transfer.
//
// Stateless Go nodes keep WebSocket connections; PostgreSQL is the source of truth with a
// gap-free per-account sequence; Redis Pub/Sub fans events out between nodes on
// per-account channels. See README for the architecture.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func newLogger(cfg *Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h).With("node", cfg.NodeID)
}

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, flagErrHelp) {
			os.Exit(0)
		}
		slog.Error("invalid configuration", "err", err)
		os.Exit(2)
	}
	log := newLogger(cfg)
	if err := run(cfg, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfg *Config, log *slog.Logger) error {
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !cfg.CookieSecure {
		log.Warn("session cookies are not marked Secure; use only for local plain-HTTP testing")
	}

	startCtx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	store, err := NewPGStore(startCtx, cfg.PGDSN, cfg.PGMaxConn, cfg.NodeID, log)
	cancel()
	if err != nil {
		return err
	}
	defer store.Close()

	startCtx, cancel = context.WithTimeout(rootCtx, 10*time.Second)
	broker, err := NewRedisBroker(startCtx, cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB, cfg.NodeID, log)
	cancel()
	if err != nil {
		return err
	}
	defer func() { _ = broker.Close() }()

	hub := NewHub(store, broker, cfg.NodeID, cfg.MaxDevicesPerUser, log)
	files, err := NewFileManager(cfg, store, hub, log)
	if err != nil {
		return err
	}
	srv := NewServer(cfg, log, store, broker, hub, files)

	bgCtx, bgCancel := context.WithCancel(context.Background())
	var bg sync.WaitGroup
	broker.Start(bgCtx, hub.RouteFromBroker, hub.ResyncAll)
	bg.Add(2)
	go func() { defer bg.Done(); store.StartNodeLeaseLoop(bgCtx, hub.PublishPresenceFor) }()
	go func() { defer bg.Done(); runMaintenance(bgCtx, cfg, store, files, log) }()

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		// No global Read/WriteTimeout: WebSockets and large downloads are long-lived.
		// Chunk uploads set their own read deadline per request.
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("waft node online", "addr", cfg.Addr, "signup", cfg.AllowSignup, "require_e2ee", cfg.RequireE2EE)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-rootCtx.Done():
	case err := <-errCh:
		if err != nil {
			bgCancel()
			bg.Wait()
			return err
		}
	}

	log.Info("shutting down: closing sockets so clients fail over")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx) // stop accepting, finish in-flight REST calls
	hub.CloseAll()                    // hijacked WebSockets are not covered by Shutdown
	time.Sleep(300 * time.Millisecond)
	bgCancel() // lease loop marks this node's devices offline and drops its lease
	bg.Wait()
	return nil
}

// runMaintenance applies retention every 10 minutes on whichever node wins the lock.
func runMaintenance(ctx context.Context, cfg *Config, store *PGStore, files *FileManager, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	timer := time.NewTimer(30 * time.Second) // first pass shortly after start
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-ticker.C:
		}
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		res, ran, err := store.RunMaintenance(runCtx, cfg.EventRetention, cfg.FileRetention, cfg.StaleUploadTTL)
		cancel()
		if err != nil {
			log.Warn("maintenance failed", "err", err)
		}
		if !ran || res == nil {
			continue
		}
		for _, f := range res.ExpiredFiles {
			files.removeFromDisk(f.UserID, f.FileID)
		}
		if res.ExpiredSessions+res.PrunedEvents+int64(len(res.ExpiredFiles)) > 0 {
			log.Info("maintenance", "expired_sessions", res.ExpiredSessions, "pruned_events", res.PrunedEvents, "expired_files", len(res.ExpiredFiles))
		}
	}
}
