// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	userChannelPrefix = "waft:u:"
	nodeChannelPrefix = "waft:node:"
)

// Broker fans events out across cluster nodes. Each node subscribes only to the channels
// of accounts that currently have a device connected to it, so a publish costs O(nodes
// holding that account) instead of O(all nodes x all sockets).
type Broker interface {
	Publish(ctx context.Context, userID string, env Envelope) error
	Join(ctx context.Context, userID string) error
	Leave(ctx context.Context, userID string)
	Ping(ctx context.Context) error
}

type RedisBroker struct {
	client *redis.Client
	ps     *redis.PubSub
	nodeID string
	log    *slog.Logger

	// opMu serialises SUBSCRIBE/UNSUBSCRIBE so the order sent to Redis matches the
	// refcount transitions; otherwise a fast leave-then-join could end unsubscribed.
	opMu sync.Mutex
	refs map[string]int

	onMessage   func(userID string, env Envelope)
	onReconnect func()

	// downUntil is a tiny circuit breaker: after a failed PUBLISH, further publishes skip
	// Redis for a moment instead of each waiting out dial timeouts and retries.
	downUntil atomic.Int64
}

const publishBreakerWindow = 2 * time.Second

func NewRedisBroker(ctx context.Context, addr, pass string, db int, nodeID string, log *slog.Logger) (*RedisBroker, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:            addr,
		Password:        pass,
		DB:              db,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		PoolSize:        32,
		MinIdleConns:    4,
		MaxRetries:      1,
		MinRetryBackoff: 100 * time.Millisecond,
		MaxRetryBackoff: 2 * time.Second,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("initial redis ping failed: %w", err)
	}
	b := &RedisBroker{
		client: rdb,
		nodeID: nodeID,
		log:    log,
		refs:   make(map[string]int),
	}
	// The per-node channel keeps the connection in subscribe mode even with no accounts.
	b.ps = rdb.Subscribe(ctx, nodeChannelPrefix+nodeID)
	return b, nil
}

// Start begins receiving. Handlers must be set before Start.
func (b *RedisBroker) Start(ctx context.Context, onMessage func(string, Envelope), onReconnect func()) {
	b.onMessage = onMessage
	b.onReconnect = onReconnect
	go b.receiveLoop(ctx)
}

func (b *RedisBroker) Publish(ctx context.Context, userID string, env Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	// Devices on this node always get the event now. Devices on other nodes recover a
	// missed one from PostgreSQL through gap detection or the post-outage resync.
	if time.Now().UnixNano() < b.downUntil.Load() {
		b.deliverLocal(userID, env)
		return nil
	}
	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := b.client.Publish(pubCtx, userChannelPrefix+userID, raw).Err(); err != nil {
		if b.downUntil.Swap(time.Now().Add(publishBreakerWindow).UnixNano()) == 0 {
			b.log.Warn("redis publish failed; delivering locally", "err", err)
		}
		b.deliverLocal(userID, env)
	} else if b.downUntil.Load() != 0 {
		b.downUntil.Store(0)
	}
	return nil
}

func (b *RedisBroker) deliverLocal(userID string, env Envelope) {
	if b.onMessage != nil {
		b.onMessage(userID, env)
	}
}

// Join subscribes this node to an account channel (reference counted). It returns once
// the SUBSCRIBE command has been written; the caller runs a settle resync afterwards to
// cover the instant before Redis applies it.
func (b *RedisBroker) Join(ctx context.Context, userID string) error {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	b.refs[userID]++
	if b.refs[userID] > 1 {
		return nil
	}
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// go-redis records the channel even if the write fails and re-subscribes on reconnect.
	if err := b.ps.Subscribe(subCtx, userChannelPrefix+userID); err != nil {
		b.log.Warn("redis subscribe failed; will retry on reconnect", "err", err)
	}
	return nil
}

func (b *RedisBroker) Leave(ctx context.Context, userID string) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	if b.refs[userID] <= 0 {
		return
	}
	b.refs[userID]--
	if b.refs[userID] > 0 {
		return
	}
	delete(b.refs, userID)
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = b.ps.Unsubscribe(subCtx, userChannelPrefix+userID)
}

func (b *RedisBroker) Ping(ctx context.Context) error {
	return b.client.Ping(ctx).Err()
}

// receiveLoop reads the subscription. go-redis reconnects a broken PubSub connection
// transparently, which means messages published during the outage are silently lost.
// Any receive error is therefore remembered, and the first successful receive after it
// triggers onReconnect so every local connection resyncs from PostgreSQL.
func (b *RedisBroker) receiveLoop(ctx context.Context) {
	broken := false
	backoff := 250 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		msg, err := b.ps.ReceiveTimeout(ctx, 5*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Idle link: prove it is alive. A failed ping marks it broken; a good one
				// after an outage means the re-subscribed connection is healthy again.
				pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				perr := b.ps.Ping(pingCtx)
				cancel()
				if perr == nil {
					if broken {
						broken = false
						backoff = 250 * time.Millisecond
						b.log.Info("redis subscription restored; resyncing local connections")
						if b.onReconnect != nil {
							b.onReconnect()
						}
					}
					continue
				}
				err = perr
			}
			b.log.Debug("redis receive error", "err", err)
			if !broken {
				b.log.Warn("redis subscription broken; events will be gap-filled from PostgreSQL", "err", err)
			}
			broken = true
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 250 * time.Millisecond
		if broken {
			broken = false
			b.log.Info("redis subscription restored; resyncing local connections")
			if b.onReconnect != nil {
				b.onReconnect()
			}
		}

		m, ok := msg.(*redis.Message)
		if !ok {
			continue // *redis.Subscription confirmations and *redis.Pong
		}
		userID, ok := strings.CutPrefix(m.Channel, userChannelPrefix)
		if !ok {
			continue
		}
		var env Envelope
		if err := json.Unmarshal([]byte(m.Payload), &env); err != nil {
			continue
		}
		if b.onMessage != nil {
			b.onMessage(userID, env)
		}
	}
}

func (b *RedisBroker) Close() error {
	_ = b.ps.Close()
	return b.client.Close()
}

// RedisRateLimiter is a cluster-wide fixed-window limiter. It fails open when Redis is
// unavailable so an outage never locks every user out.
type RedisRateLimiter struct {
	client *redis.Client
	log    *slog.Logger
}

// Allow increments key within window and reports whether the count is within limit.
func (l *RedisRateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	k := "waft:rl:" + key
	pipe := l.client.TxPipeline()
	incr := pipe.Incr(ctx, k)
	pipe.ExpireNX(ctx, k, window)
	if _, err := pipe.Exec(ctx); err != nil {
		l.log.Warn("rate limiter unavailable; failing open", "err", err)
		return true
	}
	return incr.Val() <= limit
}

// Reset clears a counter (for example after a successful login).
func (l *RedisRateLimiter) Reset(ctx context.Context, key string) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = l.client.Del(ctx, "waft:rl:"+key).Err()
}
