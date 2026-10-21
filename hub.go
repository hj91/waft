// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	replayPageSize = 500
	settleDelay    = 2 * time.Second
)

// Hub tracks the WebSocket connections held by this node, indexed by account and device.
type Hub struct {
	mu    sync.RWMutex
	users map[string]map[string]*ClientConn // userID -> deviceID -> connection

	store      *PGStore
	broker     Broker
	nodeID     string
	log        *slog.Logger
	maxDevices int
}

func NewHub(store *PGStore, broker Broker, nodeID string, maxDevices int, log *slog.Logger) *Hub {
	return &Hub{
		users:      make(map[string]map[string]*ClientConn),
		store:      store,
		broker:     broker,
		nodeID:     nodeID,
		log:        log,
		maxDevices: maxDevices,
	}
}

// Register attaches a connection. The device row is written first so the device limit is
// enforced before the socket joins the hub. A previous socket of the same device on this
// node is evicted.
func (h *Hub) Register(ctx context.Context, c *ClientConn) error {
	if err := h.store.SetDeviceOnline(ctx, c.userID, DeviceInfo{
		DeviceID:  c.deviceID,
		Nickname:  c.nickname,
		Platform:  c.platform,
		Connected: c.connectedAt,
		RemoteIP:  c.remoteIP,
	}, h.maxDevices); err != nil {
		return err
	}

	h.mu.Lock()
	devs, ok := h.users[c.userID]
	if !ok {
		devs = make(map[string]*ClientConn)
		h.users[c.userID] = devs
	}
	old := devs[c.deviceID]
	devs[c.deviceID] = c
	h.mu.Unlock()

	if old != nil {
		h.log.Info("evicting stale socket", "user", c.userID, "device", c.deviceID)
		old.closeWith(4000, "replaced by a newer connection")
	} else {
		// One broker reference per registered device slot on this node.
		_ = h.broker.Join(ctx, c.userID)
	}

	// Tell other nodes to drop an older socket of this device that they may still hold.
	_ = h.broker.Publish(ctx, c.userID, Envelope{Type: typeEvict, SourceDevice: c.deviceID, CreatedAt: c.connectedAt})

	h.log.Info("device connected", "user", c.userID, "device", c.deviceID, "ip", c.remoteIP)
	h.publishPresence(ctx, c.userID)
	return nil
}

// Unregister detaches a connection if it is still the current one for its device.
func (h *Hub) Unregister(c *ClientConn) {
	h.mu.Lock()
	devs := h.users[c.userID]
	current := devs != nil && devs[c.deviceID] == c
	if current {
		delete(devs, c.deviceID)
		if len(devs) == 0 {
			delete(h.users, c.userID)
		}
	}
	h.mu.Unlock()
	if !current {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h.broker.Leave(ctx, c.userID)
	h.store.SetDeviceOffline(ctx, c.userID, c.deviceID, c.connectedAt)
	h.log.Info("device disconnected", "user", c.userID, "device", c.deviceID)
	h.publishPresence(ctx, c.userID)
}

// PublishAndPersist stores an event and fans it out to the account's devices.
func (h *Hub) PublishAndPersist(ctx context.Context, userID string, env *Envelope) error {
	if env.TargetDevice == "" {
		env.TargetDevice = "*"
	}
	if err := h.store.AppendEvent(ctx, userID, env); err != nil {
		return err
	}
	return h.broker.Publish(ctx, userID, *env)
}

// RouteFromBroker delivers a cluster message to this node's connections of the account.
func (h *Hub) RouteFromBroker(userID string, env Envelope) {
	h.mu.RLock()
	devs := h.users[userID]
	conns := make([]*ClientConn, 0, len(devs))
	for _, c := range devs {
		conns = append(conns, c)
	}
	h.mu.RUnlock()
	if len(conns) == 0 {
		return
	}

	if env.Type == typeRevoke {
		for _, c := range conns {
			if revokeMatches(env.Body, c.credID) {
				c.closeWith(4001, "credentials revoked")
			}
		}
		return
	}

	if env.Type == typeEvict {
		// The device reconnected (possibly on another node); close older sockets of it.
		for _, c := range conns {
			if c.deviceID == env.SourceDevice && c.connectedAt < env.CreatedAt {
				c.closeWith(4000, "replaced by a newer connection")
			}
		}
		return
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	for _, c := range conns {
		c.deliver(&env, raw)
	}
}

// ResyncAll makes every local connection re-read its account stream from PostgreSQL.
// Called after the Redis subscription recovers from an outage.
func (h *Hub) ResyncAll() {
	h.mu.RLock()
	var conns []*ClientConn
	for _, devs := range h.users {
		for _, c := range devs {
			conns = append(conns, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range conns {
		c.triggerResync(false)
	}
}

// CloseAll disconnects every socket so clients reconnect to a surviving node.
func (h *Hub) CloseAll() {
	h.mu.RLock()
	var conns []*ClientConn
	for _, devs := range h.users {
		for _, c := range devs {
			conns = append(conns, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range conns {
		c.closeWith(1001, "server shutting down")
	}
}

// RevokeCredential disconnects live sockets opened with a credential, cluster-wide.
func (h *Hub) RevokeCredential(ctx context.Context, userID, credID string) {
	env := Envelope{Type: typeRevoke, Body: credID, CreatedAt: nowMs()}
	_ = h.broker.Publish(ctx, userID, env)
}

func (h *Hub) publishPresence(ctx context.Context, userID string) {
	devices, err := h.store.ListDevices(ctx, userID)
	if err != nil {
		return
	}
	body, _ := json.Marshal(devices)
	_ = h.broker.Publish(ctx, userID, Envelope{
		Type:         TypePresence,
		SourceDevice: "cluster",
		TargetDevice: "*",
		Body:         string(body),
		CreatedAt:    nowMs(),
	})
}

// PublishPresenceFor is used by the lease sweeper after devices of a dead node go offline.
func (h *Hub) PublishPresenceFor(userIDs []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, uid := range userIDs {
		h.publishPresence(ctx, uid)
	}
}

// --- Per-connection ordered delivery with gap detection ---
//
// Each connection tracks lastSeq: the highest account sequence it has accounted for,
// whether the event was sent to it or skipped because it targeted another device. Live
// events arrive from Redis; because sequences are per account and gap-free, a jump means
// something was missed (another node published out of order, or Redis dropped it).
// Instead of guessing, the connection switches to "syncing" and reads the gap from
// PostgreSQL in order. Live events that arrive while syncing are not sent directly;
// the sync loop re-reads until it has caught up with everything it was told about.

func (c *ClientConn) deliver(env *Envelope, raw []byte) {
	if env.SeqID == 0 {
		// Control frames (presence) are best-effort and never kill the socket.
		select {
		case c.send <- raw:
		default:
		}
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.syncing {
		if env.SeqID > c.dirtyMax {
			c.dirtyMax = env.SeqID
		}
		return
	}
	switch {
	case env.SeqID <= c.lastSeq:
		return // duplicate (for example local fallback plus Redis)
	case env.SeqID == c.lastSeq+1:
		c.lastSeq = env.SeqID
		if env.visibleTo(c.deviceID) {
			select {
			case c.send <- raw:
			default:
				c.hub.log.Warn("outbound buffer full; dropping slow socket", "user", c.userID, "device", c.deviceID)
				go c.closeWith(4002, "client too slow")
			}
		}
	default:
		c.dirtyMax = env.SeqID
		c.startSyncLocked(false)
	}
}

// triggerResync starts a resync unless one is already running.
func (c *ClientConn) triggerResync(initial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.syncing {
		c.again = true
		return
	}
	c.startSyncLocked(initial)
}

func (c *ClientConn) startSyncLocked(initial bool) {
	c.syncing = true
	go c.syncLoop(initial)
}

func (c *ClientConn) syncLoop(initial bool) {
	var replayed int
	for {
		if c.isClosed() {
			return
		}
		c.mu.Lock()
		after := c.lastSeq
		c.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		events, head, err := c.hub.store.FetchDelta(ctx, c.userID, after, c.deviceID, replayPageSize)
		cancel()
		if err != nil {
			c.hub.log.Warn("resync query failed", "user", c.userID, "device", c.deviceID, "err", err)
			if errors.Is(err, ErrNotFound) {
				c.closeWith(4001, "account no longer exists")
				return
			}
			select {
			case <-c.done:
				return
			case <-time.After(time.Second):
			}
			continue
		}

		for i := range events {
			raw, _ := json.Marshal(&events[i])
			select {
			case c.send <- raw:
			case <-c.done:
				return
			}
		}
		replayed += len(events)

		c.mu.Lock()
		if len(events) == replayPageSize {
			c.lastSeq = events[len(events)-1].SeqID
			c.mu.Unlock()
			continue
		}
		// The page was short, so nothing visible remains up to head in that snapshot.
		// head can be below lastSeq only when the database was reset; the client follows
		// the authoritative cursor in sync_complete.
		c.lastSeq = head
		if c.dirtyMax > head || c.again {
			// Events arrived during the query that its snapshot did not include, or a
			// resync was requested meanwhile (for example after a Redis outage).
			c.again = false
			c.mu.Unlock()
			continue
		}
		c.dirtyMax = 0
		c.syncing = false
		cursor := c.lastSeq
		c.mu.Unlock()

		if initial {
			done, _ := json.Marshal(Envelope{
				Type:      TypeSyncComplete,
				Cursor:    cursor,
				Body:      "replayed " + strconv.Itoa(replayed) + " event(s) on node " + c.hub.nodeID,
				CreatedAt: nowMs(),
			})
			select {
			case c.send <- done:
			case <-c.done:
				return
			}
			// Settle: covers an event published in the instant before this node's Redis
			// SUBSCRIBE took effect. One cheap query per connect.
			go func() {
				select {
				case <-time.After(settleDelay):
					c.triggerResync(false)
				case <-c.done:
				}
			}()
		}
		return
	}
}

// revokeMatches implements revoke rules: "*" (every credential), "s:*" (every browser
// session), "s:*!<id>" (every session except one), or an exact credential ID.
func revokeMatches(rule, credID string) bool {
	switch {
	case rule == "*":
		return true
	case rule == "s:*":
		return strings.HasPrefix(credID, "s:")
	case strings.HasPrefix(rule, "s:*!"):
		return strings.HasPrefix(credID, "s:") && credID != rule[len("s:*!"):]
	default:
		return rule == credID
	}
}
