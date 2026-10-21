// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"strconv"
)

const pushBodyLimit = 160 << 10

// GET /v2/pushes?after=N&device_id=X&limit=L
// Returns the account's events after N (visible to device_id when given) plus the head
// cursor, so a REST poller can page with the same semantics as the WebSocket stream.
func (s *Server) handleListPushes(w http.ResponseWriter, r *http.Request, p *Principal) {
	q := r.URL.Query()
	afterRaw := q.Get("after")
	if afterRaw == "" {
		afterRaw = q.Get("modified_after") // v1 parameter name
	}
	after, _ := strconv.ParseInt(afterRaw, 10, 64)
	if after < 0 {
		after = 0
	}
	deviceID := q.Get("device_id")
	if deviceID == "" {
		deviceID = "*"
	} else if !validDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, head, err := s.store.FetchDelta(r.Context(), p.User.ID, after, deviceID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	cursor := head
	more := len(events) == limit
	if more {
		cursor = events[len(events)-1].SeqID
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "cursor": cursor, "has_more": more})
}

// POST /v2/pushes   body: Envelope (ciphertext, target_device, type, source_device)
func (s *Server) handleCreatePush(w http.ResponseWriter, r *http.Request, p *Principal) {
	var env Envelope
	if !readJSON(w, r, &env, pushBodyLimit) {
		return
	}
	if env.Type == "" {
		env.Type = TypePush
	}
	source := env.SourceDevice
	if source == "" {
		source = "api"
	}
	if !validDeviceID(source) {
		writeError(w, http.StatusBadRequest, "invalid source_device")
		return
	}
	if err := s.sanitizeClientEvent(&env, source); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.hub.PublishAndPersist(r.Context(), p.User.ID, &env); err != nil {
		s.log.Error("persist event failed", "user", p.User.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "event not stored")
		return
	}
	writeJSON(w, http.StatusCreated, env)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, p *Principal) {
	devices, err := s.store.ListDevices(r.Context(), p.User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	var req struct {
		Nickname string `json:"nickname"`
	}
	if !readJSON(w, r, &req, 4<<10) {
		return
	}
	name := cleanLabel(req.Nickname, 64)
	if !validDeviceID(id) || name == "" {
		writeError(w, http.StatusBadRequest, "valid device id and nickname required")
		return
	}
	ok, err := s.store.RenameDevice(r.Context(), p.User.ID, id, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	s.hub.publishPresence(r.Context(), p.User.ID)
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /v2/devices/{id} forgets a device and disconnects it if online.
func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if !validDeviceID(id) {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	ok, err := s.store.DeleteDevice(r.Context(), p.User.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	_ = s.broker.Publish(r.Context(), p.User.ID, Envelope{Type: typeEvict, SourceDevice: id, CreatedAt: nowMs() + 1})
	s.store.Audit(r.Context(), p.User.ID, "device.removed", s.clientIP(r), r.UserAgent(), id)
	s.hub.publishPresence(r.Context(), p.User.ID)
	w.WriteHeader(http.StatusNoContent)
}
