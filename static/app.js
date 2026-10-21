// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0
// Waft web client. All user content is rendered with textContent; nothing from the
// network is ever assigned to innerHTML.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const WATCHDOG_MS = 28000;
  const MAX_BACKOFF_MS = 15000;
  const SEG = 64 * 1024;          // GPF1 plaintext segment size
  const CHUNK = 4 * 1024 * 1024;  // upload PATCH size
  const WEB_UPLOAD_LIMIT = 1024 * 1024 * 1024;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- Small DOM helper ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function safeStorage(kind) {
    try { const s = window[kind]; s.getItem("x"); return s; } catch { return null; }
  }
  const local = safeStorage("localStorage");
  const session = safeStorage("sessionStorage");
  const lsGet = (k) => { try { return local ? local.getItem(k) : null; } catch { return null; } };
  const lsSet = (k, v) => { try { local && local.setItem(k, v); } catch {} };
  const ssGet = (k) => { try { return session ? session.getItem(k) : null; } catch { return null; } };
  const ssSet = (k, v) => { try { session && session.setItem(k, v); } catch {} };
  const ssDel = (k) => { try { session && session.removeItem(k); } catch {} };

  let toastTimer = null;
  function toast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
  }

  function rel(ms) {
    if (!ms) return "never";
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 45) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(ms).toLocaleDateString();
  }
  function bytes(n) {
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB"]; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
  }

  // ---------- API ----------
  class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

  async function api(method, path, body) {
    const opts = { method, credentials: "same-origin", headers: { "X-Waft-CSRF": "1" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok) {
      if (res.status === 401 && state.me && !path.startsWith("/v2/auth/")) signedOut("Your session ended. Sign in again.");
      throw new ApiError(res.status, (data && data.error) || `Request failed (${res.status})`);
    }
    return data;
  }

  // ---------- Crypto (identical to pkg/e2ee) ----------
  function b64(bytesArr) {
    let s = "";
    for (let i = 0; i < bytesArr.length; i += 0x8000) s += String.fromCharCode.apply(null, bytesArr.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(str) {
    const bin = atob(str); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  async function sha256Hex(buf) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
    return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function deriveKey(pass, saltB64, iterations) {
    const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: unb64(saltB64), iterations, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function sealBytes(key, plain) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
    return b64(out);
  }
  async function openBytes(key, str) {
    const raw = unb64(str);
    if (raw.length < 28) throw new Error("ciphertext too short");
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(0, 12) }, key, raw.subarray(12)));
  }
  const seal = async (obj) => sealBytes(state.key, enc.encode(JSON.stringify(obj)));
  const open = async (str) => JSON.parse(dec.decode(await openBytes(state.key, str)));
  const KEY_CHECK = "gopush-key-check-v2";

  const MAGIC = enc.encode("GPF1");
  function segNonce(prefix, i) {
    const n = new Uint8Array(12); n.set(prefix);
    new DataView(n.buffer).setUint32(8, i, false);
    return n;
  }
  function segAD(final) { const ad = new Uint8Array(5); ad.set(MAGIC); ad[4] = final ? 1 : 0; return ad; }

  async function encryptFile(key, plain, onProgress) {
    const n = plain.length;
    const segs = Math.max(1, Math.ceil(n / SEG));
    const out = new Uint8Array(12 + n + 16 * segs);
    const prefix = crypto.getRandomValues(new Uint8Array(8));
    out.set(MAGIC); out.set(prefix, 4);
    let off = 12;
    for (let i = 0; i < segs; i++) {
      const chunk = plain.subarray(i * SEG, Math.min(n, (i + 1) * SEG));
      const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: segNonce(prefix, i), additionalData: segAD(i === segs - 1) }, key, chunk));
      out.set(ct, off); off += ct.length;
      if (onProgress && i % 64 === 0) onProgress(i / segs);
    }
    return out;
  }
  async function decryptFile(key, data) {
    if (data.length < 28) throw new Error("encrypted file is truncated");
    for (let i = 0; i < 4; i++) if (data[i] !== MAGIC[i]) throw new Error("not an encrypted Waft file");
    const prefix = data.subarray(4, 12);
    const parts = []; let off = 12; let total = 0;
    for (let i = 0; off < data.length; i++) {
      const len = Math.min(SEG + 16, data.length - off);
      const final = off + len === data.length;
      if (len < 16) throw new Error("encrypted file is truncated");
      const pt = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: segNonce(prefix, i), additionalData: segAD(final) }, key, data.subarray(off, off + len)));
      parts.push(pt); total += pt.length; off += len;
    }
    const out = new Uint8Array(total); let p = 0;
    for (const part of parts) { out.set(part, p); p += part.length; }
    return out;
  }

  // ---------- State ----------
  const state = {
    me: null, key: null, deviceId: null, nickname: null,
    ws: null, connState: "offline", retry: 0, reconnectTimer: null, watchdog: null,
    lastBeat: 0, linkBroken: false, replaced: false,
    devices: [], events: [], kind: "note", forceNewKey: false,
  };

  function ensureDeviceIdentity() {
    let id = lsGet("waft_device_id");
    if (!id || !/^[A-Za-z0-9._:-]{1,64}$/.test(id)) {
      const r = crypto.getRandomValues(new Uint8Array(5));
      id = "web-" + Array.from(r, (b) => b.toString(16).padStart(2, "0")).join("");
      lsSet("waft_device_id", id);
    }
    state.deviceId = id;
    state.nickname = lsGet("waft_device_name") || defaultNickname();
  }
  function defaultNickname() {
    const ua = navigator.userAgent;
    const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
    const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
    return os ? `${browser} on ${os}` : browser;
  }
  const cursorKey = () => `waft_cursor_${state.me.id}_${state.deviceId}`;
  const getCursor = () => parseInt(lsGet(cursorKey()) || "0", 10) || 0;
  function setCursor(seq, force) {
    if (force || seq > getCursor()) lsSet(cursorKey(), String(seq));
    $("dCursor").textContent = String(getCursor());
  }

  function logConn(msg) {
    const li = h("li", {}, `${new Date().toLocaleTimeString()}  ${msg}`);
    const log = $("connLog"); log.prepend(li);
    while (log.children.length > 80) log.lastChild.remove();
  }

  // ---------- Views ----------
  function show(view) {
    for (const v of ["authView", "unlockView", "appView"]) $(v).hidden = v !== view;
  }
  function showTab(name) {
    $("streamView").hidden = name !== "stream";
    $("settingsView").hidden = name !== "settings";
    $("navStream").toggleAttribute("aria-current", name === "stream");
    $("navSettings").toggleAttribute("aria-current", name === "settings");
    if (name === "stream") $("navStream").setAttribute("aria-current", "page");
    if (name === "settings") { $("navSettings").setAttribute("aria-current", "page"); loadSettings(); }
  }

  // ---------- Auth ----------
  let registering = false;
  let authConfig = { allow_signup: true, min_password_length: 10 };

  function setAuthMode(reg) {
    registering = reg;
    $("authNameRow").hidden = !reg;
    $("authSubmit").textContent = reg ? "Create account" : "Sign in";
    $("authSwitchText").textContent = reg ? "Already have an account?" : "New here?";
    $("authSwitch").textContent = reg ? "Sign in" : "Create an account";
    $("authPassword").autocomplete = reg ? "new-password" : "current-password";
    $("authHint").hidden = !reg;
    $("authHint").textContent = `Use at least ${authConfig.min_password_length} characters.`;
    $("authError").hidden = true;
    $("authSwitch").parentElement.hidden = !reg && !authConfig.allow_signup;
  }

  $("authSwitch").onclick = () => setAuthMode(!registering);
  $("authForm").onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("authSubmit"); btn.disabled = true; $("authError").hidden = true;
    try {
      const body = { email: $("authEmail").value.trim(), password: $("authPassword").value };
      if (registering) body.display_name = $("authName").value.trim();
      state.me = await api("POST", registering ? "/v2/auth/register" : "/v2/auth/login", body);
      $("authPassword").value = "";
      afterSignIn();
    } catch (err) {
      $("authError").textContent = err.message; $("authError").hidden = false;
    } finally { btn.disabled = false; }
  };

  function afterSignIn() {
    $("whoami").textContent = state.me.email;
    const cached = ssGet(`waft_pass_${state.me.id}`);
    if (cached) { unlock(cached, false).catch(() => showUnlock()); return; }
    showUnlock();
  }

  function showUnlock(forceNew) {
    state.forceNewKey = !!forceNew;
    const fresh = !state.me.e2ee_check || forceNew;
    $("unlockLede").textContent = fresh
      ? "Choose a passphrase for end-to-end encryption. Use the same one on every device. It never leaves your devices and cannot be recovered."
      : "Enter your encryption passphrase to read and send messages on this device.";
    $("unlockConfirmRow").hidden = !fresh;
    $("unlockSubmit").textContent = fresh ? "Set passphrase" : "Unlock";
    $("unlockError").hidden = true;
    $("unlockPass").value = ""; $("unlockConfirm").value = "";
    show("unlockView");
    $("unlockPass").focus();
  }

  async function unlock(pass, remember) {
    const key = await deriveKey(pass, state.me.e2ee_salt, state.me.kdf_iterations);
    if (state.me.e2ee_check && !state.forceNewKey) {
      try {
        const plain = dec.decode(await openBytes(key, state.me.e2ee_check));
        if (plain !== KEY_CHECK) throw new Error();
      } catch { throw new Error("That passphrase does not match the one your other devices use."); }
    } else {
      const check = await sealBytes(key, enc.encode(KEY_CHECK));
      await api("PUT", "/v2/me/e2ee-check", { check, force: state.forceNewKey });
      state.me.e2ee_check = check;
      state.forceNewKey = false;
    }
    state.key = key;
    if (remember) ssSet(`waft_pass_${state.me.id}`, pass);
    enterApp();
  }

  $("unlockForm").onsubmit = async (e) => {
    e.preventDefault();
    const pass = $("unlockPass").value;
    const fresh = !$("unlockConfirmRow").hidden;
    const err = $("unlockError"); err.hidden = true;
    if (pass.length < 8) { err.textContent = "Use at least 8 characters."; err.hidden = false; return; }
    if (fresh && pass !== $("unlockConfirm").value) { err.textContent = "The two passphrases differ."; err.hidden = false; return; }
    const btn = $("unlockSubmit"); btn.disabled = true; btn.textContent = "Deriving key…";
    try { await unlock(pass, $("unlockRemember").checked); }
    catch (ex) { err.textContent = ex.message; err.hidden = false; }
    finally { btn.disabled = false; btn.textContent = fresh ? "Set passphrase" : "Unlock"; }
  };
  $("unlockSignOut").onclick = () => signOut();

  async function signOut() {
    try { await api("POST", "/v2/auth/logout"); } catch {}
    signedOut();
  }
  function signedOut(msg) {
    if (state.me) ssDel(`waft_pass_${state.me.id}`);
    disconnect();
    state.me = null; state.key = null; state.events = []; state.devices = [];
    $("stream").replaceChildren();
    setAuthMode(false);
    show("authView");
    if (msg) { $("authError").textContent = msg; $("authError").hidden = false; }
  }

  // ---------- App ----------
  function enterApp() {
    show("appView");
    showTab("stream");
    $("pDevice").textContent = `${state.nickname} (${state.deviceId})`;
    $("dCursor").textContent = String(getCursor());
    renderEvents();
    refreshDevices();
    connect();
  }

  $("navStream").onclick = () => showTab("stream");
  $("navSettings").onclick = () => showTab("settings");

  // ---------- WebSocket ----------
  function setConn(s, label) {
    state.connState = s;
    const p = $("connPill"); p.dataset.state = s; p.textContent = label;
  }
  function disconnect() {
    clearTimeout(state.reconnectTimer); clearTimeout(state.watchdog);
    if (state.ws) { state.ws.onclose = null; state.ws.close(); state.ws = null; }
    setConn("offline", "Offline");
  }
  function armWatchdog() {
    clearTimeout(state.watchdog);
    state.lastBeat = Date.now();
    state.watchdog = setTimeout(() => {
      logConn("Watchdog expired: no traffic for 28 s, dropping socket");
      if (state.ws) state.ws.close();
    }, WATCHDOG_MS);
  }
  setInterval(() => {
    if (state.lastBeat) $("dBeat").textContent = `${((Date.now() - state.lastBeat) / 1000).toFixed(0)} s ago`;
  }, 1000);

  function connect() {
    if (!state.key || state.linkBroken || state.replaced) return;
    clearTimeout(state.reconnectTimer);
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const q = new URLSearchParams({ device_id: state.deviceId, nickname: state.nickname, platform: "web", last_seq: String(getCursor()) });
    setConn("connecting", "Connecting");
    logConn(`Dialing (last_seq=${getCursor()})`);
    const ws = new WebSocket(`${proto}//${location.host}/v2/stream?${q}`);
    state.ws = ws;
    ws.onopen = () => { state.retry = 0; setConn("syncing", "Syncing"); armWatchdog(); };
    ws.onmessage = (ev) => { armWatchdog(); onFrame(JSON.parse(ev.data)).catch((e) => logConn(`Frame error: ${e.message}`)); };
    ws.onclose = (ev) => {
      clearTimeout(state.watchdog);
      if (state.ws !== ws) return;
      state.ws = null;
      setConn("offline", "Offline");
      logConn(`Closed (code ${ev.code}${ev.reason ? `: ${ev.reason}` : ""})`);
      if (ev.code === 4001) { signedOut("This browser was signed out."); return; }
      if (ev.code === 4003) { toast(ev.reason || "Device limit reached. Remove a device in Settings."); return; }
      if (ev.code === 4000) {
        state.replaced = true;
        setConn("offline", "Open in another tab");
        toast("Waft is open in another tab of this browser. Reload here to use this tab instead.");
        return;
      }
      if (state.linkBroken) return;
      state.retry++;
      const cap = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** (state.retry - 1));
      const delay = Math.floor(cap / 2 + Math.random() * cap / 2);
      setConn("connecting", "Reconnecting");
      state.reconnectTimer = setTimeout(connect, delay);
    };
  }

  async function onFrame(f) {
    switch (f.type) {
      case "heartbeat": return;
      case "error": toast(f.body); return;
      case "presence": state.devices = JSON.parse(f.body || "[]"); renderDevices(); return;
      case "sync_complete":
        setCursor(f.cursor || 0, true);
        setConn("online", "Online");
        logConn(`In sync: ${f.body}`);
        $("dNode").textContent = (f.body || "").split("node ").pop();
        return;
    }
    if (f.seq_id) setCursor(f.seq_id, false);
    const item = { ...f, secret: null, failed: false };
    if (f.ciphertext) {
      try { item.secret = await open(f.ciphertext); } catch { item.failed = true; }
    }
    if (f.type === "dismiss") return;
    if (state.events.some((e) => e.seq_id === f.seq_id)) return;
    state.events.unshift(item);
    if (state.events.length > 300) state.events.length = 300;
    renderEvents(f.seq_id);
  }

  $("linkToggle").onclick = () => {
    state.linkBroken = !state.linkBroken;
    $("linkToggle").textContent = state.linkBroken ? "Restore link" : "Simulate link break";
    if (state.linkBroken) { logConn("Link break simulated"); if (state.ws) state.ws.close(); setConn("offline", "Link broken (test)"); }
    else { state.retry = 0; connect(); }
  };

  // ---------- Devices ----------
  async function refreshDevices() {
    try { state.devices = await api("GET", "/v2/devices"); renderDevices(); } catch {}
  }
  function deviceName(id) {
    if (id === "*") return "All devices";
    const d = state.devices.find((x) => x.device_id === id);
    return d ? d.nickname : id;
  }
  function renderDevices() {
    const list = $("deviceList");
    list.replaceChildren(...state.devices.map((d) => {
      const self = d.device_id === state.deviceId;
      return h("li", { class: `device${d.online ? " online" : ""}` },
        h("span", { class: "device-name" }, d.nickname, self ? h("span", { class: "self-tag" }, "this browser") : null),
        h("span", { class: "device-meta" }, `${d.platform} · ${d.online ? "online" : `seen ${rel(d.last_seen)}`}`),
        self ? null : h("span", { class: "device-actions" },
          h("button", { class: "link", type: "button", onclick: () => { $("cTarget").value = d.device_id; $("cBody").focus(); } }, "Send to"),
          h("button", { class: "link", type: "button", onclick: () => removeDevice(d) }, "Remove")));
    }));
    const sel = $("cTarget"); const cur = sel.value;
    sel.replaceChildren(h("option", { value: "*" }, "All devices"),
      ...state.devices.filter((d) => d.device_id !== state.deviceId).map((d) => h("option", { value: d.device_id }, d.nickname)));
    sel.value = [...sel.options].some((o) => o.value === cur) ? cur : "*";
  }
  async function removeDevice(d) {
    if (!confirm(`Remove ${d.nickname}? If it still has a valid token it will reappear when it reconnects; revoke its token to block it.`)) return;
    try { await api("DELETE", `/v2/devices/${encodeURIComponent(d.device_id)}`); toast("Device removed"); refreshDevices(); }
    catch (e) { toast(e.message); }
  }

  // ---------- Stream rendering ----------
  const KIND = { push: "Note", clip: "Clipboard", mirror: "Notification", file: "File" };
  function safeHref(u) {
    try { const x = new URL(u); return x.protocol === "https:" || x.protocol === "http:" ? x.href : null; } catch { return null; }
  }
  function renderEvents(freshSeq) {
    const ol = $("stream");
    $("streamEmpty").hidden = state.events.length > 0;
    ol.replaceChildren(...state.events.map((e) => eventNode(e, e.seq_id === freshSeq)));
  }
  function eventNode(e, fresh) {
    const s = e.secret || {};
    const route = h("div", { class: "route" },
      h("span", { class: "kind" }, KIND[e.type] || e.type),
      h("span", { class: "end", title: e.source_device }, e.source_device === state.deviceId ? "This browser" : deviceName(e.source_device)),
      h("span", { class: "wire", "aria-label": "to" }),
      h("span", { class: "end", title: e.target_device }, e.target_device === state.deviceId ? "This browser" : deviceName(e.target_device)),
      h("time", { datetime: new Date(e.created_at).toISOString() }, new Date(e.created_at).toLocaleTimeString()));
    if (e.failed) {
      return h("li", { class: "event undecryptable" }, route,
        h("p", { class: "event-body" }, "Encrypted with a different passphrase. This device cannot read it."));
    }
    const actions = [];
    const href = s.url ? safeHref(s.url) : null;
    if (href) actions.push(h("a", { href, target: "_blank", rel: "noopener noreferrer" }, "Open link"));
    if (e.type === "clip" && s.body) actions.push(h("button", { class: "link", type: "button", onclick: () => copy(s.body) }, "Copy"));
    if (e.type === "file") actions.push(h("button", { class: "link", type: "button", onclick: (ev) => downloadFile(e, ev.target) }, `Download ${s.file_name || "file"} (${bytes(s.file_size || 0)})`));
    const title = e.type === "file" ? (s.file_name || "File") : (s.title || "");
    return h("li", { class: `event${fresh ? " fresh" : ""}` }, route,
      title ? h("div", { class: "event-title" }, s.app_name && e.type === "mirror" ? `${s.app_name}: ${title}` : title) : null,
      s.body && e.type !== "file" ? h("p", { class: "event-body" }, s.body) : null,
      href && !s.body ? h("p", { class: "event-body" }, href) : null,
      actions.length ? h("div", { class: "event-actions" }, actions) : null);
  }
  $("clearStream").onclick = () => { state.events = []; renderEvents(); };

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Clipboard access was blocked by the browser"); }
  }

  // ---------- Composer ----------
  function setKind(kind) {
    state.kind = kind;
    for (const b of document.querySelectorAll(".composer-tabs button")) b.setAttribute("aria-selected", String(b.dataset.kind === kind));
    $("cTitle").hidden = kind === "clip" || kind === "file";
    $("cUrl").hidden = kind !== "link";
    $("cBody").hidden = kind === "file";
    $("cFileRow").hidden = kind !== "file";
    $("cBody").placeholder = kind === "clip" ? "Text to put on your other devices' clipboard" : kind === "link" ? "Note (optional)" : "Message";
    $("cSend").textContent = kind === "file" ? "Send file" : "Send";
    $("cStatus").textContent = "";
  }
  for (const b of document.querySelectorAll(".composer-tabs button")) b.onclick = () => setKind(b.dataset.kind);

  $("composer").onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("cSend"); const status = $("cStatus");
    const target = $("cTarget").value;
    btn.disabled = true; status.textContent = "";
    try {
      if (state.kind === "file") { await uploadFile(target); return; }
      const title = $("cTitle").value.trim(), body = $("cBody").value, url = $("cUrl").value.trim();
      let payload, type = "push";
      if (state.kind === "clip") { if (!body) return; payload = { title: "Clipboard", body }; type = "clip"; }
      else if (state.kind === "link") {
        if (!safeHref(url)) { status.textContent = "Enter a full http or https address."; return; }
        payload = { title: title || url, body, url };
      } else { if (!title && !body) return; payload = { title, body }; }
      status.textContent = "Encrypting…";
      const ciphertext = await seal(payload);
      await api("POST", "/v2/pushes", { type, target_device: target, source_device: state.deviceId, ciphertext });
      $("cTitle").value = ""; $("cBody").value = ""; $("cUrl").value = "";
      status.textContent = "Sent";
    } catch (err) { status.textContent = err.message; }
    finally { btn.disabled = false; }
  };

  async function uploadFile(target) {
    const input = $("cFile"); const status = $("cStatus");
    if (!input.files.length) { status.textContent = "Choose a file first."; return; }
    const file = input.files[0];
    if (file.size > WEB_UPLOAD_LIMIT) { status.textContent = "Files over 1 GB: send them with the waft CLI."; return; }
    if (state.me.max_file_size && file.size > state.me.max_file_size) { status.textContent = `This server accepts files up to ${bytes(state.me.max_file_size)}.`; return; }
    const bar = $("cProgress"); bar.parentElement.hidden = false; bar.style.width = "0%";
    status.textContent = "Reading…";
    const plain = new Uint8Array(await file.arrayBuffer());
    const plainSHA = await sha256Hex(plain);
    status.textContent = "Encrypting…";
    const cipher = await encryptFile(state.key, plain, (p) => { bar.style.width = `${Math.round(p * 30)}%`; });
    const cipherSHA = await sha256Hex(cipher);
    const meta = await seal({ title: `File: ${file.name}`, file_name: file.name, file_sha256: plainSHA, file_size: file.size, mime_type: file.type || "application/octet-stream" });
    const sess = await api("POST", "/v2/files", {
      file_name: "encrypted.gpf", source_device: state.deviceId, target_device: target,
      total_size: cipher.length, expected_sha256: cipherSHA, ciphertext_meta: meta,
    });
    let offset = 0, failures = 0;
    while (offset < cipher.length) {
      try {
        const res = await fetch(`/v2/files/${sess.file_id}`, {
          method: "PATCH", credentials: "same-origin",
          headers: { "X-Waft-CSRF": "1", "Content-Type": "application/offset+octet-stream", "Upload-Offset": String(offset) },
          body: cipher.subarray(offset, Math.min(offset + CHUNK, cipher.length)),
        });
        if (res.status === 409 || res.status === 423) { offset = parseInt(res.headers.get("Upload-Offset") || "0", 10); await sleep(500); continue; }
        if (res.status === 422 || res.status === 410 || res.status === 404) { throw new ApiError(res.status, "The server rejected the upload. Try again."); }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        offset = parseInt(res.headers.get("Upload-Offset"), 10);
        failures = 0;
        bar.style.width = `${30 + Math.round((offset / cipher.length) * 70)}%`;
        status.textContent = `Uploading ${bytes(offset)} of ${bytes(cipher.length)}`;
      } catch (err) {
        if (err instanceof ApiError || ++failures > 20) throw err;
        status.textContent = "Connection dropped, resuming…";
        await sleep(Math.min(5000, 500 * failures));
        try {
          const head = await fetch(`/v2/files/${sess.file_id}`, { method: "HEAD", credentials: "same-origin" });
          if (head.ok) offset = parseInt(head.headers.get("Upload-Offset") || "0", 10);
        } catch {}
      }
    }
    status.textContent = "Sent and verified";
    input.value = "";
    setTimeout(() => { bar.parentElement.hidden = true; }, 1500);
  }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function downloadFile(e, btn) {
    const s = e.secret || {};
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = "Downloading…";
    try {
      const res = await fetch(e.url, { credentials: "same-origin" });
      if (!res.ok) throw new Error(res.status === 404 ? "This file has expired or was deleted." : `Download failed (${res.status})`);
      const data = new Uint8Array(await res.arrayBuffer());
      if (e.file_sha256 && (await sha256Hex(data)) !== e.file_sha256) throw new Error("Downloaded data is corrupted.");
      btn.textContent = "Decrypting…";
      const plain = await decryptFile(state.key, data);
      if (s.file_sha256 && (await sha256Hex(plain)) !== s.file_sha256) throw new Error("Decrypted file does not match its checksum.");
      const url = URL.createObjectURL(new Blob([plain], { type: s.mime_type || "application/octet-stream" }));
      const a = h("a", { href: url, download: (s.file_name || "waft-file").replace(/[\\/]/g, "_") });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
      btn.textContent = label;
    } catch (err) { toast(err.message); btn.textContent = label; }
    finally { btn.disabled = false; }
  }

  // ---------- Settings ----------
  async function loadSettings() {
    try {
      const me = await api("GET", "/v2/me");
      Object.assign(state.me, me);
      $("pName").value = me.display_name;
      $("pEmail").textContent = me.email;
      $("pStorage").textContent = me.storage_quota ? `${bytes(me.storage_used)} of ${bytes(me.storage_quota)}` : `${bytes(me.storage_used)} used`;
      $("pSelfName").value = state.nickname;
    } catch {}
    loadTokens(); loadSessions(); loadAudit();
  }

  $("profileForm").onsubmit = async (e) => {
    e.preventDefault();
    try { await api("PATCH", "/v2/me", { display_name: $("pName").value }); toast("Name saved"); } catch (err) { toast(err.message); }
  };
  $("selfNameForm").onsubmit = async (e) => {
    e.preventDefault();
    const name = $("pSelfName").value.trim(); if (!name) return;
    state.nickname = name; lsSet("waft_device_name", name);
    $("pDevice").textContent = `${state.nickname} (${state.deviceId})`;
    try { await api("PATCH", `/v2/devices/${encodeURIComponent(state.deviceId)}`, { nickname: name }); } catch {}
    toast("Browser renamed");
  };
  $("pwForm").onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api("POST", "/v2/me/password", { current_password: $("pwCurrent").value, new_password: $("pwNew").value });
      $("pwCurrent").value = ""; $("pwNew").value = "";
      toast("Password changed. Other browsers were signed out.");
      loadSessions();
    } catch (err) { toast(err.message); }
  };

  async function loadTokens() {
    const list = await api("GET", "/v2/tokens").catch(() => []);
    $("tokenList").replaceChildren(...list.map((t) => h("li", {},
      h("span", {}, t.name, h("span", { class: "sub" },
        `${t.prefix}… · created ${rel(t.created_at)} · used ${rel(t.last_used_at)}${t.expires_at ? ` · expires ${new Date(t.expires_at).toLocaleDateString()}` : ""}`)),
      h("button", { class: "secondary", type: "button", onclick: async () => {
        if (!confirm(`Revoke "${t.name}"? Anything using it disconnects immediately.`)) return;
        try { await api("DELETE", `/v2/tokens/${t.id}`); toast("Token revoked"); loadTokens(); } catch (err) { toast(err.message); }
      } }, "Revoke"))));
    if (!list.length) $("tokenList").replaceChildren(h("li", { class: "hint" }, "No tokens yet."));
  }
  $("tokenForm").onsubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await api("POST", "/v2/tokens", { name: $("tName").value.trim() || "Token", expires_in_days: parseInt($("tExpiry").value, 10) });
      $("tokenValue").textContent = res.token;
      $("tokenSnippet").textContent =
        `export WAFT_SERVER=${location.origin}\nexport WAFT_TOKEN=${res.token}\nexport WAFT_KEY='your encryption passphrase'\n\npb "hello from the terminal"\nwaftd`;
      $("tokenReveal").hidden = false; $("tName").value = "";
      loadTokens();
    } catch (err) { toast(err.message); }
  };
  $("tokenCopy").onclick = () => copy($("tokenValue").textContent);

  async function loadSessions() {
    const list = await api("GET", "/v2/sessions").catch(() => []);
    $("sessionList").replaceChildren(...list.map((s) => h("li", {},
      h("span", {}, s.current ? "This browser" : (s.user_agent || "Unknown browser").slice(0, 80),
        h("span", { class: "sub" }, `${s.ip} · active ${rel(s.last_seen_at)} · signed in ${new Date(s.created_at).toLocaleDateString()}`)),
      s.current ? null : h("button", { class: "secondary", type: "button", onclick: async () => {
        try { await api("DELETE", `/v2/sessions/${s.id}`); loadSessions(); } catch (err) { toast(err.message); }
      } }, "Sign out"))));
  }
  $("logoutAll").onclick = async () => {
    if (!confirm("Sign out of every browser, including this one?")) return;
    try { await api("POST", "/v2/auth/logout-all"); } catch {}
    signedOut("Signed out everywhere.");
  };

  async function loadAudit() {
    const list = await api("GET", "/v2/audit").catch(() => []);
    const words = {
      "account.created": "Account created", "login.succeeded": "Signed in", "login.failed": "Failed sign-in",
      "logout": "Signed out", "logout.all": "Signed out everywhere", "password.changed": "Password changed",
      "token.created": "Token created", "token.revoked": "Token revoked", "session.revoked": "Browser signed out",
      "device.removed": "Device removed", "reauth.failed": "Wrong password confirmation", "e2ee.key_check_replaced": "Encryption passphrase replaced",
    };
    $("auditList").replaceChildren(...list.slice(0, 30).map((a) => h("li", {},
      h("span", {}, words[a.action] || a.action, a.detail ? h("span", { class: "sub" }, a.detail) : null),
      h("span", { class: "sub" }, `${a.ip} · ${new Date(a.created_at).toLocaleString()}`))));
  }

  $("lockNow").onclick = () => { ssDel(`waft_pass_${state.me.id}`); state.key = null; disconnect(); showUnlock(); };
  $("resetKey").onclick = () => {
    if (!confirm("Set a new encryption passphrase? Your other devices will need it too, and older messages stay readable only with the old one.")) return;
    ssDel(`waft_pass_${state.me.id}`); state.key = null; disconnect(); showUnlock(true);
  };

  $("deleteForm").onsubmit = async (e) => {
    e.preventDefault();
    if (!confirm("Delete your account, devices, messages and files permanently?")) return;
    try { await api("POST", "/v2/me/delete", { password: $("delPass").value }); signedOut("Your account was deleted."); }
    catch (err) { toast(err.message); }
  };

  // ---------- Boot ----------
  async function boot() {
    ensureDeviceIdentity();
    try { authConfig = await api("GET", "/v2/auth/config"); } catch {}
    try {
      state.me = await api("GET", "/v2/me");
      afterSignIn();
    } catch {
      state.me = null;
      setAuthMode(false);
      show("authView");
    }
  }
  setKind("note");
  boot();
})();
