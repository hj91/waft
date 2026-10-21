# Waft

![Licence: Apache 2.0](https://img.shields.io/badge/licence-Apache%202.0-2f5bea)

Waft is a self-hosted, multi-user, end-to-end encrypted device bus: pushes, universal clipboard, notification mirroring and resumable file transfer between a person's own devices.

Every account is fully isolated. The server stores only ciphertext, and it cannot read messages, clipboard text, file names or file contents.

Stateless Go nodes hold WebSocket connections. PostgreSQL is the source of truth, with a gap-free sequence per account. Redis Pub/Sub fans events out between nodes on per-account channels.

---

## What changed from the v1 prototype

Waft began as a single-user prototype under the working name GoPush. Version 2 is a rework of that prototype:

| Area | v1 | v2 |
| --- | --- | --- |
| Accounts | None. Anyone could read every event and download every file. | Email + password accounts (Argon2id), HttpOnly session cookies for the web app, revocable API tokens for `waft` and `waftd`. |
| Isolation | One global stream. | Every table is keyed by account. Another account's file ID returns 404 exactly like a missing one. |
| Encryption | One global PBKDF2 salt (same passphrase = same key for everyone). File contents were sent in plaintext. | Per-account random salt, 600 000 PBKDF2 iterations, key-check value to catch a mismatched passphrase, file contents encrypted in authenticated 64 KiB segments (GPF1). |
| Ordering | One global advisory lock serialised every insert in the cluster. | One `UPDATE ... RETURNING` on the account's counter row: writers of the same account are ordered; different accounts never contend. |
| Fan-out | Every event checked against every socket; presence pushed the full device table to everyone. | Each node subscribes only to channels of accounts it currently serves; presence is per account. |
| Delivery | Events committed between replay and registration were lost; backlog above 200 was lost; out-of-order frames across nodes were dropped; go-redis reconnects silently so "gap-fill" rarely ran; `serveWS` could panic. | Per-connection gap detection with ordered PostgreSQL resync, paged replay without limit, explicit Redis outage detection, publish circuit breaker, no closed-channel sends. |
| Files | In-memory per-node lock (two nodes could write the same file), client-chosen MIME type served back. | Cluster-wide write lease in PostgreSQL, quotas, retention, always `application/octet-stream`. |
| Web UI | Stored XSS through `innerHTML`; `javascript:` URLs clickable; any origin could open the WebSocket. | Text-only rendering, strict CSP (`script-src 'self'`), Origin checks, CSRF header, sign-in, settings, tokens, sessions, activity log. |
| Operations | Postgres and Redis published to the host with default passwords; no Dockerfile. | Internal network only, passwords from `.env`, non-root image, `/readyz`, structured JSON logs, retention jobs. |

---

## Architecture

```text
 browser / waft / waftd
          |  HTTPS + WSS
        nginx  (TLS, per-IP limit on login)
       /     \
  node-alpha  node-beta        stateless Go, embedded web app
      |   \     /   |
      |    Redis    |          waft:u:<account>  (one channel per account)
      |             |
      +--PostgreSQL-+          users, sessions, api_tokens, devices,
                               events (account, seq), file_transfers, audit_log
      shared upload volume     <uploads>/<account>/<file>.bin
```

### Delivery guarantees

1. A client sends an event. The node appends it with the next per-account `seq_id` in a single statement, then publishes it on the account's Redis channel.
2. Each connection tracks `lastSeq`, the highest account sequence it has accounted for. That includes events skipped because they target another device.
3. A live frame with `seq == lastSeq + 1` is sent. A duplicate is dropped. A jump means something was missed, so the connection switches to syncing and reads the gap from PostgreSQL in order.
4. The initial connect is the same path: register (and subscribe) first, then read the backlog from a repeatable-read snapshot in pages of 500. Frames that arrive meanwhile are not lost, because the loop re-reads until it has caught up with everything it was told about.
5. `sync_complete` carries the authoritative `cursor`. If the client's cursor is ahead of the server (for example after a database restore), it is moved back.
6. If the Redis subscription breaks, the node remembers it and resyncs every local connection as soon as the link is proven healthy. While Redis is down, publishes skip it for 2 seconds at a time and deliver locally, so pushes stay fast.

### Node failure

Every node renews a lease in `cluster_nodes` every 5 seconds against a 15 second TTL. Devices pinned to an expired node are shown offline immediately and swept, and their accounts get a presence update. On a graceful shutdown, a node closes its sockets with code 1001 so clients reconnect to a surviving node.

---

## Security model

- **Passwords:** Argon2id (m=19 MiB, t=2, p=1), constant-time comparison, a dummy verification for unknown emails (no account enumeration), automatic rehash when parameters rise.
- **Sessions:** 256-bit random tokens, stored only as SHA-256 digests. Cookie `__Host-waft_session` is `HttpOnly`, `Secure` and `SameSite=Strict`, and lasts 30 days.
- **API tokens:** prefix `gpt_`, 256-bit, shown once, stored as digests. They can only be created from a signed-in browser, never by another token. Optional expiry; revocation closes live sockets on every node within milliseconds.
- **CSRF:** cookie-authenticated state changes need the `X-Waft-CSRF` header and a matching Origin. WebSocket upgrades with a cookie must come from an allowed origin.
- **Rate limits (Redis, cluster-wide):** login 30 per IP and 20 per email per 15 minutes; registration 10 per IP per hour; password re-checks 10 per account per 15 minutes; 20 frames per second per socket. These fail open if Redis is down. Nginx adds a coarse per-IP limit on the auth endpoints.
- **Password change:** signs out every other browser and closes their sockets. API tokens are separate credentials and keep working.
- **E2EE strict mode (`-require-e2ee`, default on):** the server rejects events that carry plaintext title, body or URL, and uploads without encrypted metadata.
- **Audit log:** sign-ins, failures, token and session changes, device removal and passphrase replacement. Visible to the account owner in Settings.
- **Account deletion:** cascades through every table and removes the account's files from disk.

What the server still sees: account email, device IDs and nicknames, event types and timestamps, routing (source and target device), sizes, and IP addresses. It never sees passphrases, keys or content.

### E2EE format

```text
key      = PBKDF2-HMAC-SHA256(passphrase, account_salt[16], 600000) -> AES-256
event    = base64( nonce[12] || AES-GCM(json payload) || tag[16] )
file     = "GPF1" || prefix[8] || seg_0 || seg_1 || ...
seg_i    = AES-GCM(plain[i*64KiB : (i+1)*64KiB], nonce = prefix || u32be(i), ad = "GPF1" || final)
```

Reordered, truncated, extended or modified files fail authentication. `pkg/e2ee` (Go) and `static/app.js` (WebCrypto) produce identical bytes.

---

## Quick start (Docker Compose)

```bash
cp .env.example .env          # set POSTGRES_PASSWORD and REDIS_PASSWORD
docker compose up --build -d
curl -s http://localhost:8080/readyz
```

Open `http://localhost:8080`, create an account and choose an encryption passphrase. The first account created becomes the admin. Set `WAFT_ALLOW_SIGNUP=false` afterwards to close registration.

For production, terminate TLS in Nginx or a load balancer and keep `WAFT_COOKIE_SECURE=true`. The `.env.example` sets it to `false` only so plain `http://localhost` works.

---

## Command-line tools

Create a token in **Settings > API tokens**, then:

```bash
export WAFT_SERVER=https://push.example.com
export WAFT_TOKEN=gpt_...
export WAFT_KEY='your encryption passphrase'

waft "Build finished"                         # push to all your devices
waft -to thinkpad-linux -t "Deploy" "v2.4.1"  # push to one device
waft -url https://example.com "read later"    # push a link
make 2>&1 | tail -20 | waft -t "make output"  # body from stdin
waft -file ./firmware.bin                     # encrypted resumable upload
waft -devices                                 # list devices

waftd -id thinkpad-linux -name "ThinkPad"   # Linux daemon: notifications, clipboard, downloads
```

Secrets can also come from files (`-token-file`, `-key-file`), which keeps them out of the process list. `waftd` stores its resume cursor per account and device under `~/.local/share/waft/`, and saves verified downloads to `~/Downloads/Waft` without ever overwriting an existing file.

---

## Installing the command-line tools

```bash
go install github.com/hj91/waft/cmd/waft@latest    # CLI
go install github.com/hj91/waft/cmd/waftd@latest   # Linux daemon
```

## Building from source

```bash
go mod tidy                     # creates go.sum on first build
go test ./...
go build -o bin/waft-server .
go build -o bin/waft ./cmd/waft
go build -o bin/waftd ./cmd/waftd
```

The web app is embedded with `go:embed`, so `waft-server` is a single self-contained binary. Requirements: Go 1.23+, PostgreSQL 13+ (16 recommended), Redis 7+.

### Configuration

Every flag has an environment variable. Flags win.

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `-addr` | `WAFT_ADDR` | `:8080` | Listen address |
| `-node-id` | `WAFT_NODE_ID` | host-pid | Unique per node |
| `-pg` | `WAFT_PG_DSN` | local | PostgreSQL DSN |
| `-pg-max-conns` | `WAFT_PG_MAX_CONNS` | 30 | Pool size per node |
| `-redis` | `WAFT_REDIS_ADDR` | `localhost:6379` | Redis address |
| `-redis-pass` | `WAFT_REDIS_PASSWORD` | | Redis password |
| `-uploads` | `WAFT_UPLOAD_DIR` | `./uploads` | Shared file storage |
| `-allow-signup` | `WAFT_ALLOW_SIGNUP` | true | Public registration |
| `-cookie-secure` | `WAFT_COOKIE_SECURE` | true | Secure cookies (HTTPS) |
| `-trust-proxy` | `WAFT_TRUST_PROXY` | false | Use X-Real-IP from the proxy |
| `-allowed-origins` | `WAFT_ALLOWED_ORIGINS` | | Extra browser origins |
| `-require-e2ee` | `WAFT_REQUIRE_E2EE` | true | Reject plaintext events |
| `-session-ttl` | `WAFT_SESSION_TTL` | 720h | Session lifetime |
| `-event-retention` | `WAFT_EVENT_RETENTION` | 720h | Event retention (0 keeps) |
| `-file-retention` | `WAFT_FILE_RETENTION` | 168h | File retention (0 keeps) |
| `-stale-upload-ttl` | `WAFT_STALE_UPLOAD_TTL` | 24h | Abandoned upload cleanup |
| `-max-file-size` | `WAFT_MAX_FILE_SIZE` | 2 GiB | Per file |
| `-user-quota` | `WAFT_USER_QUOTA` | 10 GiB | Per account (0 = unlimited) |
| `-max-devices` | `WAFT_MAX_DEVICES` | 50 | Devices per account |
| `-max-chunk` | `WAFT_MAX_CHUNK` | 16 MiB | Bytes per upload PATCH |
| `-log-level` / `-log-format` | `WAFT_LOG_LEVEL` / `WAFT_LOG_FORMAT` | info / json | Logging |

### Upgrading from v1

Migrations are versioned and run under an advisory lock, so several nodes can start together. A v1 database keeps its old single-user tables as `legacy_v1_devices`, `legacy_v1_events` and `legacy_v1_file_transfers`. Nothing is deleted. v1 clients must be updated: they need an API token and the per-account salt.

---

## HTTP API

The full client contract, including the encryption formats, stream semantics, cursor rules and test vectors, is in [PROTOCOL.md](PROTOCOL.md). The table below is a summary.

All endpoints except `/healthz`, `/readyz` and `/v2/auth/*` require a session cookie or `Authorization: Bearer gpt_...`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v2/auth/register` | Create an account (sets session cookie) |
| `POST` | `/v2/auth/login` / `logout` / `logout-all` | Sessions |
| `GET` | `/v2/me` | Account, salt, key check, limits |
| `PATCH` | `/v2/me` | Display name |
| `PUT` | `/v2/me/e2ee-check` | Store the passphrase key check |
| `POST` | `/v2/me/password` | Change password (signs out other browsers) |
| `POST` | `/v2/me/delete` | Delete account and all data |
| `GET` `DELETE` | `/v2/sessions`, `/v2/sessions/{id}` | Signed-in browsers |
| `GET` `POST` `DELETE` | `/v2/tokens`, `/v2/tokens/{id}` | API tokens |
| `GET` | `/v2/audit` | Account activity |
| `GET` | `/v2/stream?device_id=&nickname=&platform=&last_seq=` | WebSocket stream |
| `GET` | `/v2/pushes?after=&device_id=&limit=` | Events after a cursor (`events`, `cursor`, `has_more`) |
| `POST` | `/v2/pushes` | Send an event |
| `GET` `PATCH` `DELETE` | `/v2/devices`, `/v2/devices/{id}` | Devices |
| `GET` `POST` | `/v2/files` | List files / start an upload |
| `HEAD` `PATCH` `GET` `DELETE` | `/v2/files/{id}` | Offset, append chunk, download (Range), delete |
| `GET` | `/healthz`, `/readyz` | Liveness; readiness checks PostgreSQL and Redis |

WebSocket close codes: `4000` replaced by a newer connection of the same device, `4001` credentials revoked or account deleted, `4002` client too slow, `4003` device limit reached.

---

## Verified behaviour

These were run against real PostgreSQL 16 and Redis 7 with two nodes:

- 1200 events written concurrently through both nodes while a device was offline, then replayed: all received, in order, no duplicates.
- 600 events written live through both nodes by 4 concurrent writers: all received in order, exactly once.
- Redis shut down during traffic: pushes kept working (20 pushes in 0.37 s), and a device on the other node received every missed event in order once Redis returned.
- Node SIGKILL: its devices shown offline within the 15 second lease.
- Token revoked on one node: the live socket on the other node closed with 4001; the token is rejected afterwards.
- Cross-account file read, HEAD and delete: 404. Forged control frames, plaintext under strict mode and invalid device IDs: rejected.
- Two nodes writing the same upload: the second gets 423 and the file is not corrupted.
- Browser, `waft` and `waftd` exchanged encrypted pushes and files in every direction, byte-identical after decryption. An XSS payload in a title rendered as text, and a `javascript:` link was not made clickable.

## Scaling notes

- Nodes are stateless. Add more behind Nginx; each Redis message reaches only the nodes serving that account.
- File storage must be shared between nodes (a volume, NFS or similar). Object storage (S3-compatible) is the natural next step for large deployments.
- For very large event volumes, partition `events` by `created_at` month; retention then becomes a partition drop.
- Browser uploads hold the file in memory and are capped at 1 GB. Use `waft` for anything larger.

## Contributing and security

Issues and pull requests are welcome. By submitting a contribution you agree that it is licensed under the Apache License 2.0, as stated in section 5 of the licence. Please report security problems privately as described in [SECURITY.md](SECURITY.md).

## Licence

Copyright 2026 Bufferstack.IO Analytics Technology LLP.

Licensed under the [Apache License, Version 2.0](LICENSE). You may not use this project except in compliance with the licence. Unless required by applicable law or agreed to in writing, software distributed under the licence is distributed on an "AS IS" basis, without warranties or conditions of any kind, either express or implied. See the licence for the specific language governing permissions and limitations.

Waft depends on open-source Go modules under the MIT and BSD licences. Their notices are reproduced in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) and are shipped inside the Docker image at `/usr/share/doc/waft/`.

## Disclaimer

This software is in beta. Review the configuration, use TLS, and keep backups of PostgreSQL before relying on it for important data.
