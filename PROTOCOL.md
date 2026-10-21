# Waft Protocol, version 2

This document specifies how a client talks to a Waft v2 server: authentication, key setup, end-to-end encryption, the event stream, the REST API and file transfer. It is the contract for every client: the open web app, `waft`, `waftd`, the desktop browser extension and the Android app.

The reference implementations are `pkg/e2ee` (Go) and `static/app.js` (WebCrypto). Where this document and the reference code disagree, that is a bug in one of them; please report it.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119.

Contents

1. Conventions
2. Authentication
3. Account bootstrap and key setup
4. End-to-end encryption
5. Encrypted file format (GPF1)
6. Events
7. The event stream (WebSocket)
8. REST endpoints for events and devices
9. File transfer
10. Errors and limits
11. Platform identifiers
12. Compatibility rules
13. Known gaps (planned server work)
14. Test vectors

---

## 1. Conventions

- All request and response bodies are JSON, UTF-8, unless stated otherwise.
- Timestamps are integers: milliseconds since the Unix epoch, UTC.
- `base64` means standard base64 with padding (RFC 4648 section 4), not the URL-safe alphabet.
- Hex strings are lowercase.
- Every endpoint lives under `/v2/`. The server base URL is configured by the user, for example `https://push.example.com`.
- Clients MUST use HTTPS and WSS in production. Plain HTTP exists only for local testing.

**Device ID.** Every client installation has a device ID that matches `^[A-Za-z0-9._:-]{1,64}$` and is not `*`. It MUST be generated once per installation, stored, and reused for the life of the installation. Recommended form: a platform prefix plus random hex, for example `android-3f9a61c2` or `ext-chrome-b71e09d4`. The ID is visible to the server, so it MUST NOT contain personal data such as a phone number or a user name.

**Nickname.** A human label for the device, up to 64 characters, chosen by the user (for example "Pixel 8" or "Work laptop, Chrome"). The server strips control characters.

---

## 2. Authentication

### 2.1 Credentials

There are two kinds of credential:

| Kind | Used by | How it is sent |
| --- | --- | --- |
| Session cookie | The open web app only | `__Host-waft_session` cookie (`waft_session` on plain-HTTP test servers); `HttpOnly`, `Secure`, `SameSite=Strict`, 30 days |
| API token | Every other client | `Authorization: Bearer gpt_<43 chars>` |

Clients other than the web app MUST use API tokens. A token is a secret equal in power to the account password for everything except account management. Clients MUST store it in the platform's secure storage (Android Keystore-backed storage, the extension's local storage area, never in synced storage).

The server stores only a SHA-256 digest of the token. A lost token cannot be recovered; the user creates a new one.

### 2.2 Obtaining a token

A token is created by `POST /v2/tokens`, which only works with a session cookie. A token can never mint another token.

**Today, a client obtains a token in one of two ways:**

1. **The user pastes it.** The user creates a token in the web app (Settings, API tokens) and pastes it into the client. This works for every client and is the recommended path for the browser extension today.
2. **The client signs in on the user's behalf.** This works for native clients with their own cookie jar, such as the Android app:

```http
POST /v2/auth/login
X-Waft-CSRF: 1
Content-Type: application/json

{"email":"user@example.com","password":"..."}
```

`200 OK` sets the session cookie and returns the account (section 3.1). Then, with that cookie:

```http
POST /v2/tokens
X-Waft-CSRF: 1
Content-Type: application/json

{"name":"Pixel 8 (Android app)","expires_in_days":0}
```

`201 Created` returns `{"token":"gpt_...","info":{...}}`. The client stores the token, then calls `POST /v2/auth/logout` (with the cookie and the CSRF header) so no session is left behind. Native HTTP clients do not send an `Origin` header, which the server accepts.

`expires_in_days` is 0 (never) to 3650. A device token SHOULD be named after the device so the user can recognise it in Settings and revoke it.

The browser extension cannot use path 2 without operator configuration, because its requests carry an `Origin` of `chrome-extension://...` (see section 13).

### 2.3 Rules for cookie-authenticated requests

These apply only to the web app. Every state-changing request (anything other than GET, HEAD or OPTIONS), and every call to `/v2/auth/login`, `/v2/auth/register` and `/v2/auth/logout`, MUST carry the header `X-Waft-CSRF: 1`. If an `Origin` header is present, it must be the server's own origin or one listed in the server's `WAFT_ALLOWED_ORIGINS`. Otherwise the server answers `403 {"error":"cross-site request blocked"}`.

### 2.4 Revocation

When a token is revoked, or the account is deleted, the server closes every live stream opened with that credential with close code `4001` (section 7.6). Any later request with it gets `401`. A client that receives either MUST stop retrying, discard the token, and ask the user to sign in again.

---

## 3. Account bootstrap and key setup

### 3.1 `GET /v2/me`

Called once at start-up and whenever the client needs fresh limits.

```json
{
  "id": "058f4f39-0906-4398-becb-8672e7150492",
  "email": "user@example.com",
  "display_name": "Harshad",
  "role": "user",
  "e2ee_salt": "HvDwIhldeERdtvQBev5+2w==",
  "e2ee_check": "sLGys7S1tre4...",
  "created_at": 1792559037680,
  "storage_used": 300092,
  "storage_quota": 10737418240,
  "max_file_size": 2147483648,
  "max_devices": 50,
  "kdf_iterations": 600000,
  "require_e2ee": true
}
```

| Field | Meaning |
| --- | --- |
| `id` | Account UUID. Clients SHOULD include it in local storage keys (cursor, cached key) so that switching accounts never mixes state. |
| `e2ee_salt` | base64 of 16 random bytes, fixed for the life of the account. |
| `e2ee_check` | Key-check value (section 3.3); empty string when no device has set one yet. |
| `kdf_iterations` | PBKDF2 iteration count. Clients MUST use this value, not a hard-coded one. |
| `storage_quota` | Bytes; 0 means unlimited. |
| `require_e2ee` | When true, the server rejects plaintext content (section 6.3). |

### 3.2 Key derivation

```text
key = PBKDF2-HMAC-SHA256(
        password   = UTF-8 bytes of the passphrase, exactly as entered,
        salt       = base64-decode(e2ee_salt),
        iterations = kdf_iterations,
        length     = 32 bytes)
```

The key is used with AES-256-GCM. Clients MUST NOT trim, case-fold or Unicode-normalise the passphrase; the bytes must match on every device.

Derivation is deliberately slow (around half a second on a phone). Clients MUST derive once per unlock and keep the key in memory. The passphrase itself SHOULD NOT be persisted. Where the platform offers hardware-backed storage, a client MAY store the derived key there so the user does not re-enter the passphrase on every start.

The passphrase never leaves the device and the server cannot recover it.

### 3.3 Key check

The key check lets a device detect a mistyped passphrase before it sends anything unreadable.

```text
e2ee_check = seal(key, "gopush-key-check-v2")        (section 4.1)
```

The marker keeps the project's earlier working name. It is part of the v2 format and does not change with the product name.

After deriving the key:

- If `e2ee_check` is empty, the client MUST create one and store it:
  `PUT /v2/me/e2ee-check` with `{"check":"<value>"}`. `204` means it was stored. `409` means another device set one first: fetch `/v2/me` again and verify against that one instead.
- If `e2ee_check` is not empty, the client MUST open it with the key. If authentication fails or the plaintext is not exactly `gopush-key-check-v2`, the passphrase is wrong: the client MUST refuse to continue and ask again.

Replacing the passphrase: `PUT /v2/me/e2ee-check` with `{"check":"<value>","force":true}`. Events and files encrypted with the old passphrase become unreadable to devices using the new one. Clients MUST warn the user before doing this. Only the web app offers it today.

---

## 4. End-to-end encryption

### 4.1 Sealed values

Event contents and the key check use one format:

```text
sealed = base64( nonce (12 bytes) || AES-256-GCM ciphertext || tag (16 bytes) )
```

- `nonce` MUST be 12 bytes from a cryptographically secure random generator, fresh for every seal. A nonce MUST NEVER be reused with the same key.
- No additional authenticated data is used.
- Minimum valid length after decoding: 28 bytes.

In WebCrypto terms: `encrypt({name:"AES-GCM", iv: nonce}, key, plaintext)` returns ciphertext and tag together, and the sealed value is `base64(nonce || result)`.

### 4.2 Secret payload

The plaintext of an event's `ciphertext` is a UTF-8 JSON object. All fields are optional strings unless stated:

| Field | Used by types | Meaning |
| --- | --- | --- |
| `title` | push, mirror, file | Heading |
| `body` | push, clip, mirror | Text. For `clip`, the clipboard contents. |
| `url` | push | A link. Receivers MUST only open `http:` and `https:` URLs. |
| `app_name` | mirror | Name of the app that raised the notification |
| `file_name` | file | Original file name. Receivers MUST sanitise it before writing to disk. |
| `file_sha256` | file | Hex SHA-256 of the plaintext file |
| `file_size` | file | Integer, plaintext size in bytes |
| `mime_type` | file | Original media type |

Receivers MUST ignore unknown fields. Senders SHOULD omit empty fields.

All text from a payload is untrusted. Receivers MUST render it as plain text, never as HTML or markup.

### 4.3 What the server can see

Encrypted: everything in section 4.2.

Not encrypted (needed for routing): account email, device IDs, nicknames and platforms, event `type`, `source_device`, `target_device`, `notification_id`, file ciphertext sizes and digests, timestamps, and IP addresses. Clients SHOULD keep these free of personal data; see section 6.4 for `notification_id`.

---

## 5. Encrypted file format (GPF1)

File contents are encrypted on the sending device before upload. The server stores and serves only GPF1 bytes.

```text
file      = header || segment_0 || segment_1 || ... || segment_(n-1)
header    = "GPF1" (4 ASCII bytes) || prefix (8 random bytes)
segment_i = AES-256-GCM( plaintext[i*65536 : (i+1)*65536],
                         nonce = prefix || uint32_big_endian(i),
                         aad   = "GPF1" || final_flag )   ->  ciphertext || tag (16 bytes)
final_flag = 0x01 for the last segment, 0x00 for every other segment
n          = max(1, ceil(plaintext_size / 65536))
```

- `prefix` MUST be fresh random bytes for every file.
- Every segment except the last holds exactly 65 536 plaintext bytes (65 552 ciphertext bytes).
- An empty file is one final segment with no plaintext (16 bytes).
- Encrypted size: `12 + plaintext_size + 16 * n`.

**Decryption.** Read the 12-byte header and check the magic. Then repeatedly take up to 65 552 bytes. A segment is final exactly when it ends at the end of the data. Decrypt it with that final flag. Any authentication failure, a remainder shorter than 16 bytes, or a non-final segment shorter than 65 552 bytes MUST fail the whole file. This rejects reordered, dropped, truncated, extended and modified files.

Receivers MUST NOT hand out partially decrypted output as if it were complete. Decrypt to a temporary file and move it into place only after the whole file and its digest (section 9.4) verify.

---

## 6. Events

### 6.1 Envelope

Every event, in the stream and in REST, is a JSON envelope:

| Field | Type | Set by | Meaning |
| --- | --- | --- | --- |
| `seq_id` | int | server | Per-account sequence number, starting at 1, gap-free, strictly increasing. 0 on control frames. |
| `type` | string | client | See 6.2 |
| `source_device` | string | server | The sending device. The server overwrites whatever the client sends on the stream. |
| `target_device` | string | client | A device ID, or `*` for all of the account's devices |
| `ciphertext` | string | client | Sealed secret payload (section 4) |
| `notification_id` | string | client | Opaque ID linking `mirror` and `dismiss` (6.4) |
| `title`, `body`, `url`, `app_name` | string | client | Plaintext fields; rejected when `require_e2ee` is on (6.3) |
| `file_id`, `file_name`, `file_size`, `file_sha256` | | server | Only on `file` events (section 9.3) |
| `url` | string | server | On `file` events: the download path |
| `cursor` | int | server | Only on `sync_complete` |
| `created_at` | int | server | Time the server stored the event |

### 6.2 Types

| Type | Origin | Meaning |
| --- | --- | --- |
| `push` | client | A note or link for the user |
| `clip` | client | New clipboard contents. Receivers that sync the clipboard write `body` into the local clipboard. |
| `mirror` | client | A notification mirrored from a phone |
| `dismiss` | client | The mirrored notification with this `notification_id` was dismissed; remove the local copy |
| `file` | server only | A verified upload is ready to download |
| `presence` | server only | The account's device list changed (section 7.4) |
| `sync_complete` | server only | Initial replay finished (section 7.3) |
| `heartbeat` | both | Keep-alive (section 7.5) |
| `error` | server only | A frame from this client was rejected (section 7.4) |

Clients MUST NOT send `file`, `presence`, `sync_complete` or `error`. The server rejects them.

### 6.3 Strict encryption mode

When `require_e2ee` is true (the default), the server rejects any client event that has a non-empty `title`, `body` or `url`, and any event other than `dismiss` without `ciphertext`. It also clears `app_name`. Clients MUST put all content inside `ciphertext` regardless of the mode.

### 6.4 Mirror and dismiss

A `mirror` event SHOULD carry `notification_id`, and a later `dismiss` with the same `notification_id` and no `ciphertext` tells other devices to remove it.

`notification_id` is visible to the server. Android notification keys contain package names, so the Android app MUST NOT send them raw. Use either a random ID per notification kept in a local map, or `hex(HMAC-SHA256(device_secret, android_key))[:32]` with a secret that never leaves the device. Maximum length 256 bytes.

### 6.5 Ordering and visibility

- Sequence numbers are per account. Two accounts have independent sequences.
- A device receives an event when `target_device` is `*`, equals its device ID, or when it is the `source_device`. A sender therefore receives its own events back (the echo). Clients SHOULD use the echo as delivery confirmation and MUST NOT show a notification for their own events.
- Events addressed to other devices are invisible to this device, so the `seq_id` values a device sees can have gaps. That is normal.

---

## 7. The event stream (WebSocket)

### 7.1 Connecting

```text
GET /v2/stream?device_id=<id>&nickname=<label>&platform=<platform>&last_seq=<cursor>
Authorization: Bearer gpt_...
Upgrade: websocket
```

| Parameter | Required | Meaning |
| --- | --- | --- |
| `device_id` | yes | Section 1 |
| `nickname` | no | Up to 64 characters; defaults to the device ID |
| `platform` | no | Section 11; up to 32 characters |
| `last_seq` | no | The client's stored cursor; 0 or absent for a new device |

The first connection with a new device ID registers the device. An account has at most `max_devices` devices; above that, the server closes with `4003`.

Only one socket per device is live. A newer connection with the same device ID (on any server node) closes the older one with `4000`.

### 7.2 Cursor

The cursor is the client's position in the account sequence. Clients MUST:

1. Store the cursor durably, per account ID and device ID.
2. After handling an event with `seq_id > 0`, set `cursor = max(cursor, seq_id)`. Persist the cursor after the event is handled, not before, so a crash re-delivers the event instead of losing it.
3. On `sync_complete`, set `cursor = frame.cursor` exactly, even if it is lower than the stored value. The server is authoritative; a lower value means the server was restored from a backup.
4. Send the stored cursor as `last_seq` on every connect.

### 7.3 Connection sequence

After the upgrade, the server:

1. Sends every event visible to this device with `seq_id > last_seq`, in order. There is no upper limit; large backlogs are sent in pages without gaps.
2. Sends `{"type":"sync_complete","cursor":N,"body":"...","created_at":...}`.
3. Sends live events in order as they happen.

Live events created during step 1 are not lost; they are sent after the backlog or before `sync_complete`, still in order. A client SHOULD show itself as "syncing" until `sync_complete` and "online" after it.

**Guarantee.** Within one connection, each visible event is delivered exactly once and in increasing `seq_id` order. Across reconnects, delivery is at least once: an event handled before a crash, but whose cursor was not yet saved, will come again. Handlers SHOULD therefore be idempotent per `seq_id`, for example by not re-showing a notification for a `seq_id` already shown.

### 7.4 Frames from the server

Data events use the envelope in 6.1. Control frames have `seq_id` 0:

```json
{"seq_id":0,"type":"heartbeat","body":"ping","created_at":0}
{"seq_id":0,"type":"presence","source_device":"cluster","target_device":"*","body":"[...]","created_at":1792559037680}
{"seq_id":0,"type":"error","body":"rate limited","created_at":1792559037680}
```

`presence.body` is a JSON-encoded string holding an array of devices:

```json
[{"device_id":"android-3f9a61c2","nickname":"Pixel 8","platform":"android",
  "online":true,"last_seen":1792559037680,"connected_at":1792558000000,
  "remote_ip":"203.0.113.7","created_at":1792000000000}]
```

`error` frames report that one client frame was rejected and not stored. The connection stays open.

### 7.5 Frames from the client and keep-alive

A client sends events as text frames containing an envelope with at least `type`, `target_device` and `ciphertext` (or `notification_id` for `dismiss`). The server assigns `seq_id`, `created_at` and `source_device`, and ignores client values for them.

Limits: 128 KiB per frame, 96 KiB of `ciphertext`, and 20 frames per second with bursts of 40. Over the limit, the frame is dropped with an `error` frame. A frame sent on the stream is confirmed only by its echo. For a user action that must be confirmed, such as pressing Send, clients SHOULD use `POST /v2/pushes` (section 8.2), which returns the stored event.

Keep-alive:

- The server sends a WebSocket ping and a `heartbeat` text frame every 17.5 seconds.
- The server closes a connection that sends nothing (no frame, no pong) for 25 seconds. Standard WebSocket libraries and browsers answer pings automatically.
- A client MAY send `{"type":"heartbeat"}`; the server answers `{"type":"heartbeat","body":"pong"}`.
- Clients MUST run a watchdog. If nothing at all arrives for 30 seconds, the link is dead even if the socket looks open (suspend, network change): close it and reconnect.

### 7.6 Close codes and reconnection

| Code | Meaning | Client action |
| --- | --- | --- |
| 1000, 1001, 1006 | Normal close, server shutting down, or network loss | Reconnect with backoff |
| 1011 | Server could not register the device | Reconnect with backoff |
| 4000 | Replaced by a newer connection of the same device | Do not reconnect automatically; another instance is active |
| 4001 | Credential revoked or account deleted | Do not reconnect; discard the token and ask the user to sign in |
| 4002 | Client read too slowly and its buffer overflowed | Reconnect with backoff; the cursor resync recovers everything |
| 4003 | Device limit reached | Do not reconnect; tell the user to remove a device |

An HTTP `401` on the upgrade request means the same as `4001`.

Backoff: exponential from 1 second, capped between 15 and 32 seconds, with jitter of at least half the interval. Reset the backoff after a connection stays up for 30 seconds. Clients MUST NOT reconnect in a tight loop.

---

## 8. REST endpoints for events and devices

All require `Authorization: Bearer gpt_...` (or the web app's cookie).

### 8.1 `GET /v2/pushes`

Polling access to the same sequence, for clients that cannot hold a socket.

Query: `after` (cursor, default 0), `device_id` (only events visible to that device; omit for all), `limit` (1 to 500, default 100).

```json
{"events":[ ...envelopes... ],"cursor":1804,"has_more":false}
```

When `has_more` is true, call again with `after=cursor`. When it is false, `cursor` is the account head, and it is safe to store it as the device cursor.

### 8.2 `POST /v2/pushes`

Body: an envelope with `type`, `target_device`, `ciphertext`, and `source_device` set to the sender's own device ID (so its stream recognises the echo). `type` defaults to `push`.

`201 Created` returns the stored envelope including its `seq_id`. Validation failures return `400` with an `error` message.

### 8.3 Devices

| Request | Result |
| --- | --- |
| `GET /v2/devices` | Array of devices (format as in 7.4) |
| `PATCH /v2/devices/{id}` with `{"nickname":"..."}` | `204`; presence is broadcast |
| `DELETE /v2/devices/{id}` | `204`; a live socket of that device is closed with `4000` |

Deleting a device does not block it: if it still holds a valid token, it re-registers on its next connect. To block a device, revoke its token.

---

## 9. File transfer

Files move as GPF1 ciphertext through a resumable, offset-based upload. The receiving device downloads, verifies and decrypts.

### 9.1 Upload

**Step 1. Prepare.** Encrypt the file to GPF1 (to a temporary file, or in memory for small files). Compute the SHA-256 of the plaintext and of the ciphertext. Seal the metadata payload:

```json
{"title":"File: report.pdf","file_name":"report.pdf","file_sha256":"<plaintext sha256>",
 "file_size":123456,"mime_type":"application/pdf"}
```

**Step 2. Create the upload.**

```http
POST /v2/files
Content-Type: application/json

{"file_name":"encrypted.gpf","source_device":"<own id>","target_device":"<id or *>",
 "total_size":<ciphertext size>,"expected_sha256":"<ciphertext sha256>",
 "ciphertext_meta":"<sealed metadata>"}
```

`file_name` here is visible to the server and is only used in the download header. Clients SHOULD send `encrypted.gpf` and keep the real name inside `ciphertext_meta`.

`201 Created` returns the upload session with `file_id` and the header `Upload-Offset: 0`.

| Status | Meaning |
| --- | --- |
| `400` | Invalid fields, or `ciphertext_meta` missing in strict mode |
| `413` | `total_size` above `max_file_size` |
| `507` | The account quota would be exceeded |

**Step 3. Send bytes.**

```http
PATCH /v2/files/{file_id}
Upload-Offset: <offset>
Content-Type: application/offset+octet-stream

<raw ciphertext bytes starting at offset>
```

Clients SHOULD send chunks of 4 MiB. The server accepts at most 16 MiB per request (configurable) and may store fewer bytes than were sent. Clients MUST always continue from the `Upload-Offset` response header, never from their own arithmetic.

| Status | Meaning | Client action |
| --- | --- | --- |
| `200` | Bytes stored. `Upload-Offset` is the new offset; the body is the session. When the offset equals `total_size`, the server has verified the ciphertext digest and the `file` event has been sent. | Continue, or finish |
| `204` | Already complete | Finish |
| `408` | The request body stopped early; what arrived is stored | Continue from `Upload-Offset` |
| `409` | `Upload-Offset` did not match; body has `server_offset` | Continue from the header value |
| `423` | Another request is writing this upload | Wait `Retry-After` seconds (2), then continue |
| `410` | The upload failed verification earlier | Start a new upload |
| `422` | Digest mismatch at completion; the stored bytes were discarded and later requests get `410` | Start a new upload |
| `404` | No such upload (or it expired) | Start a new upload |

After a network error, ask for the current offset:

```http
HEAD /v2/files/{file_id}
```

`204` with `Upload-Offset`, `Upload-Length` and `Upload-Status` (`UPLOADING`, `COMPLETED`, `CORRUPTED`). Uploads idle for 24 hours are deleted.

### 9.2 `GET /v2/files`

Lists the account's recent uploads, newest first (`limit` up to 200). `DELETE /v2/files/{id}` removes one and frees its quota.

### 9.3 The `file` event

When an upload completes, the server emits:

| Field | Value |
| --- | --- |
| `type` | `file` |
| `source_device`, `target_device` | From the upload |
| `ciphertext` | The `ciphertext_meta` from the upload, unchanged |
| `url` | `/v2/files/{file_id}` |
| `file_id` | The upload ID |
| `file_name` | The server-visible name (normally `encrypted.gpf`); clients MUST use `file_name` from the decrypted metadata instead |
| `file_size` | Ciphertext size |
| `file_sha256` | SHA-256 of the ciphertext, verified by the server |

### 9.4 Download and verification

```http
GET /v2/files/{file_id}
Authorization: Bearer gpt_...
```

The response is `application/octet-stream`, supports `Range`, and carries `X-Content-SHA256` (the ciphertext digest). Files expire after the server's retention period (7 days by default); expired files return `404`, and clients SHOULD say "this file has expired" rather than show a generic error.

A receiver MUST:

1. Download to a temporary location.
2. Check that the SHA-256 of the downloaded bytes equals the event's `file_sha256`.
3. Decrypt GPF1 (section 5).
4. Check that the SHA-256 of the plaintext equals `file_sha256` from the decrypted metadata.
5. Sanitise the metadata `file_name` (strip directories and characters invalid on the platform; never accept `.` or `..`), pick a name that does not overwrite an existing file, and only then move the file into place.

If any check fails, delete the temporary file and report the failure. Never keep a partial or unverified file.

---

## 10. Errors and limits

Errors are JSON: `{"error":"human readable message"}`. Clients SHOULD show the message; it is written for users.

| Status | Meaning |
| --- | --- |
| `400` | Invalid request |
| `401` | Missing, expired or revoked credential |
| `403` | Cross-site rule (2.3), or an action this credential may not perform |
| `404` | Not found, or belongs to another account (the two are indistinguishable by design) |
| `409` | Conflict (existing account, key check already set, upload offset) |
| `413` | Body or file too large |
| `429` | Rate limited; wait before retrying |
| `503` | Authentication backend temporarily unavailable; retry with backoff |

Rate limits enforced by the server:

| What | Limit |
| --- | --- |
| Login | 30 per IP and 20 per email per 15 minutes |
| Registration | 10 per IP per hour |
| Password confirmation | 10 per account per 15 minutes |
| Stream frames | 20 per second, bursts of 40, per connection |

Size limits: 96 KiB of `ciphertext` per event (clipboard text SHOULD be capped at 32 KiB before encryption); 8 KiB of `ciphertext_meta`; `max_file_size` per file (2 GiB by default); `storage_quota` per account (10 GiB by default); 50 devices per account; 50 API tokens per account.

---

## 11. Platform identifiers

`platform` is free text on the server, but clients MUST use one of these values so that the device list and future server features can tell clients apart:

| Value | Client |
| --- | --- |
| `web` | Open web app |
| `extension-chrome` | Desktop browser extension in Chrome |
| `extension-edge` | Desktop browser extension in Edge |
| `extension-firefox` | Desktop browser extension in Firefox |
| `android` | Android app |
| `linux-daemon` | `waftd` |
| `windows-tray`, `macos-tray` | Reserved for future desktop tray apps |
| `cli` | Command-line tools that open a stream |

New values are added to this table before a client ships with them.

---

## 12. Compatibility rules

To let the server evolve without breaking shipped clients:

- Clients MUST ignore unknown JSON fields everywhere.
- Clients MUST ignore unknown event `type` values, while still advancing the cursor for them.
- Clients MUST ignore unknown close codes in the 4000 to 4999 range by treating them as "reconnect with backoff", except the codes listed in 7.6.
- The server adds fields and types only within `/v2/`. A breaking change gets a new path prefix (`/v3/`), and `/v2/` keeps working for at least one release cycle.
- The encryption formats in sections 4 and 5 are fixed for v2. A new format would use a new magic value (`GPF2`) and a new key-check marker, and receivers would select the format by those markers.

---

## 13. Known gaps (planned server work)

These are not implemented yet. The desktop extension and the Android app depend on them, and they are listed here so client work can plan around them.

**13.1 Stream tickets for the browser extension.** The browser WebSocket API cannot set an `Authorization` header, so the extension cannot open `/v2/stream` with its token. Planned: `POST /v2/stream/ticket` (bearer token) returns a single-use ticket valid for 30 seconds, and the extension connects with `/v2/stream?ticket=...`. The ticket keeps the long-lived token out of URLs and logs. Until this lands, the extension cannot hold a live stream; it can poll `GET /v2/pushes` (section 8.1) as a stop-gap.

**13.2 Direct token sign-in.** `POST /v2/auth/token` with email, password and a device name would return an API token directly, without a temporary session or Origin rules. It would replace path 2 in section 2.2 and let the extension sign in without the user pasting a token.

**13.3 Wake-up pushes for Android.** Android stops background sockets in Doze mode. Planned: the device registers a Firebase Cloud Messaging token; when an event targets a device that is offline, the server sends an FCM message with no content (only "new events"). The app wakes, connects and receives the events through the normal cursor sync. Google sees no content, and a lost wake-up is harmless because the next connection catches up anyway.

---

## 14. Test vectors

Machine-readable copy: `pkg/e2ee/testdata/vectors.json`. The plaintexts are fixed test bytes from the project's earlier working name, GoPush; they must not be edited, because every ciphertext below depends on them. They were generated by an implementation independent of `pkg/e2ee`, and `pkg/e2ee/vectors_test.go` checks the reference code against them byte for byte. A client implementation SHOULD pass all of them before it ships.

**Key derivation**

```text
passphrase  correct horse battery staple
salt (b64)  AAECAwQFBgcICQoLDA0ODw==          (bytes 00 01 02 ... 0f)
iterations  600000
key (hex)   ef177144eec9420cbc1093d2a8b344a92bc506d0d4ec9c028dd19f8324d8c1e6
```

**Event payload** (fixed nonce, for testing only; real seals use random nonces)

```text
nonce (hex)  a0a1a2a3a4a5a6a7a8a9aaab
plaintext    {"title":"Hello","body":"From GoPush","url":"https://example.com/"}
sealed       oKGio6Slpqeoqaqr0EzH6Q9ZoMoNCFrXaPlikdR8jVqdZauPeZRXhlMWZpACtONGkW0GijyXLpvwHlFcluSuJoK5jLBI9yXOCLJrd/m4Lm8TL5/76xW7+VZpjPkNEUo=
```

**Key check**

```text
nonce (hex)  b0b1b2b3b4b5b6b7b8b9babb
plaintext    gopush-key-check-v2
sealed       sLGys7S1tre4ubq7jEu528wPULRLRAcg/Kts+GcZEyKU1et6jI8sbANUI03xFpg=
```

**GPF1, small file** (prefix `1011121314151617`, plaintext `GoPush`, 34 bytes)

```text
4750463110111213141516178b180b4756e605a94d66ddf8e3f1e62ba3278df86864
```

**GPF1, empty file** (same prefix, 28 bytes)

```text
47504631101112131415161753aa5701b05d137f2b59df2871d047ba
```

**GPF1, two segments** (same prefix; plaintext is 70 000 bytes where byte `i` is `i mod 251`)

```text
plaintext sha256   9dc177c2fde29dea8e7c29f7ddf147b7c449c99d049c62f3aac0a5933ecf76a3
ciphertext size    70044
ciphertext sha256  115dc4f5c357e27f5bd91dc6ca299d0cc6d8357dc0196db709451c26c44457f8
```

A conforming implementation, given the key above, must reproduce each sealed value and ciphertext exactly with the fixed nonce or prefix, and must decrypt each back to its plaintext.
