# TLS Configuration Runbook

This document covers TLS setup for `stoa-reader` and `stoa-transit`.

---

## Reader TLS (`crates/reader/`)

### Configuration

```toml
[tls]
cert_path = "/etc/ssl/certs/nntp.pem"   # PEM certificate chain (leaf first)
key_path  = "/etc/ssl/private/nntp.key"  # PEM private key
tls_addr  = "0.0.0.0:563"               # optional NNTPS listener (immediate TLS)
```

**Behavior:**

- When `cert_path` and `key_path` are set, STARTTLS is advertised in the `CAPABILITIES` response on the plain-text listener (port 119 by default).
- `tls_addr` starts a second listener that wraps every connection in TLS before any NNTP bytes are exchanged (NNTPS, port 563 by convention). This is optional; omit it if you only want STARTTLS.
- Both `cert_path` and `key_path` must be set together or both omitted. Setting only one is a config error.
- `tls_addr` requires `cert_path` and `key_path` to also be set.

**Config errors:**

| Error message | Cause |
|---|---|
| `tls.cert_path and tls.key_path must both be set or both be absent` | Set both fields or neither |
| `tls.tls_addr requires tls.cert_path and tls.key_path to be set` | Cannot open NNTPS listener without a certificate |

**Auth + TLS warning:**

At startup, if `auth.required = true` but `cert_path` and `key_path` are not set, the server logs a warning. With no TLS available, clients attempting `AUTHINFO USER/PASS` on a plain connection receive `483 Encryption required for authentication`. Credentials are never sent in the clear when `auth.required = true`.

**Client certificate authentication (NNTPS only):**

On NNTPS connections, the server requests but does not require a client certificate. After the handshake, the leaf certificate's SHA-256 fingerprint is matched against entries in `auth.client_certs`. If matched, the session is authenticated as the mapped username without a password exchange.

```toml
[[auth.client_certs]]
sha256_fingerprint = "sha256:<64 lowercase hex chars>"
username = "alice"
```

Certificates signed by a trusted CA issuer can authenticate using the leaf certificate's Common Name:

```toml
[[auth.trusted_issuers]]
cert_path = "/etc/ssl/certs/my-ca.pem"
```

Client certificate auth is only available on NNTPS connections (not STARTTLS-upgraded plain connections).

---

## Transit TLS (`crates/transit/`)

### Inbound peering listener

The `[tls]` section is optional. When absent, the peering listener accepts plain TCP connections (suitable for LAN or loopback peering, or when a TLS terminator sits in front of the daemon).

```toml
[tls]
cert_path = "/etc/ssl/certs/transit.pem"
key_path  = "/etc/ssl/private/transit.key"
```

When present, every accepted connection is wrapped in TLS before being handed to the session handler. Plain TCP peers that do not speak TLS will fail the handshake and be dropped.

### Outbound peering (per-peer TLS)

Use the structured `[[peers.peer]]` table for peers that require TLS:

```toml
[[peers.peer]]
addr        = "transit2.example.com:119"
tls         = true
cert_sha256 = "aa:bb:cc:dd:..."   # SHA-256 fingerprint of peer's DER cert
```

- `tls = true` requires `cert_sha256`. The config validator rejects `tls = true` without it.
- `cert_sha256` format: colon-separated lowercase hex bytes, 32 bytes total, 95 characters (e.g. `"aa:bb:cc:dd:ee:ff:..."`).
- Certificate validation does **not** use CA roots. Only the pinned fingerprint is checked. Self-signed certificates are fully supported.

**Config error:**

| Error message | Cause |
|---|---|
| `peers.peer entry 'X': tls = true requires cert_sha256 to be set` | Add the fingerprint for the peer |

Plain peers (no TLS) can be listed in the legacy flat list:

```toml
[peers]
addresses = [
    "192.0.2.10:119",
    "192.0.2.20:119",
]
```

Entries in `addresses` are equivalent to `[[peers.peer]]` with `tls = false` and no cert pin.

---

## Certificate Generation

### Self-signed certificate (development)

Generate a self-signed RSA certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout nntp.key -out nntp.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

This produces:
- `nntp.key` — PEM private key (use as `key_path`)
- `nntp.pem` — PEM certificate (use as `cert_path`)

Compute the SHA-256 fingerprint for use in `cert_sha256` on the peering peer:

```bash
openssl x509 -in nntp.pem -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}' \
  | fold -w 2 \
  | paste -sd ':' -
```

The output is 95 characters in the form `aa:bb:cc:dd:...`. Copy it verbatim into the `cert_sha256` field on the connecting peer.

### Let's Encrypt / ACME (production)

Use certbot or acme.sh to obtain a certificate. No Let's Encrypt-specific configuration exists in the server — it reads standard PEM files.

```bash
# certbot example (nginx/standalone mode, adjust to your setup)
certbot certonly --standalone -d nntp.example.com
```

Point `cert_path` and `key_path` at the live files:

```toml
[tls]
cert_path = "/etc/letsencrypt/live/nntp.example.com/fullchain.pem"
key_path  = "/etc/letsencrypt/live/nntp.example.com/privkey.pem"
```

Configure auto-renewal to restart or reload the server after renewal so the new certificate is loaded. A systemd `ExecStartPost` or a certbot deploy hook works well for this. The server does not hot-reload certificates; a restart is required.

**Expired certificate behavior:** If the server is running with an expired certificate and has not been restarted, new TLS connections (STARTTLS or NNTPS) will fail with a `rustls` handshake error logged at WARN level:

```
WARN ... TLS handshake failed: ...certificate expired...
```

Plain-text connections on port 119 continue to work. To confirm certificate expiry:

```bash
openssl x509 -in /path/to/cert.pem -noout -dates
```

---

## TLS Version and Cipher Policy

The server accepts TLS 1.2 and TLS 1.3. TLS 1.0 and 1.1 are not offered. Cipher selection follows the rustls defaults (a conservative set without RC4, 3DES, or export ciphers). These parameters are not configurable.
