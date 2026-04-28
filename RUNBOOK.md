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

---

# Secrets Management

Several config fields accept `secretx:` URIs in addition to literal values.  At startup the daemon resolves any URI and exits with an error if retrieval fails — secrets are never fetched at request time.

## Fields that accept secretx: URIs

| Crate | Config field | Value type |
|---|---|---|
| transit | `admin.bearer_token` | UTF-8 string |
| reader | `admin.admin_token` | UTF-8 string |
| transit | `pinning.external_services[*].api_key` | UTF-8 string |
| transit | `operator.signing_key_path` | 32-byte binary (Ed25519 seed) |
| reader | `operator.signing_key_path` | 32-byte binary (Ed25519 seed) |
| reader | `auth.credential_file` | UTF-8 text (username:hash lines) |
| mail | `auth.credential_file` | UTF-8 text (username:hash lines) |
| smtp | `auth.credential_file` | UTF-8 text (username:hash lines) |
| transit | `tls.key_path` | UTF-8 PEM (TLS private key) |
| reader | `tls.key_path` | UTF-8 PEM (TLS private key) |
| smtp | `tls.key_path` | UTF-8 PEM (TLS private key) |

## URI formats

```
secretx:env:<VAR_NAME>
secretx:file:<absolute-path>
secretx:aws-sm:<secret-name-or-arn>[?field=<json_field>]
secretx:aws-kms:<key-id-or-alias>[?algorithm=<algo>]
```

### Examples

```toml
# Read admin token from environment variable
admin.bearer_token = "secretx:env:STOA_ADMIN_TOKEN"

# Read admin token from a file (no world-readable permission check for secretx paths)
admin.admin_token = "secretx:file:/run/secrets/stoa_admin_token"

# Read signing key from AWS Secrets Manager (binary secret, 32 bytes)
operator.signing_key_path = "secretx:aws-sm:prod/stoa/signing-key"

# Read TLS private key PEM from AWS Secrets Manager
tls.key_path = "secretx:aws-sm:prod/stoa/tls-private-key"

# Read credential file content from AWS Secrets Manager
auth.credential_file = "secretx:aws-sm:prod/stoa/credentials?field=creds"
```

## AWS Secrets Manager setup

### Operator signing key (binary secret)

The signing key is a raw 32-byte Ed25519 seed.  Store it as a **binary** secret:

```bash
# Export the key file as a binary secret (key file must be exactly 32 bytes)
aws secretsmanager create-secret \
  --name prod/stoa/signing-key \
  --secret-binary fileb:///etc/stoa/operator.key

# Verify
aws secretsmanager get-secret-value --secret-id prod/stoa/signing-key \
  --query SecretBinary --output text | base64 -d | wc -c
# must print: 32
```

Note: AWS KMS asymmetric keys support only ECDSA-P256 and RSA-PSS-2048 for signing — **not Ed25519**. Stoa uses Ed25519 exclusively. Store the 32-byte seed in Secrets Manager; do not use KMS for the signing key.

### TLS private key (string secret)

The TLS private key is a PEM-encoded file.  Store it as a **string** secret:

```bash
aws secretsmanager create-secret \
  --name prod/stoa/tls-private-key \
  --secret-string file:///etc/ssl/private/stoa.key
```

### Credential file (string secret)

Store credential file content (username:bcrypt_hash lines) as a string secret.  Use the `?field=<name>` query parameter if the secret is a JSON object:

```bash
# Single-value string secret
aws secretsmanager create-secret \
  --name prod/stoa/credentials \
  --secret-string "$(cat /etc/stoa/credentials.txt)"

# Or as a JSON field:
# {"creds":"alice:$2b$12$..."}
# → use: secretx:aws-sm:prod/stoa/credentials?field=creds
```

## IAM policy

Grant the stoa process only the secrets it needs.  Use the IAM role attached to your EC2 instance or ECS task:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": [
        "arn:aws:secretsmanager:<region>:<account>:secret:prod/stoa/*"
      ]
    }
  ]
}
```

Tighten the `Resource` list to only the specific secret ARNs if the instance hosts multiple services.

## Behavior notes

### credential_file failures are fatal at startup

If `auth.credential_file` is set (filesystem path or secretx URI) and cannot be
read or parsed, all binaries (`stoa-reader`, `stoa-smtp`, `stoa-mail`) will exit
with an error at startup rather than continuing with only inline `auth.users`.
This is intentional: silently ignoring a misconfigured credential file would mean
authentication runs against a different set of users than expected, which is a
security regression, not graceful degradation.

If you want a server to start without any credential file, remove the
`credential_file` key from the `[auth]` section entirely.

### secretx:env is not suitable for binary secrets

`secretx:env:FOO` resolves the value of the environment variable `FOO` as
raw bytes.  For the Ed25519 signing key (32 raw binary bytes), this means the
env var must contain exactly 32 raw binary bytes — not a base64 or hex
encoding.  Setting a 32-byte raw binary value in a shell env var is impractical.

Use `secretx:file:/path/to/key` for local deployments (the key file already
contains raw bytes, same constraint as the direct `signing_key_path` file path).
Use `secretx:aws-sm:...` for production.  Do not use `secretx:env:` for the
signing key.

## Adding new secretx-capable config fields (developer note)

Three patterns exist in the codebase for resolving secretx URIs at startup.
Use the right one for each field type:

**Pattern A — `resolve_secret_uri` helper (UTF-8 string fields)**
Use for string fields that need no special post-processing (admin tokens,
bearer tokens). Call site in `main()`:
```rust
let admin_token = resolve_secret_uri(config.admin.admin_token.clone(), "admin.admin_token").await;
```

**Pattern B — method on the type (domain types that own their secret)**
Use when the field has its own opaque type with a `Debug`/`Display` redaction
invariant that must be preserved during resolution (currently: `PinningApiKey`).
Implement `pub async fn resolve(self, label: &str) -> Self` on the type.
The type owns the `secretx::from_uri` call and the `process::exit` on failure.

**Pattern C — inline resolution (binary/non-UTF-8 secrets)**
Use for secrets where the raw bytes must be post-processed before use (TLS
private key PEM → `PrivateKeyDer`, Ed25519 seed bytes → `SigningKey`).
The conversion step (`load_private_key_from_bytes`, `load_signing_key_from_bytes`)
is specific enough that a shared helper would not simplify the code.

Do not use `secretx` at request time. All resolution must happen before the
server starts accepting connections.

## Enabling AWS SM support

The `secretx` crate is compiled with `env` and `file` features by default.  To enable `aws-sm`, add the feature in `Cargo.toml` (root workspace):

```toml
[workspace.dependencies]
secretx = { version = "0.3.0", default-features = false, features = ["env", "file", "aws-sm"] }
```

This requires the `aws-config` crate chain and will increase binary size.  Only enable it on deployments that use AWS Secrets Manager.

---

## Aurora Serverless v2 Deployment (usenet-ipfs-ky62.7)

This section documents running `stoa-transit` and `stoa-reader` with Amazon
Aurora Serverless v2 (PostgreSQL-compatible) instead of the default SQLite
backend.

### 1. Create the Aurora Serverless v2 Cluster

```bash
aws rds create-db-cluster \
  --db-cluster-identifier stoa-db \
  --engine aurora-postgresql \
  --engine-version 16.2 \
  --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=16 \
  --db-subnet-group-name stoa-subnet-group \
  --vpc-security-group-ids sg-XXXXXXXX \
  --enable-iam-database-authentication \
  --master-username stoaadmin \
  --manage-master-user-password \
  --no-deletion-protection
```

Then add a writer instance:

```bash
aws rds create-db-instance \
  --db-instance-identifier stoa-db-writer \
  --db-cluster-identifier stoa-db \
  --db-instance-class db.serverless \
  --engine aurora-postgresql
```

### 2. VPC and Security Group Configuration

- Place the cluster in private subnets with no direct internet access.
- Create a security group `sg-stoa-db` that allows TCP 5432 from the
  transit/reader instance security groups only. No 0.0.0.0/0 ingress.
- The transit and reader EC2 instances need an IAM role with the
  `rds-db:connect` permission (see §3 below).
- Outbound: allow TCP 443 from transit/reader to reach AWS secrets endpoints
  (Secrets Manager, IAM) when using IAM authentication.

Example security group ingress rule (CLI):

```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-stoa-db \
  --protocol tcp --port 5432 \
  --source-group sg-stoa-transit
```

### 3. IAM Database Authentication (preferred)

IAM auth eliminates long-lived passwords. The connection token is a
short-lived (15-minute) pre-signed URL derived from the instance's IAM role.

**Enable on the cluster** (already included in the `create-db-cluster` command
above via `--enable-iam-database-authentication`).

**Create a DB user mapped to IAM:**

```sql
CREATE USER stoa_transit WITH LOGIN;
GRANT rds_iam TO stoa_transit;

CREATE USER stoa_reader WITH LOGIN;
GRANT rds_iam TO stoa_reader;
```

**IAM policy for the EC2 instance role:**

```json
{
  "Effect": "Allow",
  "Action": "rds-db:connect",
  "Resource": "arn:aws:rds-db:REGION:ACCOUNT:dbuser:CLUSTER_RESOURCE_ID/stoa_transit"
}
```

**Generate a connection token** (for debugging; the application does this
automatically via the `aws-sdk-rds` crate when using the `iam-auth` driver):

```bash
aws rds generate-db-auth-token \
  --hostname stoa-db.cluster-XXXXX.REGION.rds.amazonaws.com \
  --port 5432 --region REGION --username stoa_transit
```

**Connection string format with IAM auth token** (token is the password):

```
postgres://stoa_transit:TOKEN@stoa-db.cluster-XXXXX.REGION.rds.amazonaws.com:5432/stoa?sslmode=verify-full&sslrootcert=/etc/ssl/certs/rds-combined-ca-bundle.pem
```

Set this in `database.url` (or a `secretx:` URI pointing to AWS Secrets
Manager for the token rotation case):

```toml
[database]
url = "secretx:aws-sm:///stoa/transit/db_url"
```

### 4. Password Authentication (simpler, less preferred)

If IAM auth is not used, Aurora's master password is stored in AWS Secrets
Manager by passing `--manage-master-user-password` to `create-db-cluster`.
Retrieve it and set:

```toml
[database]
url = "secretx:aws-sm:///stoa/transit/db_url"
```

Where the Secrets Manager secret value is the full connection string:

```
postgres://stoa_transit:PASSWORD@stoa-db.cluster-XXXXX.REGION.rds.amazonaws.com:5432/stoa?sslmode=verify-full
```

### 5. Connection Pool Sizing for Serverless v2

Aurora Serverless v2 scales ACUs (Aurora Capacity Units) based on load.
Each ACU provides approximately 2 GiB of RAM. The PostgreSQL `max_connections`
parameter scales with ACUs:

| ACUs | Approximate `max_connections` |
|------|-------------------------------|
| 0.5  | ~90                           |
| 2    | ~350                          |
| 8    | ~1400                         |
| 16   | ~2800                         |

The stoa config `database.pool_size` defaults to 4 connections per process.
For a multi-instance deployment with N transit daemons, total connections ≈
`N × pool_size`. Keep this well below Aurora's `max_connections` to leave
headroom for administrative connections and autoscaling warm-up.

Recommended starting values:

```toml
[database]
pool_size = 4   # per transit/reader process; multiply by instance count
```

For Aurora Serverless v2, avoid setting `MinCapacity` below 0.5 ACU in
production — the cold-start latency on the first connection after a scale-to-zero
event can exceed 30 seconds and will timeout the connection pool.

### 6. Multi-Instance Transit Deployment

With Aurora as the shared metadata backend, multiple `stoa-transit` daemons
can run simultaneously against the same database.  The following features
coordinate across instances automatically:

| Feature | Mechanism | Behaviour |
|---------|-----------|-----------|
| GC runs | `pg_try_advisory_lock(GC_ADVISORY_LOCK_ID)` | Only one instance runs GC per interval |
| IPNS publishing | `pg_try_advisory_lock(IPNS_ADVISORY_LOCK_ID)` | Only one instance publishes IPNS records |
| HLC node_id | `transit_instance_id` table | Each hostname gets a distinct, stable 8-byte ID |

**Deployment checklist:**

1. Run migrations once before starting any daemon (use `--check` mode or a
   migration-only invocation; the normal startup path also runs them idempotently).
2. All daemons must point at the same `database.url` (Aurora writer endpoint).
3. Each daemon should use a distinct `operator.hostname` (or leave it unset so
   the system hostname is used). This determines the HLC `node_id` and the
   IPNS advisory lock winner.
4. The GC schedule is per-instance; only the lock-holder runs GC. Ensure all
   instances have the same `[gc]` configuration.
5. Monitor `gc_articles_unpinned_total` and `gc_last_run_duration_ms` in the
   admin Prometheus endpoint to confirm exactly one instance is performing GC.

### 7. Running Migrations Against Aurora

```bash
# One-time setup (run from a host with network access to the Aurora endpoint):
export DATABASE_URL="postgres://stoa_transit:TOKEN@stoa-db.cluster-XXXXX.REGION.rds.amazonaws.com:5432/stoa?sslmode=verify-full"

# Core schema:
cargo run -p stoa-transit -- --config /dev/null --check 2>/dev/null || true

# Or use the migration runner directly (requires sqlx-cli):
sqlx migrate run --source crates/core/migrations_pg     --database-url "$DATABASE_URL"
sqlx migrate run --source crates/transit/migrations_pg  --database-url "$DATABASE_URL"
sqlx migrate run --source crates/reader/migrations_pg   --database-url "$DATABASE_URL"
sqlx migrate run --source crates/verify/migrations_pg   --database-url "$DATABASE_URL"
```

Normal daemon startup also runs migrations (idempotently), so the explicit
migration step is only needed for zero-downtime upgrades where you want
migrations applied before the new binary is rolled out.
