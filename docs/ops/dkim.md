# DKIM Key Generation

stoa-smtp supports Ed25519 DKIM signing of outbound messages (RFC 8463).
The signing keypair is supplied in the `[delivery.dkim]` config section as
standard base64-encoded raw 32-byte values — NOT PEM files, NOT DER files.

## Key format

- `key_seed_b64`: the 32-byte Ed25519 private seed, base64-standard-encoded
- `public_key_b64`: the 32-byte Ed25519 public key, base64-standard-encoded

Both use **standard** base64 (RFC 4648 §4 — `+` and `/` alphabet, `=` padding).
URL-safe base64 (`-` and `_`) is NOT accepted.

## Generating a keypair

Using OpenSSL 3.x:

```sh
# Generate an Ed25519 private key in PEM form
openssl genpkey -algorithm ed25519 -out dkim.pem

# Extract the raw 32-byte seed.
# Ed25519 PKCS8 DER is 48 bytes: 16-byte header + 32-byte seed.
openssl pkey -in dkim.pem -outform DER | tail -c 32 | base64

# Extract the raw 32-byte public key.
# Ed25519 SubjectPublicKeyInfo DER is 44 bytes: 12-byte header + 32-byte key.
openssl pkey -in dkim.pem -pubout -outform DER | tail -c 32 | base64
```

The first `base64` output is `key_seed_b64`.
The second `base64` output is `public_key_b64`.

Verify the lengths decode correctly:

```sh
echo "<your key_seed_b64>"   | base64 -d | wc -c   # must print 32
echo "<your public_key_b64>" | base64 -d | wc -c   # must print 32
```

## Config example

```toml
[delivery.dkim]
domain      = "example.com"
selector    = "mail"
key_seed_b64   = "<your key_seed_b64>"
public_key_b64 = "<your public_key_b64>"
```

When `[delivery.dkim]` is absent, outbound messages are not DKIM-signed and
no DNS record is required.

## DNS TXT record

Publish a TXT record at `<selector>._domainkey.<domain>`:

```
v=DKIM1; k=ed25519; p=<your public_key_b64>
```

Example for domain `example.com`, selector `mail`:

```
mail._domainkey.example.com.  300  IN  TXT  "v=DKIM1; k=ed25519; p=<your public_key_b64>"
```

Most DNS providers accept the record body without the leading `v=DKIM1; k=ed25519; `
prefix as a separate quoted string — check your provider's DKIM wizard for the
expected format.

You can verify the record published correctly with:

```sh
dig TXT mail._domainkey.example.com +short
```

## Security

`key_seed_b64` is the private signing key.  Treat it as a secret:

- Do not commit it to source control.
- Use `secretx://` URI injection or environment variable substitution for
  production deployments.  See `docs/adr/ADR-0011-secretx-operator-secrets.md`
  for the secretx:// protocol.
- stoa-smtp redacts `key_seed_b64` from all `Debug` output and log lines.

## Key rotation

To rotate the DKIM key:

1. Generate a new keypair as above.
2. Publish the new public key at a **new selector** (e.g. `mail2`).
3. Verify the new DNS record is live: `dig TXT mail2._domainkey.example.com`.
4. Update `selector` and both key fields in the config and restart stoa-smtp.
5. Remove the old DNS record after a suitable propagation window (24–48 h).
