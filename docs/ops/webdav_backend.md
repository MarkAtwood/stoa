# WebDAV Block Store Backend

This guide covers the `backend.type = "webdav"` configuration option for
`stoa-reader`, which stores article blocks on any WebDAV-compatible server.

## Configuration

```toml
[backend]
type = "webdav"

[backend.webdav]
url = "https://dav.example.com/remote.php/dav/files/USERNAME/stoa-blocks/"
username = "alice"
password = "secretx://env/WEBDAV_PASSWORD"   # or literal string
# allow_http = false                         # default; set true for LAN-only servers
```

- **`url`** — Base URL of the WebDAV collection. Must end with `/`. All blocks
  are stored directly under this prefix as `<url>/<cid>`.
- **`username`** / **`password`** — Optional Basic-auth credentials.
  Use `secretx://env/VAR` or `secretx://file/path` to avoid plaintext secrets
  in the config file.
- **`allow_http`** — Defaults to `false`. The daemon refuses to start with an
  `http://` URL unless this is set to `true`. Never set `true` for
  internet-facing servers; credentials would be transmitted in plaintext.

## Nextcloud

### Prerequisites

- Nextcloud instance with a dedicated user (e.g. `stoa-blocks`)
- An **App Password** for that user (`Settings → Security → App passwords`)

### URL Format

Nextcloud exposes WebDAV at:

```
https://<nextcloud-host>/remote.php/dav/files/<username>/
```

Create a dedicated folder in the Nextcloud Files UI (e.g. `stoa-blocks`), then
configure:

```toml
[backend.webdav]
url = "https://cloud.example.com/remote.php/dav/files/stoa-blocks/stoa-blocks/"
username = "stoa-blocks"
password = "secretx://env/NC_APP_PASSWORD"
```

### App Password

1. Log in as the `stoa-blocks` user
2. Navigate to **Settings → Security**
3. Scroll to **App passwords**, enter an app name (e.g. `stoa-transit`), click **Create new app password**
4. Copy the generated password — it is only shown once
5. Store it in your secrets manager or set `NC_APP_PASSWORD` in the environment

### Verification

```sh
curl -u stoa-blocks:"$NC_APP_PASSWORD" \
     -T /dev/null \
     https://cloud.example.com/remote.php/dav/files/stoa-blocks/stoa-blocks/_probe
curl -u stoa-blocks:"$NC_APP_PASSWORD" \
     -X DELETE \
     https://cloud.example.com/remote.php/dav/files/stoa-blocks/stoa-blocks/_probe
```

Both should return HTTP 2xx. If you get 401, re-check the app password. If you
get 403 on DELETE, the folder permissions are too restrictive.

## Hetzner Storage Box

Hetzner Storage Boxes support WebDAV over HTTPS (port 443) and plain HTTP
(port 80). Always use HTTPS.

### URL Format

```
https://<username>.your-storagebox.de/
```

Sub-directories are created on demand:

```toml
[backend.webdav]
url = "https://u123456.your-storagebox.de/stoa-blocks/"
username = "u123456"
password = "secretx://env/HETZNER_BOX_PASSWORD"
```

### Creating the Sub-directory

```sh
curl -u u123456:"$HETZNER_BOX_PASSWORD" \
     -X MKCOL \
     https://u123456.your-storagebox.de/stoa-blocks/
```

Returns `201 Created` on success, `405 Method Not Allowed` if it already exists
(safe to ignore).

### Sub-account with Restricted Path

For least-privilege access, create a Storage Box sub-account in the Hetzner
Robot panel and restrict it to the `/stoa-blocks` directory. Use the
sub-account credentials in the config.

## Local Testing with Docker

Start a local no-auth WebDAV server:

```sh
docker-compose -f docker-compose.webdav.yml up -d
```

Run the integration test suite:

```sh
TEST_WEBDAV_URL=http://localhost:8181/ \
  cargo test -p stoa-reader --test webdav_integration
```

Stop and discard:

```sh
docker-compose -f docker-compose.webdav.yml down -v
```

## Startup Probe

On every daemon start, `stoa-reader` writes and deletes a zero-byte object at
`<url>/_stoa_write_probe`. If either the write or delete fails, the daemon
exits immediately with a descriptive error. This catches:

- Wrong URL or missing trailing slash
- Incorrect credentials
- Quota exceeded
- Read-only mount

## Security Notes

- Use `secretx://` for all credentials — never commit raw passwords.
- Bind the Nextcloud user to the minimum folder needed; grant no admin rights.
- For Hetzner Storage Box, prefer a sub-account scoped to the stoa directory.
- `allow_http = true` is only appropriate for loopback or isolated LAN servers
  where the network is fully trusted and no credentials are configured.
