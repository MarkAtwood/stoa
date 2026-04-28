# Ceph RADOS Block Store Backend

The `rados` backend stores article blocks as RADOS objects in a Ceph cluster.
The CIDv1 string is the object key.

This backend is **transit-only** (`stoa-transit` only) and requires the `rados`
Cargo feature and `librados-dev` at build time.  It is not supported by
`stoa-reader`.

## Build requirements

Install `librados-dev` before building:

```sh
apt install librados-dev        # Debian/Ubuntu
dnf install librados-devel      # Fedora/RHEL
```

Build with the `rados` feature:

```sh
cargo build --features rados -p stoa-transit
```

## Configuration

```toml
[backend]
type = "rados"

[backend.rados]
# Path to ceph.conf (default location if omitted: /etc/ceph/ceph.conf).
conf_path = "/etc/ceph/ceph.conf"

# RADOS pool name.  Must exist before stoa-transit starts.
pool = "stoa_blocks"

# Ceph client user (without "client." prefix).
user = "stoa"
```

## Pool setup

Create the pool before starting stoa-transit.  Choose the PG count based on
your cluster size (see [Ceph PG calculator](https://docs.ceph.com/en/latest/rados/operations/placement-groups/)):

```sh
ceph osd pool create stoa_blocks 64
ceph osd pool application enable stoa_blocks nntp
```

Create a dedicated client with the minimum required permissions:

```sh
ceph auth get-or-create client.stoa \
    mon 'allow r' \
    osd 'allow rwx pool=stoa_blocks' \
    -o /etc/ceph/ceph.client.stoa.keyring
```

## Startup behaviour

On startup, stoa-transit:
1. Connects to the Ceph cluster using `conf_path` and `user`.
2. Opens an I/O context on `pool`.
3. Writes a probe object (`_stoa_write_probe`) to verify write access, then
   deletes it.

If the pool does not exist or the client lacks write permission, startup fails
immediately with a descriptive error message.

## Deletion semantics

`delete()` calls `rados_remove` which is synchronous from the application's
perspective.  After a successful delete, `get_raw()` returns `None`
immediately.  Returns `DeletionOutcome::Immediate`.

Deleting an object that does not exist is a no-op (idempotent).

## Integration testing

Use the provided docker-compose file for local testing:

```sh
docker-compose -f docker-compose.ceph.yml up -d
# Wait ~60 s for the cluster to be healthy.
docker exec stoa_test_ceph ceph osd pool create stoa_test 8
docker exec stoa_test_ceph cat /etc/ceph/ceph.conf > /tmp/ceph.conf
export TEST_RADOS_CONF=/tmp/ceph.conf
export TEST_RADOS_POOL=stoa_test
export TEST_RADOS_USER=admin
cargo test --features rados -p stoa-transit --test rados_integration
docker-compose -f docker-compose.ceph.yml down -v
```

