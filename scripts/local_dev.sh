#!/usr/bin/env bash
set -euo pipefail

# usenet-ipfs local two-node development environment.
# Requires: kubo (ipfs), cargo (Rust toolchain).
# Starts: 1 IPFS node, 1 transit daemon, 1 reader daemon.
# All state written to /tmp/usenet-ipfs-dev/.
#
# NOTE: /health endpoints are not yet implemented in either daemon.
# The readiness poll will time out and print a warning; this is expected
# until those endpoints are wired up.

WORK_DIR=/tmp/usenet-ipfs-dev
TRANSIT_PID_FILE="$WORK_DIR/transit.pid"
READER_PID_FILE="$WORK_DIR/reader.pid"
IPFS_PID_FILE="$WORK_DIR/ipfs.pid"
TRANSIT_LOG="$WORK_DIR/transit.log"
READER_LOG="$WORK_DIR/reader.log"
IPFS_LOG="$WORK_DIR/ipfs.log"
TRANSIT_ADMIN_ADDR="127.0.0.1:8080"
READER_NNTP_ADDR="127.0.0.1:1190"
READER_ADMIN_ADDR="127.0.0.1:8081"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

check_binary() {
    local bin=$1
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "WARNING: '$bin' not found in PATH — some steps will be skipped" >&2
        return 1
    fi
    return 0
}

check_already_running() {
    local pid_file=$1 name=$2
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: $name is already running (pid $pid). Run scripts/local_dev_stop.sh first." >&2
            exit 1
        else
            rm -f "$pid_file"
        fi
    fi
}

wait_for_health() {
    local addr=$1 name=$2
    for i in $(seq 1 30); do
        if curl -sf "http://$addr/health" >/dev/null 2>&1; then
            echo "  $name is ready"
            return 0
        fi
        sleep 1
    done
    echo "  WARNING: $name did not become ready in 30s (health endpoint may not be implemented yet)" >&2
    return 0
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

mkdir -p "$WORK_DIR"

echo "==> Checking required binaries"
HAVE_IPFS=true
HAVE_CARGO=true
check_binary ipfs   || HAVE_IPFS=false
check_binary cargo  || HAVE_CARGO=false
check_binary openssl || echo "WARNING: 'openssl' not found — keypair generation will be skipped" >&2

# ---------------------------------------------------------------------------
# Guard against double-start
# ---------------------------------------------------------------------------

check_already_running "$IPFS_PID_FILE"    "IPFS"
check_already_running "$TRANSIT_PID_FILE" "transit"
check_already_running "$READER_PID_FILE"  "reader"

# ---------------------------------------------------------------------------
# Start IPFS
# ---------------------------------------------------------------------------

if [ "$HAVE_IPFS" = "true" ]; then
    echo "==> Starting IPFS daemon"
    export IPFS_PATH="$WORK_DIR/ipfs-repo"

    if [ ! -d "$IPFS_PATH" ]; then
        echo "    Initialising IPFS repo at $IPFS_PATH"
        ipfs init --profile=test >"$IPFS_LOG" 2>&1
    fi

    # Use a non-standard API port to avoid colliding with any running kubo.
    ipfs config Addresses.API "/ip4/127.0.0.1/tcp/5001" >>"$IPFS_LOG" 2>&1
    ipfs config Addresses.Gateway "/ip4/127.0.0.1/tcp/8090" >>"$IPFS_LOG" 2>&1

    ipfs daemon --routing=none >>"$IPFS_LOG" 2>&1 &
    IPFS_PID=$!
    echo "$IPFS_PID" >"$IPFS_PID_FILE"
    echo "    IPFS daemon started (pid $IPFS_PID)"

    echo "    Waiting for IPFS API to become ready..."
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:5001/api/v0/id" >/dev/null 2>&1; then
            echo "    IPFS is ready"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "    WARNING: IPFS did not become ready in 30s; continuing anyway" >&2
        fi
        sleep 1
    done
else
    echo "    Skipping IPFS start (ipfs not found)"
fi

# ---------------------------------------------------------------------------
# Build workspace
# ---------------------------------------------------------------------------

if [ "$HAVE_CARGO" = "true" ]; then
    echo "==> Building workspace"
    cargo build --workspace --quiet --manifest-path "$REPO_ROOT/Cargo.toml"
    TRANSIT_BIN="$REPO_ROOT/target/debug/usenet-ipfs-transit"
    READER_BIN="$REPO_ROOT/target/debug/usenet-ipfs-reader"
else
    echo "    Skipping build (cargo not found)"
    TRANSIT_BIN=""
    READER_BIN=""
fi

# ---------------------------------------------------------------------------
# Generate test keypair
# ---------------------------------------------------------------------------

KEY_FILE="$WORK_DIR/operator-key.json"
if [ ! -f "$KEY_FILE" ]; then
    if command -v openssl >/dev/null 2>&1; then
        echo "==> Generating test operator keypair"
        PRIVKEY_HEX=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null \
            | tail -c 32 | xxd -p -c 64)
        printf '{"type":"ed25519","private_key_hex":"%s"}\n' "$PRIVKEY_HEX" >"$KEY_FILE"
        echo "    Keypair written to $KEY_FILE"
    else
        echo "    Skipping keypair generation (openssl not found)"
    fi
else
    echo "==> Operator keypair already exists at $KEY_FILE"
fi

# ---------------------------------------------------------------------------
# Write transit config
# ---------------------------------------------------------------------------

echo "==> Writing transit config"
cat >"$WORK_DIR/transit.toml" <<EOF
[listen]
addr = "127.0.0.1:1119"

[peers]
addresses = []

[groups]
names = [
    "alt.test",
    "comp.lang.rust",
]

[ipfs]
api_url = "http://127.0.0.1:5001"

[pinning]
rules = [
    "pin-all-ingress",
]

[gc]
schedule = "0 3 * * *"
max_age_days = 90

[admin]
addr = "$TRANSIT_ADMIN_ADDR"

[log]
level = "info"
format = "text"
EOF

# ---------------------------------------------------------------------------
# Write reader config
# ---------------------------------------------------------------------------

echo "==> Writing reader config"
cat >"$WORK_DIR/reader.toml" <<EOF
[listen]
addr = "$READER_NNTP_ADDR"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[admin]
addr = "$READER_ADMIN_ADDR"

[log]
level = "info"
format = "text"
EOF

# ---------------------------------------------------------------------------
# Start transit
# ---------------------------------------------------------------------------

if [ -n "$TRANSIT_BIN" ] && [ -x "$TRANSIT_BIN" ]; then
    echo "==> Starting transit daemon"
    "$TRANSIT_BIN" --config "$WORK_DIR/transit.toml" >"$TRANSIT_LOG" 2>&1 &
    TRANSIT_PID=$!
    echo "$TRANSIT_PID" >"$TRANSIT_PID_FILE"
    echo "    Transit started (pid $TRANSIT_PID, log: $TRANSIT_LOG)"
    wait_for_health "$TRANSIT_ADMIN_ADDR" "transit"
else
    echo "    Skipping transit start (binary not found)"
fi

# ---------------------------------------------------------------------------
# Start reader
# ---------------------------------------------------------------------------

if [ -n "$READER_BIN" ] && [ -x "$READER_BIN" ]; then
    echo "==> Starting reader daemon"
    "$READER_BIN" --config "$WORK_DIR/reader.toml" >"$READER_LOG" 2>&1 &
    READER_PID=$!
    echo "$READER_PID" >"$READER_PID_FILE"
    echo "    Reader started (pid $READER_PID, log: $READER_LOG)"
    wait_for_health "$READER_ADMIN_ADDR" "reader"
else
    echo "    Skipping reader start (binary not found)"
fi

# ---------------------------------------------------------------------------
# Connection info
# ---------------------------------------------------------------------------

echo ""
echo "usenet-ipfs local dev environment is up."
echo ""
echo "  NNTP reader:      $READER_NNTP_ADDR"
echo "  Transit peering:  127.0.0.1:1119"
echo "  Transit admin:    http://$TRANSIT_ADMIN_ADDR"
echo "  Reader admin:     http://$READER_ADMIN_ADDR"
echo "  IPFS API:         http://127.0.0.1:5001"
echo "  Work dir:         $WORK_DIR"
echo ""
echo "  Connect with:     slrn -h localhost:1190"
echo "                    tin -g localhost:1190"
echo ""
echo "  Logs: $TRANSIT_LOG"
echo "        $READER_LOG"
echo "        $IPFS_LOG"
echo ""
echo "  Stop with:        scripts/local_dev_stop.sh"
