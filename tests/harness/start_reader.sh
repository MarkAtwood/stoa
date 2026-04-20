#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
READER_BIN="${REPO_ROOT}/target/debug/usenet-ipfs-reader"
PID_FILE="${SCRIPT_DIR}/.reader.pid"

if [[ ! -x "${READER_BIN}" ]]; then
    echo "error: reader binary not found at ${READER_BIN}; run: cargo build -p usenet-ipfs-reader" >&2
    exit 1
fi

if [[ -n "${1:-}" ]]; then
    PORT="$1"
else
    PORT=$(( RANDOM % 5000 + 15000 ))
fi

TMPDIR_RUN="$(mktemp -d)"
CONFIG_FILE="${TMPDIR_RUN}/reader.toml"

cat > "${CONFIG_FILE}" <<TOML
[listen]
addr = "127.0.0.1:${PORT}"

[limits]
max_connections = 10
command_timeout_secs = 30

[auth]
required = false

[tls]

[log]
level = "warn"
format = "text"
TOML

"${READER_BIN}" --config "${CONFIG_FILE}" \
    >"${TMPDIR_RUN}/reader.log" 2>&1 &
READER_PID=$!
echo "${READER_PID}" > "${PID_FILE}"
echo "${TMPDIR_RUN}" >> "${PID_FILE}"

WAIT=0
while [[ ${WAIT} -lt 50 ]]; do
    if nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
        break
    fi
    sleep 0.1
    WAIT=$(( WAIT + 1 ))
done

if ! nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
    echo "error: reader did not start on port ${PORT} within 5 seconds" >&2
    kill "${READER_PID}" 2>/dev/null || true
    rm -f "${PID_FILE}"
    rm -rf "${TMPDIR_RUN}"
    exit 1
fi

echo "${PORT}"
