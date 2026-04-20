#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.reader.pid"

if [[ ! -f "${PID_FILE}" ]]; then
    echo "stop_reader: no .reader.pid file found; nothing to stop" >&2
    exit 0
fi

READER_PID="$(head -1 "${PID_FILE}")"
TMPDIR_RUN="$(tail -1 "${PID_FILE}")"

if kill "${READER_PID}" 2>/dev/null; then
    wait "${READER_PID}" 2>/dev/null || true
fi

rm -f "${PID_FILE}"

if [[ -n "${TMPDIR_RUN}" && "${TMPDIR_RUN}" == /tmp/* ]]; then
    rm -rf "${TMPDIR_RUN}"
fi
