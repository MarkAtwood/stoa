#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
    "${SCRIPT_DIR}/stop_reader.sh"
}
trap cleanup EXIT

PORT="$("${SCRIPT_DIR}/start_reader.sh")"
echo "reader started on port ${PORT}"

if python3 "${SCRIPT_DIR}/nntp_driver.py" "${PORT}"; then
    echo "PASS"
    exit 0
else
    echo "FAIL"
    exit 1
fi
