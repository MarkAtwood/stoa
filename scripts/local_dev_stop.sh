#!/usr/bin/env bash
# Stop the usenet-ipfs local development environment.

WORK_DIR=/tmp/usenet-ipfs-dev

stop_pid() {
    local pid_file=$1 name=$2
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "Stopped $name (pid $pid)"
        else
            echo "$name was not running"
        fi
        rm -f "$pid_file"
    fi
}

stop_pid "$WORK_DIR/transit.pid" "transit"
stop_pid "$WORK_DIR/reader.pid"  "reader"
stop_pid "$WORK_DIR/ipfs.pid"    "ipfs"
echo "Done. Logs remain in $WORK_DIR/"
