#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PID=""
FRONTEND_PID=""
CLEANED_UP=0

cleanup() {
    local exit_status=$?

    if [ "$CLEANED_UP" -eq 1 ]; then
        return
    fi
    CLEANED_UP=1
    trap - EXIT INT TERM

    for pid in "$BACKEND_PID" "$FRONTEND_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$BACKEND_PID" "$FRONTEND_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    exit "$exit_status"
}

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

echo "Starting TUCO backend at http://127.0.0.1:8000 (data root: $ROOT_DIR/data)"
"$ROOT_DIR/.venv/bin/python" -m uvicorn app.main:app \
    --app-dir "$ROOT_DIR/backend" \
    --host 127.0.0.1 \
    --port 8000 \
    --reload &
BACKEND_PID=$!

echo "Starting TUCO frontend at http://127.0.0.1:5173"
(
    cd "$ROOT_DIR/frontend"
    npm run dev -- --host 127.0.0.1 --port 5173
) &
FRONTEND_PID=$!

wait -n "$BACKEND_PID" "$FRONTEND_PID"
