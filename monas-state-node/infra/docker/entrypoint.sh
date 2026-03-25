#!/bin/bash
set -eu

DATA_DIR="${DATA_DIR:-/data}"
HTTP_LISTEN="${HTTP_LISTEN:-0.0.0.0:8080}"
P2P_PORT="${P2P_PORT:-9001}"
LOG_LEVEL="${LOG_LEVEL:-info}"
NODE_ROLE="${NODE_ROLE:-member}"
BOOTSTRAP_ADDR="${BOOTSTRAP_ADDR:-}"

ARGS=(
    --data-dir "$DATA_DIR"
    --listen "$HTTP_LISTEN"
    --p2p-port "$P2P_PORT"
    --log-level "$LOG_LEVEL"
)

if [ "$NODE_ROLE" != "bootstrap" ] && [ -n "$BOOTSTRAP_ADDR" ]; then
    ARGS+=(--bootstrap "$BOOTSTRAP_ADDR")
fi

exec state-node "${ARGS[@]}"
