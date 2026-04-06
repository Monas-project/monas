#!/bin/bash
set -eu

DATA_DIR="${DATA_DIR:-/data}"
HTTP_LISTEN="${HTTP_LISTEN:-0.0.0.0:8080}"
P2P_PORT="${P2P_PORT:-9001}"
LOG_LEVEL="${LOG_LEVEL:-info}"
NODE_ROLE="${NODE_ROLE:-member}"
BOOTSTRAP_ADDR="${BOOTSTRAP_ADDR:-}"
BOOTSTRAP_DNS="${BOOTSTRAP_DNS:-}"
BOOTSTRAP_PEER_ID="${BOOTSTRAP_PEER_ID:-}"

ARGS=(
    --data-dir "$DATA_DIR"
    --listen "$HTTP_LISTEN"
    --p2p-port "$P2P_PORT"
    --log-level "$LOG_LEVEL"
)

# For member nodes, resolve bootstrap address dynamically if DNS is provided
if [ "$NODE_ROLE" != "bootstrap" ]; then
    if [ -n "$BOOTSTRAP_ADDR" ]; then
        ARGS+=(--bootstrap "$BOOTSTRAP_ADDR")
    elif [ -n "$BOOTSTRAP_DNS" ] && [ -n "$BOOTSTRAP_PEER_ID" ]; then
        # Resolve DNS to IP and wait for bootstrap node
        echo "Resolving bootstrap node: $BOOTSTRAP_DNS"
        for i in $(seq 1 30); do
            BOOTSTRAP_IP=$(getent hosts "$BOOTSTRAP_DNS" 2>/dev/null | awk '{print $1}' | head -1) || true
            if [ -n "$BOOTSTRAP_IP" ]; then
                echo "Resolved $BOOTSTRAP_DNS -> $BOOTSTRAP_IP"
                ARGS+=(--bootstrap "/ip4/${BOOTSTRAP_IP}/tcp/${P2P_PORT}/p2p/${BOOTSTRAP_PEER_ID}")
                break
            fi
            echo "Waiting for bootstrap DNS resolution (attempt $i)..."
            sleep 5
        done
    fi
fi

exec state-node "${ARGS[@]}"
