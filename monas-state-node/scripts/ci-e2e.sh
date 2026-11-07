#!/bin/bash

# Monas State Node - CI E2E runner
#
# Starts 4 state-nodes as an interconnected mesh (creator + 3 members,
# MIN_REPLICATION_FACTOR=3) and runs e2e-test.sh. The nodes are always stopped
# on exit, regardless of success or failure. Self-contained so it can be called
# both from the CI e2e job and for local reproduction.
#
# Why this script requires 4 nodes: create_content needs MIN_REPLICATION_FACTOR
# (=3) members excluding the creator itself, so with fewer than 4 nodes the member
# quorum cannot be met and it fails with NoAvailableMembers.
#
# Exit code: passes through the result of e2e-test.sh (0 if all tests pass).

set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[ci-e2e]${NC} $1"; }
warn() { echo -e "${YELLOW}[ci-e2e]${NC} $1"; }
err()  { echo -e "${RED}[ci-e2e]${NC} $1"; }

STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

BIN="$STATE_NODE_DIR/../target/debug/state-node"
LOG_DIR="$STATE_NODE_DIR/logs"; mkdir -p "$LOG_DIR"
PIDS=()

# creator + 3 members
export MIN_REPLICATION_FACTOR=3

# HTTP ports and the P2P port assigned to each (separate ports are given
# explicitly to avoid colliding with the fixed default 9090).
HTTP_PORTS=(8080 8081 8082 8083)
P2P_PORTS=(9091 9092 9093 9094)

cleanup() {
    log "Stopping nodes..."
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid:-}" ] || continue
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.3
            done
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT INT TERM

wait_for_health() {
    local port="$1"
    for _ in $(seq 1 60); do
        if curl -s "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# --- Build -----------------------------------------------------------------
log "Building state-node..."
if ! cargo build --bin state-node; then
    err "Failed to build state-node"
    exit 1
fi

# --- Clean data directories -------------------------------------------
rm -rf data/node1 data/node2 data/node3 data/node4
mkdir -p data/node1 data/node2 data/node3 data/node4

# --- bootstrap node (node1) -------------------------------------------------
# Always disable mDNS. If left enabled, nodes rediscover each other via broadcast
# even when bootstrap or Kademlia discovery is broken, and the test passes. That
# path does not exist in the VPC, so a total outage seen in production could not
# be reproduced locally. --disable-mdns verifies only the same discovery path as
# production.
log "Starting node1 (bootstrap) on :${HTTP_PORTS[0]} / p2p :${P2P_PORTS[0]}..."
"$BIN" --data-dir ./data/node1 -l "127.0.0.1:${HTTP_PORTS[0]}" \
    --p2p-port "${P2P_PORTS[0]}" --disable-mdns --log-level info > "$LOG_DIR/node1.log" 2>&1 &
PIDS+=($!)

if ! wait_for_health "${HTTP_PORTS[0]}"; then
    err "node1 failed to start"; cat "$LOG_DIR/node1.log" || true; exit 1
fi

NODE1_INFO=$(curl -s "http://127.0.0.1:${HTTP_PORTS[0]}/node/info")
NODE1_PEER_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')
NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)
if [ -z "$NODE1_PEER_ID" ] || [ "$NODE1_PEER_ID" = "null" ] || [ -z "$NODE1_ADDR" ]; then
    err "Could not get node1's peer id / listen address"; echo "$NODE1_INFO"; exit 1
fi
BOOTSTRAP="${NODE1_ADDR}/p2p/${NODE1_PEER_ID}"
log "bootstrap = $BOOTSTRAP"

# --- member nodes (node2..node4) --------------------------------------------
for i in 1 2 3; do
    n=$((i + 1))
    log "Starting node$n on :${HTTP_PORTS[$i]} / p2p :${P2P_PORTS[$i]} (-> bootstrap)..."
    "$BIN" --data-dir "./data/node$n" -l "127.0.0.1:${HTTP_PORTS[$i]}" \
        --p2p-port "${P2P_PORTS[$i]}" -b "$BOOTSTRAP" --disable-mdns --log-level info \
        > "$LOG_DIR/node$n.log" 2>&1 &
    PIDS+=($!)
    if ! wait_for_health "${HTTP_PORTS[$i]}"; then
        err "node$n failed to start"; cat "$LOG_DIR/node$n.log" || true; exit 1
    fi
done

# Wait briefly for the mesh (identify + kademlia bootstrap) to stabilize.
log "Waiting for the mesh to stabilize..."
sleep 3

# --- e2e main run (smoke) ----------------------------------------------------
# E2E_SMOKE=1 limits e2e-test.sh to "content creation 201 + immediate sync".
# This is the targeted check for the request-response DialFailure regression.
log "Running e2e-test.sh in smoke mode..."
E2E_SMOKE=1 bash "$STATE_NODE_DIR/scripts/e2e-test.sh"
RESULT=$?

if [ "$RESULT" -ne 0 ]; then
    err "e2e tests failed (exit $RESULT). Node logs:"
    for n in 1 2 3 4; do
        echo -e "${BLUE}----- node$n.log (tail) -----${NC}"
        tail -n 40 "$LOG_DIR/node$n.log" 2>/dev/null || true
    done
fi

exit "$RESULT"
