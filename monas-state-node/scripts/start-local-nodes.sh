#!/bin/bash

# Monas State Node - 4-node startup script
# This script starts four State Nodes and builds a P2P network
#
# Why 4 nodes: create_content intentionally excludes the creator node itself from
# the members (it holds no local CRDT copy either), so meeting the member quorum
# of MIN_REPLICATION_FACTOR=3 requires creator + 3 members = at least 4 nodes.
# Also, since the creator is always a non-member, reads via the creator reliably
# go through the relay read path (#54/#55). e2e always runs on this 4-node setup.

set -e

# Color output definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Move to the State Node directory
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

log_info "State Node directory: $STATE_NODE_DIR"

# Clean up data directories (optional)
if [ "$1" == "--clean" ]; then
    log_warn "Deleting existing data..."
    rm -rf data/node1 data/node2 data/node3 data/node4
fi

# Create data directories
mkdir -p data/node1 data/node2 data/node3 data/node4

# File that stores the PIDs
PID_FILE="$STATE_NODE_DIR/.local-nodes.pids"
rm -f "$PID_FILE"

# Create the log directory
LOG_DIR="$STATE_NODE_DIR/logs"
mkdir -p "$LOG_DIR"

# Trap Ctrl+C
cleanup() {
    log_warn "\nReceived termination signal. Stopping nodes..."
    if [ -f "$PID_FILE" ]; then
        while IFS= read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                log_info "Stopping PID $pid..."
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    log_info "Cleanup complete"
    exit 0
}

trap cleanup INT TERM

# Quorum of creator + 3 members (see the comment above). Set the default 3 explicitly.
export MIN_REPLICATION_FACTOR="${MIN_REPLICATION_FACTOR:-3}"

# Build the State Node binary
log_info "Building the State Node binary..."
cargo build --bin state-node --release

# Check the binary path
STATE_NODE_BIN="$STATE_NODE_DIR/../target/release/state-node"
if [ ! -f "$STATE_NODE_BIN" ]; then
    log_error "State Node binary not found: $STATE_NODE_BIN"
    exit 1
fi

# Start node 1 (bootstrap node)
log_info "Starting node 1 (bootstrap node)..."
# The state-node defaults to a fixed P2P port (9090); give each node on this
# host a distinct --p2p-port to avoid a bind collision.
"$STATE_NODE_BIN" \
    --data-dir ./data/node1 \
    -l 127.0.0.1:8080 \
    --p2p-port 9091 \
    --log-level info \
    > "$LOG_DIR/node1.log" 2>&1 &
NODE1_PID=$!
echo "$NODE1_PID" >> "$PID_FILE"

# Wait for node 1 to start
log_info "Waiting for node 1 to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/health > /dev/null 2>&1; then
        log_info "Node 1 started"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Node 1 failed to start"
        cleanup
        exit 1
    fi
    sleep 1
done

# Get node 1's Peer ID and listen address
log_info "Getting node 1's Peer ID and listen address..."
NODE1_INFO=$(curl -s http://127.0.0.1:8080/node/info)
NODE1_PEER_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')
NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)

if [ -z "$NODE1_PEER_ID" ]; then
    log_error "Could not get node 1's Peer ID"
    cleanup
    exit 1
fi

if [ -z "$NODE1_ADDR" ]; then
    # If there is no 127.0.0.1 address, use the 0.0.0.0 one
    NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/0.0.0.0/tcp/"))' | head -1)
    if [ -n "$NODE1_ADDR" ]; then
        # Replace 0.0.0.0 with 127.0.0.1
        NODE1_ADDR=$(echo "$NODE1_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|')
    fi
fi

if [ -z "$NODE1_ADDR" ]; then
    log_error "Could not get node 1's listen address"
    cleanup
    exit 1
fi

BOOTSTRAP_ADDR="${NODE1_ADDR}/p2p/${NODE1_PEER_ID}"
log_info "Node 1 Peer ID: $NODE1_PEER_ID"
log_info "Bootstrap address: $BOOTSTRAP_ADDR"

# Start node 2 (connects to node 1)
log_info "Starting node 2..."
"$STATE_NODE_BIN" \
    --data-dir ./data/node2 \
    -l 127.0.0.1:8081 \
    --p2p-port 9092 \
    -b "$BOOTSTRAP_ADDR" \
    --log-level info \
    > "$LOG_DIR/node2.log" 2>&1 &
NODE2_PID=$!
echo "$NODE2_PID" >> "$PID_FILE"

# Wait for node 2 to start
log_info "Waiting for node 2 to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8081/health > /dev/null 2>&1; then
        log_info "Node 2 started"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Node 2 failed to start"
        cleanup
        exit 1
    fi
    sleep 1
done

# Start node 3 (connects to node 1)
log_info "Starting node 3..."
"$STATE_NODE_BIN" \
    --data-dir ./data/node3 \
    -l 127.0.0.1:8082 \
    --p2p-port 9093 \
    -b "$BOOTSTRAP_ADDR" \
    --log-level info \
    > "$LOG_DIR/node3.log" 2>&1 &
NODE3_PID=$!
echo "$NODE3_PID" >> "$PID_FILE"

# Wait for node 3 to start
log_info "Waiting for node 3 to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8082/health > /dev/null 2>&1; then
        log_info "Node 3 started"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Node 3 failed to start"
        cleanup
        exit 1
    fi
    sleep 1
done

# Start node 4 (connects to node 1)
log_info "Starting node 4..."
"$STATE_NODE_BIN" \
    --data-dir ./data/node4 \
    -l 127.0.0.1:8083 \
    --p2p-port 9094 \
    -b "$BOOTSTRAP_ADDR" \
    --log-level info \
    > "$LOG_DIR/node4.log" 2>&1 &
NODE4_PID=$!
echo "$NODE4_PID" >> "$PID_FILE"

# Wait for node 4 to start
log_info "Waiting for node 4 to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8083/health > /dev/null 2>&1; then
        log_info "Node 4 started"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Node 4 failed to start"
        cleanup
        exit 1
    fi
    sleep 1
done

# Wait for P2P connections to be established
log_info "Waiting for P2P connections to be established..."
sleep 3

# Show status
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}      4 State Nodes are running!        ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Node 1: http://127.0.0.1:8080"
echo "Node 2: http://127.0.0.1:8081"
echo "Node 3: http://127.0.0.1:8082"
echo "Node 4: http://127.0.0.1:8083 (the node that receives a create does not become a member; it acts as relay)"
echo ""
echo "Log files:"
echo "  - $LOG_DIR/node1.log"
echo "  - $LOG_DIR/node2.log"
echo "  - $LOG_DIR/node3.log"
echo "  - $LOG_DIR/node4.log"
echo ""
echo "Follow the logs in real time:"
echo "  tail -f $LOG_DIR/node1.log"
echo ""
echo "Run the functional tests:"
echo "  ./scripts/test-local-nodes.sh"
echo ""
echo "Press Ctrl+C to stop the nodes"
echo ""

# Follow the logs (optional)
if [ "$2" == "--follow" ]; then
    log_info "Following the logs..."
    tail -f "$LOG_DIR"/node*.log
else
    # Keep running in the background
    while true; do
        sleep 1
        # Check that the PIDs are still alive
        if ! kill -0 "$NODE1_PID" 2>/dev/null || \
           ! kill -0 "$NODE2_PID" 2>/dev/null || \
           ! kill -0 "$NODE3_PID" 2>/dev/null || \
           ! kill -0 "$NODE4_PID" 2>/dev/null; then
            log_error "One of the nodes has stopped"
            cleanup
            exit 1
        fi
    done
fi