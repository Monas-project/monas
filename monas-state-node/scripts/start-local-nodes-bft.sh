#!/bin/bash

# Monas State Node - BFT検証向け4ノード起動スクリプト
# 通常版(start-local-nodes.sh)と異なり、監視ループを持たない。
# 1ノード停止時に残りノードを継続動作させる検証に使う。

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

PID_FILE="$STATE_NODE_DIR/.local-nodes-bft.pids"
LOG_DIR="$STATE_NODE_DIR/logs-bft"

if [ "$1" = "--clean" ]; then
    log_warn "既存のデータを削除します..."
    rm -rf data/node1 data/node2 data/node3 data/node4
fi

mkdir -p data/node1 data/node2 data/node3 data/node4
mkdir -p "$LOG_DIR"
rm -f "$PID_FILE"

log_info "State Nodeバイナリをビルドしています..."
cargo build --bin state-node --release

STATE_NODE_BIN="$STATE_NODE_DIR/../target/release/state-node"
if [ ! -f "$STATE_NODE_BIN" ]; then
    log_error "State Nodeバイナリが見つかりません: $STATE_NODE_BIN"
    exit 1
fi

start_node() {
    local node_name="$1"
    local port="$2"
    local bootstrap_addr="$3"

    log_info "${node_name} を起動しています..."
    if [ -n "$bootstrap_addr" ]; then
        "$STATE_NODE_BIN" \
            --data-dir "./data/${node_name}" \
            -l "127.0.0.1:${port}" \
            -b "$bootstrap_addr" \
            --log-level info \
            > "$LOG_DIR/${node_name}.log" 2>&1 &
    else
        "$STATE_NODE_BIN" \
            --data-dir "./data/${node_name}" \
            -l "127.0.0.1:${port}" \
            --log-level info \
            > "$LOG_DIR/${node_name}.log" 2>&1 &
    fi

    local pid=$!
    echo "$pid" >> "$PID_FILE"

    for i in {1..30}; do
        if curl -s "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
            log_info "${node_name} が起動しました (pid=${pid}, port=${port})"
            return 0
        fi
        if [ "$i" -eq 30 ]; then
            log_error "${node_name} の起動に失敗しました"
            return 1
        fi
        sleep 1
    done
}

start_node "node1" "8080" ""

NODE1_INFO=$(curl -s "http://127.0.0.1:8080/node/info")
NODE1_PEER_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')
NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)

if [ -z "$NODE1_ADDR" ]; then
    NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/0.0.0.0/tcp/"))' | head -1)
    if [ -n "$NODE1_ADDR" ]; then
        NODE1_ADDR=$(echo "$NODE1_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|')
    fi
fi

if [ -z "$NODE1_PEER_ID" ] || [ -z "$NODE1_ADDR" ]; then
    log_error "node1のブートストラップ情報取得に失敗しました"
    exit 1
fi

BOOTSTRAP_ADDR="${NODE1_ADDR}/p2p/${NODE1_PEER_ID}"
log_info "ブートストラップアドレス: $BOOTSTRAP_ADDR"

start_node "node2" "8081" "$BOOTSTRAP_ADDR"
start_node "node3" "8082" "$BOOTSTRAP_ADDR"
start_node "node4" "8083" "$BOOTSTRAP_ADDR"

echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}   BFT検証向け4ノードを起動しました（監視なし） ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "ノード:"
echo "  - node1: http://127.0.0.1:8080"
echo "  - node2: http://127.0.0.1:8081"
echo "  - node3: http://127.0.0.1:8082"
echo "  - node4: http://127.0.0.1:8083"
echo ""
echo "PIDファイル: $PID_FILE"
echo "ログ: $LOG_DIR/node*.log"
echo ""
echo "停止コマンド:"
echo "  ./scripts/stop-local-nodes-bft.sh"
echo ""
echo "BFTシナリオ例:"
echo "  RUN_BFT_TEST=1 \\"
echo "  BFT_STOP_CMD='kill \$(lsof -ti tcp:8083 | awk \"NR==1\")' \\"
echo "  BFT_RESTART_CMD='../target/release/state-node --data-dir ./data/node4 -l 127.0.0.1:8083 --log-level info > ./logs-bft/node4.log 2>&1 &' \\"
echo "  ./scripts/e2e-test.sh"
