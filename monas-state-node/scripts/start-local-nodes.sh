#!/bin/bash

# Monas State Node - 3ノード起動スクリプト
# このスクリプトは3つのState Nodeを起動し、P2Pネットワークを構築します

set -e

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ログ関数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# State Nodeディレクトリに移動
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

log_info "State Nodeディレクトリ: $STATE_NODE_DIR"

# データディレクトリのクリーンアップ（オプション）
if [ "$1" == "--clean" ]; then
    log_warn "既存のデータを削除します..."
    rm -rf data/node1 data/node2 data/node3
fi

# データディレクトリの作成
mkdir -p data/node1 data/node2 data/node3

# PIDを保存するファイル
PID_FILE="$STATE_NODE_DIR/.local-nodes.pids"
rm -f "$PID_FILE"

# ログディレクトリの作成
LOG_DIR="$STATE_NODE_DIR/logs"
mkdir -p "$LOG_DIR"

# Ctrl+C のトラップ設定
cleanup() {
    log_warn "\n終了シグナルを受信しました。ノードを停止します..."
    if [ -f "$PID_FILE" ]; then
        while IFS= read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                log_info "PID $pid を停止します..."
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    log_info "クリーンアップ完了"
    exit 0
}

trap cleanup INT TERM

# State Nodeバイナリのビルド
log_info "State Nodeバイナリをビルドしています..."
cargo build --bin state-node --release

# バイナリパスの確認
STATE_NODE_BIN="$STATE_NODE_DIR/../target/release/state-node"
if [ ! -f "$STATE_NODE_BIN" ]; then
    log_error "State Nodeバイナリが見つかりません: $STATE_NODE_BIN"
    exit 1
fi

# ノード1（ブートストラップノード）の起動
log_info "ノード1（ブートストラップノード）を起動しています..."
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

# ノード1の起動を待つ
log_info "ノード1の起動を待っています..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/health > /dev/null 2>&1; then
        log_info "ノード1が起動しました"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "ノード1の起動に失敗しました"
        cleanup
        exit 1
    fi
    sleep 1
done

# ノード1のPeer IDとlistenアドレスを取得
log_info "ノード1のPeer IDとlistenアドレスを取得しています..."
NODE1_INFO=$(curl -s http://127.0.0.1:8080/node/info)
NODE1_PEER_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')
NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)

if [ -z "$NODE1_PEER_ID" ]; then
    log_error "ノード1のPeer IDが取得できませんでした"
    cleanup
    exit 1
fi

if [ -z "$NODE1_ADDR" ]; then
    # 127.0.0.1がない場合は0.0.0.0のアドレスを使う
    NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/0.0.0.0/tcp/"))' | head -1)
    if [ -n "$NODE1_ADDR" ]; then
        # 0.0.0.0を127.0.0.1に置換
        NODE1_ADDR=$(echo "$NODE1_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|')
    fi
fi

if [ -z "$NODE1_ADDR" ]; then
    log_error "ノード1のlistenアドレスが取得できませんでした"
    cleanup
    exit 1
fi

BOOTSTRAP_ADDR="${NODE1_ADDR}/p2p/${NODE1_PEER_ID}"
log_info "ノード1のPeer ID: $NODE1_PEER_ID"
log_info "ブートストラップアドレス: $BOOTSTRAP_ADDR"

# ノード2の起動（ノード1に接続）
log_info "ノード2を起動しています..."
"$STATE_NODE_BIN" \
    --data-dir ./data/node2 \
    -l 127.0.0.1:8081 \
    --p2p-port 9092 \
    -b "$BOOTSTRAP_ADDR" \
    --log-level info \
    > "$LOG_DIR/node2.log" 2>&1 &
NODE2_PID=$!
echo "$NODE2_PID" >> "$PID_FILE"

# ノード2の起動を待つ
log_info "ノード2の起動を待っています..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8081/health > /dev/null 2>&1; then
        log_info "ノード2が起動しました"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "ノード2の起動に失敗しました"
        cleanup
        exit 1
    fi
    sleep 1
done

# ノード3の起動（ノード1に接続）
log_info "ノード3を起動しています..."
"$STATE_NODE_BIN" \
    --data-dir ./data/node3 \
    -l 127.0.0.1:8082 \
    --p2p-port 9093 \
    -b "$BOOTSTRAP_ADDR" \
    --log-level info \
    > "$LOG_DIR/node3.log" 2>&1 &
NODE3_PID=$!
echo "$NODE3_PID" >> "$PID_FILE"

# ノード3の起動を待つ
log_info "ノード3の起動を待っています..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8082/health > /dev/null 2>&1; then
        log_info "ノード3が起動しました"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "ノード3の起動に失敗しました"
        cleanup
        exit 1
    fi
    sleep 1
done

# P2P接続が確立されるのを待つ
log_info "P2P接続が確立されるのを待っています..."
sleep 3

# ステータスの表示
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    3つのState Nodeが起動しました！    ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "ノード1: http://127.0.0.1:8080"
echo "ノード2: http://127.0.0.1:8081"
echo "ノード3: http://127.0.0.1:8082"
echo ""
echo "ログファイル:"
echo "  - $LOG_DIR/node1.log"
echo "  - $LOG_DIR/node2.log"
echo "  - $LOG_DIR/node3.log"
echo ""
echo "ログをリアルタイムで確認:"
echo "  tail -f $LOG_DIR/node1.log"
echo ""
echo "機能テストを実行:"
echo "  ./scripts/test-local-nodes.sh"
echo ""
echo "ノードを停止するには Ctrl+C を押してください"
echo ""

# ログの監視（オプション）
if [ "$2" == "--follow" ]; then
    log_info "ログの監視を開始します..."
    tail -f "$LOG_DIR"/node*.log
else
    # バックグラウンドで実行を継続
    while true; do
        sleep 1
        # PIDが生きているかチェック
        if ! kill -0 "$NODE1_PID" 2>/dev/null || \
           ! kill -0 "$NODE2_PID" 2>/dev/null || \
           ! kill -0 "$NODE3_PID" 2>/dev/null; then
            log_error "いずれかのノードが停止しました"
            cleanup
            exit 1
        fi
    done
fi