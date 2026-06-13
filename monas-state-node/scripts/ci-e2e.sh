#!/bin/bash

# Monas State Node - CI E2E ランナー
#
# 4 つの state-node を相互接続したメッシュとして起動し(creator + 3 members,
# MIN_REPLICATION_FACTOR=3)、e2e-test.sh を実行する。終了時には成功・失敗に
# かかわらず必ずノードを停止する。CI の e2e ジョブと、ローカルでの再現確認の
# 両方から呼べるよう自己完結している。
#
# このスクリプトが 4 ノードを要求する理由: create_content は creator 自身を
# 除いて MIN_REPLICATION_FACTOR(=3) 個のメンバーを必要とするため、最低 4 ノード
# ないとメンバー定足数を満たせず NoAvailableMembers になる。
#
# 終了コード: e2e-test.sh の結果をそのまま返す(全テスト成功で 0)。

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

# HTTP ポートと、それぞれに割り当てる P2P ポート(固定デフォルト 9090 との衝突を
# 避けるため明示的に別ポートを与える)。
HTTP_PORTS=(8080 8081 8082 8083)
P2P_PORTS=(9091 9092 9093 9094)

cleanup() {
    log "ノードを停止しています..."
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

# --- ビルド -----------------------------------------------------------------
log "state-node をビルドしています..."
if ! cargo build --bin state-node; then
    err "state-node のビルドに失敗しました"
    exit 1
fi

# --- クリーンなデータディレクトリ -------------------------------------------
rm -rf data/node1 data/node2 data/node3 data/node4
mkdir -p data/node1 data/node2 data/node3 data/node4

# --- bootstrap ノード(node1)-------------------------------------------------
log "node1 (bootstrap) を :${HTTP_PORTS[0]} / p2p :${P2P_PORTS[0]} で起動..."
"$BIN" --data-dir ./data/node1 -l "127.0.0.1:${HTTP_PORTS[0]}" \
    --p2p-port "${P2P_PORTS[0]}" --log-level info > "$LOG_DIR/node1.log" 2>&1 &
PIDS+=($!)

if ! wait_for_health "${HTTP_PORTS[0]}"; then
    err "node1 が起動しませんでした"; cat "$LOG_DIR/node1.log" || true; exit 1
fi

NODE1_INFO=$(curl -s "http://127.0.0.1:${HTTP_PORTS[0]}/node/info")
NODE1_PEER_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')
NODE1_ADDR=$(echo "$NODE1_INFO" | jq -r '.listen_addrs[] | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)
if [ -z "$NODE1_PEER_ID" ] || [ "$NODE1_PEER_ID" = "null" ] || [ -z "$NODE1_ADDR" ]; then
    err "node1 の peer id / listen アドレスを取得できませんでした"; echo "$NODE1_INFO"; exit 1
fi
BOOTSTRAP="${NODE1_ADDR}/p2p/${NODE1_PEER_ID}"
log "bootstrap = $BOOTSTRAP"

# --- member ノード(node2..node4)--------------------------------------------
for i in 1 2 3; do
    n=$((i + 1))
    log "node$n を :${HTTP_PORTS[$i]} / p2p :${P2P_PORTS[$i]} で起動 (-> bootstrap)..."
    "$BIN" --data-dir "./data/node$n" -l "127.0.0.1:${HTTP_PORTS[$i]}" \
        --p2p-port "${P2P_PORTS[$i]}" -b "$BOOTSTRAP" --log-level info \
        > "$LOG_DIR/node$n.log" 2>&1 &
    PIDS+=($!)
    if ! wait_for_health "${HTTP_PORTS[$i]}"; then
        err "node$n が起動しませんでした"; cat "$LOG_DIR/node$n.log" || true; exit 1
    fi
done

# メッシュ(identify + kademlia bootstrap)が安定するまで少し待つ。
log "メッシュの安定化を待機しています..."
sleep 3

# --- e2e 本体(スモーク) ----------------------------------------------------
# E2E_SMOKE=1 で e2e-test.sh を「content 作成 201 + 即時同期」までに限定して
# 実行する。これが request-response DialFailure 回帰のピンポイント検証。
log "e2e-test.sh をスモークモードで実行します..."
E2E_SMOKE=1 bash "$STATE_NODE_DIR/scripts/e2e-test.sh"
RESULT=$?

if [ "$RESULT" -ne 0 ]; then
    err "e2e テストが失敗しました (exit $RESULT)。ノードログ:"
    for n in 1 2 3 4; do
        echo -e "${BLUE}----- node$n.log (tail) -----${NC}"
        tail -n 40 "$LOG_DIR/node$n.log" 2>/dev/null || true
    done
fi

exit "$RESULT"
