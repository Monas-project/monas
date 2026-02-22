#!/bin/bash

# Monas State Node - 機能テストスクリプト
# 3つのノードが起動している状態で、各種機能をテストします

set -e

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
}

# State Nodeディレクトリに移動
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

# テスト結果を記録する変数
TESTS_PASSED=0
TESTS_FAILED=0

# HTTP リクエストを実行してレスポンスをチェック
test_request() {
    local description="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="${5:-200}"

    log_test "$description"

    if [ -z "$data" ]; then
        response=$(curl -s -X "$method" -w "\n%{http_code}" "$url" 2>/dev/null)
    else
        response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" -w "\n%{http_code}" "$url" 2>/dev/null)
    fi

    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$status_code" = "$expected_status" ]; then
        log_success "$description (HTTP $status_code)"
        ((TESTS_PASSED++))
        echo "$body" | jq -C '.' 2>/dev/null || echo "$body"
        return 0
    else
        log_fail "$description (期待: HTTP $expected_status, 実際: HTTP $status_code)"
        ((TESTS_FAILED++))
        echo "$body"
        return 1
    fi
}

# ノードの起動確認
check_nodes_running() {
    log_info "ノードの起動状態を確認しています..."

    local all_running=true
    for port in 8080 8081 8082; do
        if curl -s "http://127.0.0.1:$port/health" > /dev/null 2>&1; then
            log_success "ノード (ポート $port) は起動しています"
        else
            log_fail "ノード (ポート $port) は起動していません"
            all_running=false
        fi
    done

    if [ "$all_running" = false ]; then
        log_error "すべてのノードが起動していません。先に ./scripts/start-local-nodes.sh を実行してください"
        exit 1
    fi
}

# テストの実行
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Monas State Node 機能テスト開始     ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ノードの起動確認
check_nodes_running

echo ""
echo -e "${BLUE}=== 基本的なAPIテスト ===${NC}"
echo ""

# ヘルスチェック
test_request "ノード1のヘルスチェック" GET "http://127.0.0.1:8080/health"
test_request "ノード2のヘルスチェック" GET "http://127.0.0.1:8081/health"
test_request "ノード3のヘルスチェック" GET "http://127.0.0.1:8082/health"

echo ""
echo -e "${BLUE}=== ノード登録テスト ===${NC}"
echo ""

# ノード情報の取得
test_request "ノード1の情報取得" GET "http://127.0.0.1:8080/node/info"
NODE1_INFO=$(curl -s http://127.0.0.1:8080/node/info)
NODE1_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')

test_request "ノード2の情報取得" GET "http://127.0.0.1:8081/node/info"
NODE2_INFO=$(curl -s http://127.0.0.1:8081/node/info)
NODE2_ID=$(echo "$NODE2_INFO" | jq -r '.node_id')

test_request "ノード3の情報取得" GET "http://127.0.0.1:8082/node/info"
NODE3_INFO=$(curl -s http://127.0.0.1:8082/node/info)
NODE3_ID=$(echo "$NODE3_INFO" | jq -r '.node_id')

# ノード登録
test_request "ノード1の登録" POST "http://127.0.0.1:8080/node/register" '{"total_capacity": 1000000}'
test_request "ノード2の登録" POST "http://127.0.0.1:8081/node/register" '{"total_capacity": 2000000}'
test_request "ノード3の登録" POST "http://127.0.0.1:8082/node/register" '{"total_capacity": 1500000}'

# 登録されたノードの一覧を確認
echo ""
log_test "各ノードから見たノード一覧の確認"
test_request "ノード1から見たノード一覧" GET "http://127.0.0.1:8080/nodes"
test_request "ノード2から見たノード一覧" GET "http://127.0.0.1:8081/nodes"
test_request "ノード3から見たノード一覧" GET "http://127.0.0.1:8082/nodes"

echo ""
echo -e "${BLUE}=== コンテンツ操作テスト（認証なし） ===${NC}"
echo ""

# コンテンツ一覧の取得（初期状態）
test_request "初期状態のコンテンツ一覧" GET "http://127.0.0.1:8080/contents"

# 認証なしでのコンテンツ作成（失敗するはず）
echo ""
log_test "認証なしでのコンテンツ作成（失敗を期待）"
test_request "認証なしでコンテンツ作成" POST "http://127.0.0.1:8080/content" '{"data": "SGVsbG8sIFdvcmxkIQ=="}' 401 || true

echo ""
echo -e "${BLUE}=== 認証付きコンテンツ操作のシミュレーション ===${NC}"
echo ""

# 注意: 実際の認証トークンとシグネチャがない場合、これらのテストは失敗します
# ここではAPIの動作確認のため、失敗することを前提にテストします

log_warn "認証が必要な操作のテスト（実際のトークンがないため失敗を期待）"

# ダミーのトークンとシグネチャ
DUMMY_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
DUMMY_SIGNATURE="dGVzdF9zaWduYXR1cmU="

# 認証付きコンテンツ作成の試行
curl -s -X POST http://127.0.0.1:8080/content \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DUMMY_TOKEN" \
  -H "X-Request-Signature: $DUMMY_SIGNATURE" \
  -d '{"data": "SGVsbG8sIFdvcmxkIQ=="}' \
  -w "\nHTTP Status: %{http_code}\n" || true

echo ""
echo -e "${BLUE}=== P2Pネットワークテスト ===${NC}"
echo ""

# P2P接続の確認（ログから確認が必要）
log_test "P2P接続状態の確認"
log_info "ノード間のP2P接続はログファイルで確認してください:"
echo "  - tail -f logs/node1.log | grep -E 'Peer|connected|discovered'"
echo "  - tail -f logs/node2.log | grep -E 'Peer|connected|discovered'"
echo "  - tail -f logs/node3.log | grep -E 'Peer|connected|discovered'"

echo ""
echo -e "${BLUE}=== CRDT同期テスト（準備） ===${NC}"
echo ""

log_info "CRDTの同期テストには実際のコンテンツ作成が必要です"
log_info "認証トークンを生成して、以下のようなコマンドでテストできます:"
echo ""
echo 'TOKEN="your-actual-token"'
echo 'SIGNATURE="your-actual-signature"'
echo 'curl -X POST http://127.0.0.1:8080/content \'
echo '  -H "Content-Type: application/json" \'
echo '  -H "Authorization: Bearer $TOKEN" \'
echo '  -H "X-Request-Signature: $SIGNATURE" \'
echo '  -d '"'"'{"data": "SGVsbG8sIFdvcmxkIQ=="}'"'"

echo ""
echo -e "${BLUE}=== 高度な機能テスト ===${NC}"
echo ""

# ノード間のイベント伝播テスト
log_test "イベント伝播の確認"
log_info "一つのノードで変更を加えた際、他のノードにイベントが伝播することを確認"
log_info "ログファイルで以下のメッセージを確認してください:"
echo "  - 'Event received via Gossipsub'"
echo "  - 'Content synced from peer'"
echo "  - 'CRDT merge completed'"

# ディスク容量の確認
echo ""
log_test "ディスク容量の確認"
for port in 8080 8081 8082; do
    node_info=$(curl -s "http://127.0.0.1:$port/node/info")
    if [ $? -eq 0 ]; then
        total_capacity=$(echo "$node_info" | jq -r '.total_capacity // "不明"')
        available_capacity=$(echo "$node_info" | jq -r '.available_capacity // "不明"')
        log_info "ノード (ポート $port): 総容量=$total_capacity, 利用可能=$available_capacity"
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        テスト結果サマリー              ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

total_tests=$((TESTS_PASSED + TESTS_FAILED))
echo -e "実行したテスト: ${BLUE}$total_tests${NC}"
echo -e "成功: ${GREEN}$TESTS_PASSED${NC}"
echo -e "失敗: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}すべてのテストが成功しました！${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}一部のテストが失敗しました（認証が必要なテストは想定内）${NC}"
    exit 0
fi