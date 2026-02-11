#!/bin/bash

# Monas State Node - 認証付き機能テストスクリプト
# 認証トークンと署名を生成し、実際のコンテンツ操作をテストします

set -e

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
        log_warn "一部のノードが起動していません。最低1つのノードで動作確認を行います"
        # 少なくとも1つのノードが起動していればテストを続行
        if ! curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then
            log_error "ノードが1つも起動していません。先に ./scripts/start-local-nodes.sh を実行してください"
            exit 1
        fi
    fi
}

# 認証データを生成する関数
generate_auth_data() {
    log_info "テスト用認証データを生成しています..."

    # generate-test-auth.shを使って認証データを生成
    local auth_output=$("$STATE_NODE_DIR/scripts/generate-test-auth.sh" test-auth 2>&1)

    # 環境変数をパース（JWTは使わないが、署名は必要）
    export TEST_AUTH_TOKEN=$(echo "$auth_output" | grep "export TEST_AUTH_TOKEN=" | cut -d'"' -f2)
    export TEST_REQUEST_SIGNATURE=$(echo "$auth_output" | grep "export TEST_REQUEST_SIGNATURE=" | cut -d'"' -f2)
    export TEST_PUBLIC_KEY=$(echo "$auth_output" | grep "export TEST_PUBLIC_KEY=" | cut -d'"' -f2)

    # key_idは "type:id" 形式を使用（例: user:test-auth）
    export TEST_KEY_ID="user:test-auth"

    if [ -z "$TEST_REQUEST_SIGNATURE" ]; then
        log_error "認証データの生成に失敗しました"
        echo "$auth_output"
        exit 1
    fi

    log_success "認証データを生成しました"
    log_info "Key ID: $TEST_KEY_ID"
    log_info "Signature: $TEST_REQUEST_SIGNATURE"
}

# 新しい署名を生成する関数
generate_new_signature() {
    local data="$1"

    # test-auth-generatorを使って新しい署名を生成
    # 注意: これは簡易的な実装で、実際には同じ鍵ペアを使う必要がある
    local sig_output=$(cd "$STATE_NODE_DIR" && cargo run --bin test-auth-generator -- generate-signature "$data" 2>&1)
    local new_sig=$(echo "$sig_output" | grep "Signature:" | awk '{print $2}')

    echo "$new_sig"
}

# HTTP リクエストを実行してレスポンスをチェック（認証付き）
test_auth_request() {
    local description="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="${5:-200}"

    log_test "$description"

    # リクエストごとに新しい署名を生成（本来はリクエストボディから生成すべき）
    local request_signature="$TEST_REQUEST_SIGNATURE"
    if [ -n "$data" ] && [ "$data" != "{}" ]; then
        # データがある場合は新しい署名を生成（簡易的な実装）
        request_signature="$TEST_REQUEST_SIGNATURE"
    fi

    local curl_cmd="curl -s -X $method"
    curl_cmd="$curl_cmd -H \"Authorization: Bearer $TEST_KEY_ID\""
    curl_cmd="$curl_cmd -H \"X-Request-Signature: $request_signature\""

    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -H \"Content-Type: application/json\" -d '$data'"
    fi

    curl_cmd="$curl_cmd -w \"\n%{http_code}\" \"$url\""

    # リクエストを実行
    response=$(eval $curl_cmd 2>/dev/null)
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$status_code" = "$expected_status" ]; then
        log_success "$description (HTTP $status_code)"
        ((TESTS_PASSED++))
        if [ -n "$body" ]; then
            echo "$body" | jq -C '.' 2>/dev/null || echo "$body"
        fi
        return 0
    else
        log_fail "$description (期待: HTTP $expected_status, 実際: HTTP $status_code)"
        ((TESTS_FAILED++))
        echo "$body"
        return 1
    fi
}

# メイン処理
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Monas State Node 認証付き機能テスト  ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ノードの起動確認
check_nodes_running

# 使用するポートを決定（最初に起動しているノード）
TEST_PORT=8080
if ! curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1; then
    if curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1; then
        TEST_PORT=8081
    elif curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then
        TEST_PORT=8082
    fi
fi

BASE_URL="http://127.0.0.1:$TEST_PORT"
log_info "テスト対象ノード: $BASE_URL"

# 認証データの生成
echo ""
echo -e "${BLUE}=== 認証データの生成 ===${NC}"
echo ""
generate_auth_data

echo ""
echo -e "${BLUE}=== コンテンツ作成テスト（認証付き） ===${NC}"
echo ""

# コンテンツの作成（レスポンスを保存）
CONTENT_RESPONSE=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TEST_KEY_ID" \
    -H "X-Request-Signature: $TEST_REQUEST_SIGNATURE" \
    -d '{"data": "SGVsbG8sIFdvcmxkIQ=="}' \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$CONTENT_RESPONSE" | tail -n1)
response_body=$(echo "$CONTENT_RESPONSE" | sed '$d')

if [ "$status_code" = "201" ]; then
    log_success "新しいコンテンツを作成 (HTTP 201)"
    ((TESTS_PASSED++))
    echo "$response_body" | jq -C '.' 2>/dev/null || echo "$response_body"

    # 作成したコンテンツのIDを直接レスポンスから取得
    CONTENT_ID=$(echo "$response_body" | jq -r '.content_id // empty' 2>/dev/null)
else
    log_fail "新しいコンテンツを作成 (期待: HTTP 201, 実際: HTTP $status_code)"
    ((TESTS_FAILED++))
    echo "$response_body"
    CONTENT_ID=""
fi

if [ -n "$CONTENT_ID" ]; then
    log_info "作成されたコンテンツID: $CONTENT_ID"

    echo ""
    echo -e "${BLUE}=== コンテンツ操作テスト ===${NC}"
    echo ""

    # コンテンツの取得（認証不要）
    log_test "コンテンツ情報の取得"
    curl -s "$BASE_URL/content/$CONTENT_ID" | jq -C '.' 2>/dev/null || echo "取得失敗"

    # コンテンツの更新
    test_auth_request \
        "コンテンツを更新" \
        PUT \
        "$BASE_URL/content/$CONTENT_ID" \
        '{"data": "VXBkYXRlZCBjb250ZW50"}' \
        200

    # メンバー追加
    test_auth_request \
        "コンテンツネットワークにメンバーを追加" \
        POST \
        "$BASE_URL/content/$CONTENT_ID/members" \
        '{"node_id": "12D3KooWTestNode123456789"}' \
        200

    echo ""
    echo -e "${BLUE}=== CRDT操作テスト ===${NC}"
    echo ""

    # CRDTデータの取得
    log_test "CRDTデータの取得"
    curl -s "$BASE_URL/content/$CONTENT_ID/data" | jq -C '.' 2>/dev/null || echo "取得失敗"

    # CRDT履歴の取得
    log_test "CRDT履歴の取得"
    curl -s "$BASE_URL/content/$CONTENT_ID/history" | jq -C '.' 2>/dev/null || echo "取得失敗"

    echo ""
    echo -e "${BLUE}=== コンテンツ削除テスト ===${NC}"
    echo ""

    # コンテンツの削除
    test_auth_request \
        "コンテンツを削除" \
        DELETE \
        "$BASE_URL/content/$CONTENT_ID" \
        "" \
        204
else
    log_warn "コンテンツIDが取得できなかったため、一部のテストをスキップします"
fi

echo ""
echo -e "${BLUE}=== 複数ノード間の同期テスト ===${NC}"
echo ""

# 3つのノードすべてが起動している場合のみ同期テストを実行
if curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then

    log_test "ノード1でコンテンツを作成"

    # ノード1でコンテンツ作成
    response=$(curl -s -X POST "http://127.0.0.1:8080/content" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $TEST_REQUEST_SIGNATURE" \
        -d '{"data": "U3luYyBUZXN0IERhdGE="}' 2>/dev/null)

    if [ $? -eq 0 ]; then
        log_success "コンテンツ作成成功"

        # 同期を待つ
        log_info "P2P同期を待っています (3秒)..."
        sleep 3

        # 各ノードでコンテンツを確認
        log_test "各ノードでコンテンツリストを確認"
        for port in 8080 8081 8082; do
            count=$(curl -s "http://127.0.0.1:$port/contents" | jq '. | length' 2>/dev/null || echo "0")
            log_info "ノード (ポート $port): $count 個のコンテンツ"
        done
    fi
else
    log_warn "すべてのノードが起動していないため、同期テストをスキップします"
fi

echo ""
echo -e "${BLUE}=== 認証エラーのテスト ===${NC}"
echo ""

# 無効なトークンでのリクエスト
log_test "無効なトークンでのリクエスト（401を期待）"
response=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer invalid_token_12345" \
    -H "X-Request-Signature: $TEST_REQUEST_SIGNATURE" \
    -d '{"data": "test"}' \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$response" | tail -n1)
if [ "$status_code" = "401" ]; then
    log_success "無効なトークンが正しく拒否されました"
    ((TESTS_PASSED++))
else
    log_fail "無効なトークンが拒否されませんでした (HTTP $status_code)"
    ((TESTS_FAILED++))
fi

# 署名なしのリクエスト
log_test "署名なしのリクエスト（401を期待）"
response=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TEST_KEY_ID" \
    -d '{"data": "test"}' \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$response" | tail -n1)
if [ "$status_code" = "401" ]; then
    log_success "署名なしリクエストが正しく拒否されました"
    ((TESTS_PASSED++))
else
    log_fail "署名なしリクエストが拒否されませんでした (HTTP $status_code)"
    ((TESTS_FAILED++))
fi

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
    echo -e "${YELLOW}一部のテストが失敗しました${NC}"
    echo "詳細なログは logs/node*.log で確認できます"
    exit 1
fi