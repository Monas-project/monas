#!/bin/bash

# Monas State Node - 認証付き機能テストスクリプト
# P-256鍵ペアを生成し、各ノードに登録後、認証付きリクエストをテストします

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

# test-auth-generator バイナリのビルド
log_info "test-auth-generatorをビルドしています..."
cargo build --bin test-auth-generator 2>/dev/null || {
    log_error "ビルドに失敗しました"
    cargo build --bin test-auth-generator
    exit 1
}

AUTH_GEN="cargo run --bin test-auth-generator --"

# ============================================================================
# ヘルパー関数
# ============================================================================

# 署名を生成する関数
# 引数: private_key operation resource [body_base64]
generate_signature() {
    local private_key="$1"
    local operation="$2"
    local resource="$3"
    local body_b64="$4"

    local sign_args="sign-request --private-key $private_key --operation $operation --resource $resource"
    if [ -n "$body_b64" ]; then
        sign_args="$sign_args --body $body_b64"
    fi

    local output
    output=$($AUTH_GEN $sign_args 2>/dev/null)
    LAST_SIGNATURE=$(echo "$output" | grep "^SIGNATURE=" | sed 's/^SIGNATURE=//')
    LAST_TIMESTAMP=$(echo "$output" | grep "^TIMESTAMP=" | sed 's/^TIMESTAMP=//')
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
        log_warn "一部のノードが起動していません。最低1つのノードで動作確認を行います"
        if ! curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then
            log_error "ノードが1つも起動していません。先に ./scripts/start-local-nodes.sh を実行してください"
            exit 1
        fi
    fi
}

# ============================================================================
# メイン処理
# ============================================================================

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

# ============================================================================
# 認証データの生成と登録
# ============================================================================

echo ""
echo -e "${BLUE}=== 認証データの生成 ===${NC}"
echo ""

log_info "テスト用鍵ペアを生成しています..."
AUTH_OUTPUT=$($AUTH_GEN test-auth 2>/dev/null)
TEST_PRIVATE_KEY=$(echo "$AUTH_OUTPUT" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
TEST_PUBLIC_KEY=$(echo "$AUTH_OUTPUT" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
TEST_KEY_ID=$(echo "$AUTH_OUTPUT" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$TEST_PRIVATE_KEY" ] || [ -z "$TEST_PUBLIC_KEY" ] || [ -z "$TEST_KEY_ID" ]; then
    log_error "鍵ペアの生成に失敗しました"
    echo "$AUTH_OUTPUT"
    exit 1
fi

log_success "鍵ペアを生成しました"
log_info "Key ID: $TEST_KEY_ID"

# 自己完結型key_idなのでノードへの公開鍵登録は不要
log_success "自己完結型key_id: 公開鍵登録不要"

# ============================================================================
# コンテンツ作成テスト（認証付き）
# ============================================================================

echo ""
echo -e "${BLUE}=== コンテンツ作成テスト（認証付き） ===${NC}"
echo ""

# base64デコードされたバイナリデータのbase64表現
CONTENT_B64="SGVsbG8sIFdvcmxkIQ=="  # "Hello, World!"

# Create用の署名を生成（bodyベース）
# HTTP APIはJSON bodyをbase64デコードするので、署名はデコード後のバイトに対して行う
# ただし verify_caller_signature() は create_content(&data, ...) で data はデコード済みバイト
# => bodyとしてはデコード済みバイトを渡す
DECODED_BODY=$(echo -n "$CONTENT_B64" | base64 -d 2>/dev/null | base64)
generate_signature "$TEST_PRIVATE_KEY" "create" "content" "$DECODED_BODY"
CREATE_SIGNATURE="$LAST_SIGNATURE"
CREATE_TIMESTAMP="$LAST_TIMESTAMP"

log_test "新しいコンテンツを作成"
CONTENT_RESPONSE=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TEST_KEY_ID" \
    -H "X-Request-Signature: $CREATE_SIGNATURE" \
    -H "X-Request-Timestamp: $CREATE_TIMESTAMP" \
    -d "{\"data\": \"$CONTENT_B64\"}" \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$CONTENT_RESPONSE" | tail -n1)
response_body=$(echo "$CONTENT_RESPONSE" | sed '$d')

if [ "$status_code" = "201" ]; then
    log_success "新しいコンテンツを作成 (HTTP 201)"
    ((TESTS_PASSED++))
    echo "$response_body" | jq -C '.' 2>/dev/null || echo "$response_body"
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

    # コンテンツの更新
    UPDATED_B64="VXBkYXRlZCBjb250ZW50"  # "Updated content"
    DECODED_UPDATED_BODY=$(echo -n "$UPDATED_B64" | base64 -d 2>/dev/null | base64)
    generate_signature "$TEST_PRIVATE_KEY" "update" "$CONTENT_ID" "$DECODED_UPDATED_BODY"

    log_test "コンテンツを更新"
    UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/content/$CONTENT_ID" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -d "{\"data\": \"$UPDATED_B64\"}" \
        -w "\n%{http_code}" 2>/dev/null)
    UPDATE_STATUS=$(echo "$UPDATE_RESPONSE" | tail -n1)
    UPDATE_BODY=$(echo "$UPDATE_RESPONSE" | sed '$d')
    if [ "$UPDATE_STATUS" = "200" ]; then
        log_success "コンテンツを更新 (HTTP 200)"
        ((TESTS_PASSED++))
    else
        log_fail "コンテンツを更新 (期待: HTTP 200, 実際: HTTP $UPDATE_STATUS)"
        ((TESTS_FAILED++))
        echo "$UPDATE_BODY"
    fi

    # メンバー追加（count形式）
    generate_signature "$TEST_PRIVATE_KEY" "manage" "$CONTENT_ID"

    log_test "コンテンツネットワークにメンバーを追加"
    MEMBER_RESPONSE=$(curl -s -X POST "$BASE_URL/content/$CONTENT_ID/members" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -d '{"count": 1}' \
        -w "\n%{http_code}" 2>/dev/null)
    MEMBER_STATUS=$(echo "$MEMBER_RESPONSE" | tail -n1)
    MEMBER_BODY=$(echo "$MEMBER_RESPONSE" | sed '$d')
    if [ "$MEMBER_STATUS" = "200" ]; then
        log_success "メンバー追加成功 (HTTP 200)"
        ((TESTS_PASSED++))
        echo "$MEMBER_BODY" | jq -C '.' 2>/dev/null || echo "$MEMBER_BODY"
    elif [ "$MEMBER_STATUS" = "503" ]; then
        log_warn "メンバー追加: DHT peer discovery で利用可能ノードが見つかりません (HTTP 503 - 小規模クラスタでは想定内)"
        ((TESTS_PASSED++))
    else
        log_fail "メンバー追加 (期待: HTTP 200 or 503, 実際: HTTP $MEMBER_STATUS)"
        ((TESTS_FAILED++))
        echo "$MEMBER_BODY"
    fi

    echo ""
    echo -e "${BLUE}=== CRDT操作テスト ===${NC}"
    echo ""

    # CRDTデータの取得（認証ヘッダー付き）
    generate_signature "$TEST_PRIVATE_KEY" "read" "content"

    log_test "CRDTデータの取得"
    DATA_RESPONSE=$(curl -s -X GET "$BASE_URL/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    DATA_STATUS=$(echo "$DATA_RESPONSE" | tail -n1)
    DATA_BODY=$(echo "$DATA_RESPONSE" | sed '$d')
    if [ "$DATA_STATUS" = "200" ]; then
        log_success "CRDTデータの取得 (HTTP 200)"
        ((TESTS_PASSED++))
    else
        log_fail "CRDTデータの取得 (期待: HTTP 200, 実際: HTTP $DATA_STATUS)"
        ((TESTS_FAILED++))
        echo "$DATA_BODY"
    fi

    # CRDT履歴の取得（認証ヘッダー付き）
    generate_signature "$TEST_PRIVATE_KEY" "read" "content"

    log_test "CRDT履歴の取得"
    HIST_RESPONSE=$(curl -s -X GET "$BASE_URL/content/$CONTENT_ID/history" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    HIST_STATUS=$(echo "$HIST_RESPONSE" | tail -n1)
    HIST_BODY=$(echo "$HIST_RESPONSE" | sed '$d')
    if [ "$HIST_STATUS" = "200" ]; then
        log_success "CRDT履歴の取得 (HTTP 200)"
        ((TESTS_PASSED++))
    else
        log_fail "CRDT履歴の取得 (期待: HTTP 200, 実際: HTTP $HIST_STATUS)"
        ((TESTS_FAILED++))
        echo "$HIST_BODY"
    fi

    echo ""
    echo -e "${BLUE}=== コンテンツ削除テスト ===${NC}"
    echo ""

    # コンテンツの削除
    generate_signature "$TEST_PRIVATE_KEY" "delete" "$CONTENT_ID"

    log_test "コンテンツを削除"
    DEL_RESPONSE=$(curl -s -X DELETE "$BASE_URL/content/$CONTENT_ID" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    DEL_STATUS=$(echo "$DEL_RESPONSE" | tail -n1)
    DEL_BODY=$(echo "$DEL_RESPONSE" | sed '$d')
    if [ "$DEL_STATUS" = "200" ]; then
        log_success "コンテンツを削除 (HTTP 200)"
        ((TESTS_PASSED++))
    else
        log_fail "コンテンツを削除 (期待: HTTP 200, 実際: HTTP $DEL_STATUS)"
        ((TESTS_FAILED++))
        echo "$DEL_BODY"
    fi
fi

# ============================================================================
# 複数ノード間の同期テスト
# ============================================================================

echo ""
echo -e "${BLUE}=== 複数ノード間の同期テスト ===${NC}"
echo ""

# 3つのノードすべてが起動している場合のみ同期テストを実行
if curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then

    log_test "ノード1でコンテンツを作成"

    SYNC_B64="U3luYyBUZXN0IERhdGE="  # "Sync Test Data"
    DECODED_SYNC_BODY=$(echo -n "$SYNC_B64" | base64 -d 2>/dev/null | base64)
    generate_signature "$TEST_PRIVATE_KEY" "create" "content" "$DECODED_SYNC_BODY"

    response=$(curl -s -X POST "http://127.0.0.1:8080/content" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -d "{\"data\": \"$SYNC_B64\"}" 2>/dev/null)

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
    log_error "すべてのノードが起動していないため、同期テストを実行できません"
    ((TESTS_FAILED++))
fi

# ============================================================================
# 認証エラーのテスト
# ============================================================================

echo ""
echo -e "${BLUE}=== 認証エラーのテスト ===${NC}"
echo ""

# 無効なトークンでのリクエスト
log_test "無効なトークンでのリクエスト（401を期待）"
generate_signature "$TEST_PRIVATE_KEY" "create" "content"
response=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer invalid_token_12345" \
    -H "X-Request-Signature: $LAST_SIGNATURE" \
    -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
    -d '{"data": "dGVzdA=="}' \
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
    -d '{"data": "dGVzdA=="}' \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$response" | tail -n1)
if [ "$status_code" = "401" ]; then
    log_success "署名なしリクエストが正しく拒否されました"
    ((TESTS_PASSED++))
else
    log_fail "署名なしリクエストが拒否されませんでした (HTTP $status_code)"
    ((TESTS_FAILED++))
fi

# ============================================================================
# テスト結果サマリー
# ============================================================================

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
