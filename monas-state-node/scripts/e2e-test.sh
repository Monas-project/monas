#!/bin/bash

# Monas State Node - E2E テストスクリプト
# シナリオ: content作成 → update(リレー) → 同期確認 → 権限付与 → account2による更新
#
# 前提条件:
#   ./scripts/start-local-nodes.sh --clean でノードを起動済み

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

log_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}  ✓${NC} $1"
}

log_fail() {
    echo -e "${RED}  ✗${NC} $1"
}

# State Nodeディレクトリに移動
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

# テスト結果を記録する変数
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# ヘルパー関数
# ============================================================================

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
        log_error "すべてのノードが起動していません。先に ./scripts/start-local-nodes.sh --clean を実行してください"
        exit 1
    fi
}

# 認証付きHTTPリクエストを実行してレスポンスをチェック
# 引数: description method url data expected_status key_id signature
# data が空の場合は "" を渡す
test_auth_request() {
    local description="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="${5:-200}"
    local key_id="${6:-$ACCOUNT1_KEY_ID}"
    local signature="${7:-$ACCOUNT1_SIGNATURE}"

    log_test "$description"

    local response
    if [ -z "$data" ]; then
        response=$(curl -s -X "$method" \
            -H "Authorization: Bearer $key_id" \
            -H "X-Request-Signature: $signature" \
            -w "\n%{http_code}" "$url" 2>/dev/null)
    else
        response=$(curl -s -X "$method" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $key_id" \
            -H "X-Request-Signature: $signature" \
            -d "$data" \
            -w "\n%{http_code}" "$url" 2>/dev/null)
    fi

    LAST_STATUS=$(echo "$response" | tail -n1)
    LAST_BODY=$(echo "$response" | sed '$d')

    if [ "$LAST_STATUS" = "$expected_status" ]; then
        log_success "$description (HTTP $LAST_STATUS)"
        ((TESTS_PASSED++))
        return 0
    else
        log_fail "$description (期待: HTTP $expected_status, 実際: HTTP $LAST_STATUS)"
        echo "    Response: $LAST_BODY"
        ((TESTS_FAILED++))
        return 1
    fi
}

# ノード登録
register_nodes() {
    log_info "ノード登録を行います..."
    for port in 8080 8081 8082; do
        curl -s -X POST "http://127.0.0.1:$port/node/register" \
            -H "Content-Type: application/json" \
            -d '{"total_capacity": 10000000}' > /dev/null 2>&1 || true
    done
    # ノード登録の伝播を待つ
    sleep 2
    log_success "ノード登録完了"
}

# ============================================================================
# メイン処理
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Monas State Node E2E テスト          ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ノード起動確認
check_nodes_running

# ノード登録
register_nodes

# ============================================================================
# 認証データの準備
# ============================================================================

echo ""
echo -e "${BLUE}=== 認証データの準備 ===${NC}"
echo ""

# account1の認証データ生成
log_info "account1の認証データを生成しています..."
ACCOUNT1_AUTH_OUTPUT=$("$STATE_NODE_DIR/scripts/generate-test-auth.sh" test-auth 2>&1)
ACCOUNT1_SIGNATURE=$(echo "$ACCOUNT1_AUTH_OUTPUT" | grep "export TEST_REQUEST_SIGNATURE=" | cut -d'"' -f2)
ACCOUNT1_KEY_ID="user:account1"

if [ -z "$ACCOUNT1_SIGNATURE" ]; then
    log_error "account1の認証データ生成に失敗しました"
    echo "$ACCOUNT1_AUTH_OUTPUT"
    exit 1
fi
log_success "account1: key_id=$ACCOUNT1_KEY_ID"

# account2の認証データ生成
log_info "account2の認証データを生成しています..."
ACCOUNT2_AUTH_OUTPUT=$("$STATE_NODE_DIR/scripts/generate-test-auth.sh" test-auth 2>&1)
ACCOUNT2_SIGNATURE=$(echo "$ACCOUNT2_AUTH_OUTPUT" | grep "export TEST_REQUEST_SIGNATURE=" | cut -d'"' -f2)
ACCOUNT2_KEY_ID="user:account2"

if [ -z "$ACCOUNT2_SIGNATURE" ]; then
    log_error "account2の認証データ生成に失敗しました"
    echo "$ACCOUNT2_AUTH_OUTPUT"
    exit 1
fi
log_success "account2: key_id=$ACCOUNT2_KEY_ID"

# ============================================================================
# Step 1-2: Content作成
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 1-2: Content作成 ===${NC}"
echo ""

CONTENT_DATA=$(echo -n "Hello, Monas E2E Test!" | base64)
log_step "account1 が node A (8080) に POST /content を送信"

test_auth_request \
    "account1がコンテンツを作成" \
    POST \
    "http://127.0.0.1:8080/content" \
    "{\"data\": \"$CONTENT_DATA\"}" \
    201 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_SIGNATURE"

CONTENT_ID=$(echo "$LAST_BODY" | jq -r '.content_id // empty' 2>/dev/null)

if [ -z "$CONTENT_ID" ]; then
    log_error "コンテンツIDの取得に失敗しました。テストを中止します。"
    echo "Response: $LAST_BODY"
    exit 1
fi

log_info "作成されたコンテンツID: $CONTENT_ID"

# content_networkの形成を確認（各ノードでcontentsリストを確認）
sleep 2
log_step "content_networkの形成を確認"
for port in 8080 8081 8082; do
    count=$(curl -s "http://127.0.0.1:$port/contents" | jq '. | length' 2>/dev/null || echo "0")
    log_info "  ノード (ポート $port): $count 個のコンテンツを認識"
done

# ============================================================================
# エラーケース: 権限のないaccount2がgrant前に更新試行
# ============================================================================

echo ""
echo -e "${BLUE}=== エラーケース: 未認可ユーザーの更新試行 ===${NC}"
echo ""

UPDATED_DATA_UNAUTHORIZED=$(echo -n "Unauthorized update attempt" | base64)
log_step "account2がgrant前にコンテンツを更新試行（403を期待）"

test_auth_request \
    "account2が権限なしで更新試行 -> 403" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$UPDATED_DATA_UNAUTHORIZED\"}" \
    403 \
    "$ACCOUNT2_KEY_ID" \
    "$ACCOUNT2_SIGNATURE"

# ============================================================================
# エラーケース: 無効なトークンでの更新試行
# ============================================================================

echo ""
echo -e "${BLUE}=== エラーケース: 無効なトークンでの更新 ===${NC}"
echo ""

log_step "無効なトークンでコンテンツを更新試行（401を期待）"

test_auth_request \
    "無効なトークンでの更新試行 -> 401" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$UPDATED_DATA_UNAUTHORIZED\"}" \
    401 \
    "invalid:token:format" \
    "$ACCOUNT1_SIGNATURE"

# ============================================================================
# Step 3-5: Content更新（リレー）
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 3-5: Content更新（リレー） ===${NC}"
echo ""

UPDATED_DATA=$(echo -n "Updated content via relay!" | base64)
log_step "account1 が node A (8080) に PUT /content/:id を送信"
log_info "node Aはmemberではない場合リレーが発生します"

test_auth_request \
    "account1がコンテンツを更新（リレー可能性あり）" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$UPDATED_DATA\"}" \
    200 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_SIGNATURE"

# ============================================================================
# Step 6: 同期確認
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 6: 同期確認 ===${NC}"
echo ""

log_step "gossipsubによる伝播を待機 (5秒)..."
sleep 5

log_step "各ノードでcontentデータを取得し、更新が反映されていることを確認"
SYNC_OK=true
for port in 8080 8081 8082; do
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" 2>/dev/null)
    DATA_STATUS=$?

    if [ $DATA_STATUS -eq 0 ] && echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        DECODED=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null || echo "(decode failed)")
        log_info "  ノード (ポート $port): data=$DECODED"
    else
        log_info "  ノード (ポート $port): データ取得不可（memberでない可能性）"
    fi
done

# memberノードでデータを検証
log_test "少なくとも1つのノードで更新データが取得できること"
VERIFIED=false
for port in 8080 8081 8082; do
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" 2>/dev/null)
    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        if [ -n "$FETCHED_DATA" ] && [ "$FETCHED_DATA" != "null" ]; then
            VERIFIED=true
            break
        fi
    fi
done

if [ "$VERIFIED" = true ]; then
    log_success "同期確認: データが取得可能"
    ((TESTS_PASSED++))
else
    log_fail "同期確認: どのノードからもデータが取得できませんでした"
    ((TESTS_FAILED++))
fi

# ============================================================================
# Step 7-8: 権限付与
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 7-8: 権限付与 (grant_access) ===${NC}"
echo ""

log_step "account1 が node A に POST /content/:id/access/grant を送信"
log_info "grantee: user:account2, capabilities: editor_capabilities"

test_auth_request \
    "account1がaccount2にeditor権限を付与" \
    POST \
    "http://127.0.0.1:8080/content/$CONTENT_ID/access/grant" \
    "{\"grantee_id\": \"user:account2\", \"capabilities\": [\"ReadContent\", \"WriteContent\", \"ReadMetadata\"]}" \
    200 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_SIGNATURE"

if [ "$LAST_STATUS" = "200" ]; then
    log_info "grant_accessレスポンス:"
    echo "$LAST_BODY" | jq -C '.' 2>/dev/null || echo "    $LAST_BODY"
fi

# ============================================================================
# Step 9: account2による更新
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 9: account2による更新 ===${NC}"
echo ""

ACCOUNT2_DATA=$(echo -n "Content updated by account2!" | base64)
log_step "account2 が任意のノードに PUT /content/:id を送信"

test_auth_request \
    "account2が権限付与後にコンテンツを更新" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$ACCOUNT2_DATA\"}" \
    200 \
    "$ACCOUNT2_KEY_ID" \
    "$ACCOUNT2_SIGNATURE"

# 更新データの確認
if [ "$LAST_STATUS" = "200" ]; then
    sleep 2
    log_test "account2の更新データが反映されていることを確認"

    VERIFIED_UPDATE=false
    for port in 8080 8081 8082; do
        DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" 2>/dev/null)
        if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
            FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
            DECODED=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null || echo "(decode failed)")
            if [ "$DECODED" = "Content updated by account2!" ]; then
                VERIFIED_UPDATE=true
                log_success "account2の更新データを確認: '$DECODED' (ポート $port)"
                ((TESTS_PASSED++))
                break
            fi
        fi
    done

    if [ "$VERIFIED_UPDATE" = false ]; then
        log_fail "account2の更新データが確認できませんでした"
        ((TESTS_FAILED++))
    fi
fi

# ============================================================================
# テスト結果サマリー
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        E2E テスト結果サマリー          ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

total_tests=$((TESTS_PASSED + TESTS_FAILED))
echo -e "実行したテスト: ${BLUE}$total_tests${NC}"
echo -e "成功: ${GREEN}$TESTS_PASSED${NC}"
echo -e "失敗: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}すべてのE2Eテストが成功しました！${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}一部のテストが失敗しました${NC}"
    echo "詳細なログは logs/node*.log で確認できます"
    exit 1
fi
