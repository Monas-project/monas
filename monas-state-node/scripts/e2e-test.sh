#!/bin/bash

# Monas State Node - E2E テストスクリプト
# シナリオ: content作成 → update(リレー) → 同期確認 → トークン無効化
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
NODE_PORTS=(8080 8081 8082 8083)

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
    for port in "${NODE_PORTS[@]}"; do
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
# 引数: description method url data expected_status key_id private_key [body_for_sign]
# data が空の場合は "" を渡す
test_auth_request() {
    local description="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_status="${5:-200}"
    local key_id="$6"
    local private_key="$7"
    local operation="$8"
    local resource="$9"
    local body_for_sign="${10}"

    log_test "$description"

    # 署名を生成
    generate_signature "$private_key" "$operation" "$resource" "$body_for_sign"

    local response
    if [ -z "$data" ]; then
        response=$(curl -s -X "$method" \
            -H "Authorization: Bearer $key_id" \
            -H "X-Request-Signature: $LAST_SIGNATURE" \
            -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
            -w "\n%{http_code}" "$url" 2>/dev/null)
    else
        response=$(curl -s -X "$method" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $key_id" \
            -H "X-Request-Signature: $LAST_SIGNATURE" \
            -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
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
    for port in "${NODE_PORTS[@]}"; do
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

# account1の鍵ペア生成（自己完結型key_id: 公開鍵がkey_idに埋め込まれる）
log_info "account1の認証データを生成しています..."
ACCOUNT1_AUTH=$($AUTH_GEN test-auth 2>/dev/null)
ACCOUNT1_PRIVATE_KEY=$(echo "$ACCOUNT1_AUTH" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
ACCOUNT1_PUBLIC_KEY=$(echo "$ACCOUNT1_AUTH" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
ACCOUNT1_KEY_ID=$(echo "$ACCOUNT1_AUTH" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$ACCOUNT1_PRIVATE_KEY" ] || [ -z "$ACCOUNT1_PUBLIC_KEY" ] || [ -z "$ACCOUNT1_KEY_ID" ]; then
    log_error "account1の認証データ生成に失敗しました"
    exit 1
fi

# 自己完結型key_idなのでノードへの公開鍵登録は不要
log_success "account1: key_id=$ACCOUNT1_KEY_ID"

# account2の鍵ペア生成
log_info "account2の認証データを生成しています..."
ACCOUNT2_AUTH=$($AUTH_GEN test-auth 2>/dev/null)
ACCOUNT2_PRIVATE_KEY=$(echo "$ACCOUNT2_AUTH" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
ACCOUNT2_PUBLIC_KEY=$(echo "$ACCOUNT2_AUTH" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
ACCOUNT2_KEY_ID=$(echo "$ACCOUNT2_AUTH" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$ACCOUNT2_PRIVATE_KEY" ] || [ -z "$ACCOUNT2_PUBLIC_KEY" ] || [ -z "$ACCOUNT2_KEY_ID" ]; then
    log_error "account2の認証データ生成に失敗しました"
    exit 1
fi

# 自己完結型key_idなのでノードへの公開鍵登録は不要
log_success "account2: key_id=$ACCOUNT2_KEY_ID"

# ============================================================================
# Step 1-2: Content作成
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 1-2: Content作成 ===${NC}"
echo ""

CONTENT_DATA=$(echo -n "Hello, Monas E2E Test!" | base64)
DECODED_BODY=$(echo -n "$CONTENT_DATA" | base64 -d 2>/dev/null | base64)
log_step "account1 が node A (8080) に POST /content を送信"

test_auth_request \
    "account1がコンテンツを作成" \
    POST \
    "http://127.0.0.1:8080/content" \
    "{\"data\": \"$CONTENT_DATA\"}" \
    201 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_PRIVATE_KEY" \
    "create" \
    "content" \
    "$DECODED_BODY"

CONTENT_ID=$(echo "$LAST_BODY" | jq -r '.content_id // empty' 2>/dev/null)

if [ -z "$CONTENT_ID" ]; then
    log_error "コンテンツIDの取得に失敗しました。テストを中止します。"
    echo "Response: $LAST_BODY"
    exit 1
fi

log_info "作成されたコンテンツID: $CONTENT_ID"

# ============================================================================
# Step 2.5: create直後の即時read検証 (push-before-announce race の回帰テスト)
# ----------------------------------------------------------------------------
# gossipsub settle に依存せず、create_content から戻った直後に member ノードが
# CRDT データを保持していることを確認する。push_operations が bootstrap 付きで
# member に同期配信される必要がある。sleep は TCP/swarm がレスポンスを
# 受け取るのに必要な最小限 (200ms) のみ。
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 2.5: 作成直後の即時同期検証 ===${NC}"
echo ""
sleep 0.2
log_step "全ノードから content データを即座に取得できるか確認"

IMMEDIATE_MEMBERS=0
for port in "${NODE_PORTS[@]}"; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "content"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)
    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        if [ -n "$FETCHED_DATA" ] && [ "$FETCHED_DATA" != "null" ]; then
            DECODED=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null || echo "(decode failed)")
            log_info "  ノード (ポート $port): data=$DECODED (member: data あり)"
            ((IMMEDIATE_MEMBERS++))
        else
            log_info "  ノード (ポート $port): member だが data が空"
        fi
    else
        log_info "  ノード (ポート $port): member ではない"
    fi
done

log_test "少なくとも1つの member が create 直後にデータを保持していること (push-before-announce race の回帰防止)"
if [ "$IMMEDIATE_MEMBERS" -ge 1 ]; then
    log_success "即時同期 OK: $IMMEDIATE_MEMBERS 個の member がデータを保持"
    ((TESTS_PASSED++))
else
    log_fail "即時同期 NG: どの member も create 直後にデータを取得できませんでした"
    log_fail "  → push_operations が bootstrap なしで reject されている可能性があります"
    ((TESTS_FAILED++))
fi

# content_networkの形成を確認（各ノードでcontentsリストを確認）
sleep 2
log_step "content_networkの形成を確認"
for port in "${NODE_PORTS[@]}"; do
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
DECODED_UNAUTH_BODY=$(echo -n "$UPDATED_DATA_UNAUTHORIZED" | base64 -d 2>/dev/null | base64)
log_step "account2がgrant前にコンテンツを更新試行（403を期待）"

test_auth_request \
    "account2が権限なしで更新試行 -> 403" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$UPDATED_DATA_UNAUTHORIZED\"}" \
    403 \
    "$ACCOUNT2_KEY_ID" \
    "$ACCOUNT2_PRIVATE_KEY" \
    "update" \
    "$CONTENT_ID" \
    "$DECODED_UNAUTH_BODY"

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
    "$ACCOUNT1_PRIVATE_KEY" \
    "update" \
    "$CONTENT_ID" \
    "$DECODED_UNAUTH_BODY"

# ============================================================================
# Step 3-5: Content更新（リレー）
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 3-5: Content更新（リレー） ===${NC}"
echo ""

UPDATED_DATA=$(echo -n "Updated content via relay!" | base64)
DECODED_UPDATE_BODY=$(echo -n "$UPDATED_DATA" | base64 -d 2>/dev/null | base64)
log_step "account1 が node A (8080) に PUT /content/:id を送信"
log_info "node Aはmemberではない場合リレーが発生します"

test_auth_request \
    "account1がコンテンツを更新（リレー可能性あり）" \
    PUT \
    "http://127.0.0.1:8080/content/$CONTENT_ID" \
    "{\"data\": \"$UPDATED_DATA\"}" \
    200 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_PRIVATE_KEY" \
    "update" \
    "$CONTENT_ID" \
    "$DECODED_UPDATE_BODY"

# ============================================================================
# Step 6: 同期確認
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 6: 同期確認 ===${NC}"
echo ""

log_step "gossipsubによる伝播を待機 (5秒)..."
sleep 5

log_step "各ノードでcontentデータを取得し、更新が反映されていることを確認"
for port in "${NODE_PORTS[@]}"; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "content"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)

    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        DECODED=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null || echo "(decode failed)")
        log_info "  ノード (ポート $port): data=$DECODED"
    else
        log_info "  ノード (ポート $port): データ取得不可（memberでない可能性）"
    fi
done

# memberノードでデータを検証
log_test "少なくとも1つのノードで更新データが取得できること（4ノード構成）"
VERIFIED=false
for port in "${NODE_PORTS[@]}"; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "content"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)
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
    log_fail "同期確認: 4ノードのいずれからもデータが取得できませんでした"
    ((TESTS_FAILED++))
fi

# ============================================================================
# Step 7: BFT 停止/復帰シナリオ（任意実行）
# ----------------------------------------------------------------------------
# RUN_BFT_TEST=1 を指定した場合にのみ実行する。
# 停止/復帰は環境依存のため、以下のコマンド注入方式で実行する:
#   BFT_STOP_CMD="..." RUN_BFT_TEST=1 ./scripts/e2e-test.sh
#   (必要なら BFT_RESTART_CMD を上書き可能)
# 例（ローカル手動運用）:
#   BFT_STOP_CMD="kill $(lsof -ti tcp:8083 | awk 'NR==1')" \
#   RUN_BFT_TEST=1 ./scripts/e2e-test.sh
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 7: BFT 停止/復帰シナリオ（任意） ===${NC}"
echo ""

if [ "${RUN_BFT_TEST:-0}" = "1" ]; then
    if [ -z "${BFT_STOP_CMD:-}" ]; then
        log_fail "RUN_BFT_TEST=1 の場合は BFT_STOP_CMD が必須です"
        ((TESTS_FAILED++))
    else
        if [ -z "${BFT_RESTART_CMD:-}" ]; then
            BOOTSTRAP_INFO=$(curl -s "http://127.0.0.1:8080/node/info" 2>/dev/null || true)
            BOOTSTRAP_PEER_ID=$(echo "$BOOTSTRAP_INFO" | jq -r '.node_id // empty')
            BOOTSTRAP_LISTEN_ADDR=$(echo "$BOOTSTRAP_INFO" | jq -r '.listen_addrs[]? | select(startswith("/ip4/127.0.0.1/tcp/"))' | head -1)
            if [ -z "$BOOTSTRAP_LISTEN_ADDR" ]; then
                BOOTSTRAP_LISTEN_ADDR=$(echo "$BOOTSTRAP_INFO" | jq -r '.listen_addrs[]? | select(startswith("/ip4/0.0.0.0/tcp/"))' | head -1)
                if [ -n "$BOOTSTRAP_LISTEN_ADDR" ]; then
                    BOOTSTRAP_LISTEN_ADDR=$(echo "$BOOTSTRAP_LISTEN_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|')
                fi
            fi

            if [ -z "$BOOTSTRAP_PEER_ID" ] || [ -z "$BOOTSTRAP_LISTEN_ADDR" ]; then
                log_fail "node4復帰用の bootstrap 情報を node1(8080) から取得できませんでした"
                ((TESTS_FAILED++))
            else
                BOOTSTRAP_ADDR="${BOOTSTRAP_LISTEN_ADDR}/p2p/${BOOTSTRAP_PEER_ID}"
                mkdir -p "./logs-bft"
                BFT_RESTART_CMD="../target/release/state-node --data-dir ./data/node4 -l 127.0.0.1:8083 -b ${BOOTSTRAP_ADDR} --log-level info > ./logs-bft/node4.log 2>&1 &"
                log_info "BFT_RESTART_CMD 未指定のため bootstrap付きデフォルト復帰コマンドを使用します"
            fi
        fi

        if [ -z "${BFT_RESTART_CMD:-}" ]; then
            log_fail "node4復帰コマンドの組み立てに失敗しました"
            ((TESTS_FAILED++))
        fi

        if [ "$TESTS_FAILED" -gt 0 ]; then
            :
        else
        log_step "ノード停止コマンドを実行します"
        eval "$BFT_STOP_CMD"

        log_step "node4(8083) 停止確認"
        if curl -s "http://127.0.0.1:8083/health" > /dev/null 2>&1; then
            log_fail "node4 が停止していません（8083 が応答しています）"
            ((TESTS_FAILED++))
        else
            log_success "node4 停止を確認"
            ((TESTS_PASSED++))
        fi

        BFT_UPDATE_DATA=$(echo -n "BFT update while node4 down" | base64)
        DECODED_BFT_UPDATE_BODY=$(echo -n "$BFT_UPDATE_DATA" | base64 -d 2>/dev/null | base64)
        log_step "node4停止中に残りノード経由で更新を実行"
        test_auth_request \
            "node4停止中の更新（継続動作確認）" \
            PUT \
            "http://127.0.0.1:8080/content/$CONTENT_ID" \
            "{\"data\": \"$BFT_UPDATE_DATA\"}" \
            200 \
            "$ACCOUNT1_KEY_ID" \
            "$ACCOUNT1_PRIVATE_KEY" \
            "update" \
            "$CONTENT_ID" \
            "$DECODED_BFT_UPDATE_BODY"

        log_step "ノード復帰コマンドを実行します"
        eval "$BFT_RESTART_CMD"

        log_step "node4(8083) 復帰待ち"
        NODE4_RECOVERED=false
        for _ in {1..30}; do
            if curl -s "http://127.0.0.1:8083/health" > /dev/null 2>&1; then
                NODE4_RECOVERED=true
                break
            fi
            sleep 1
        done

        if [ "$NODE4_RECOVERED" = true ]; then
            log_success "node4 復帰を確認"
            ((TESTS_PASSED++))
        else
            log_fail "node4 が30秒以内に復帰しませんでした"
            ((TESTS_FAILED++))
        fi

        if [ "$NODE4_RECOVERED" = true ]; then
            log_step "復帰後キャッチアップ確認（node4 の contents に対象IDが存在すること）"
            NODE4_CONTENTS=$(curl -s "http://127.0.0.1:8083/contents" 2>/dev/null || true)
            if echo "$NODE4_CONTENTS" | grep -q "$CONTENT_ID"; then
                log_success "node4 で対象コンテンツを確認（キャッチアップ）"
                ((TESTS_PASSED++))
            else
                log_fail "node4 で対象コンテンツを確認できませんでした（キャッチアップ未達の可能性）"
                ((TESTS_FAILED++))
            fi
        fi
        fi
    fi
else
    log_warn "RUN_BFT_TEST=1 が未指定のため BFT 停止/復帰シナリオをスキップします"
fi

# ============================================================================
# Step 8: トークン無効化 (invalidate_tokens)
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 8: トークン無効化 (invalidate_tokens) ===${NC}"
echo ""

log_step "account1 が node A に POST /content/:id/access/invalidate を送信"
log_info "ownerが全AuthTokenを無効化"

test_auth_request \
    "account1がトークンを無効化" \
    POST \
    "http://127.0.0.1:8080/content/$CONTENT_ID/access/invalidate" \
    "" \
    200 \
    "$ACCOUNT1_KEY_ID" \
    "$ACCOUNT1_PRIVATE_KEY" \
    "invalidate" \
    "$CONTENT_ID" \
    ""

if [ "$LAST_STATUS" = "200" ]; then
    log_info "invalidate_tokensレスポンス:"
    echo "$LAST_BODY" | jq -C '.' 2>/dev/null || echo "    $LAST_BODY"
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
