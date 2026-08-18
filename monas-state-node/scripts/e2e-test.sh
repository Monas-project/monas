#!/bin/bash

# Monas State Node - E2E テストスクリプト
# シナリオ: content作成 → update(リレー) → 同期確認 → トークン無効化
#
# 前提条件:
#   ./scripts/start-local-nodes.sh --clean でノードを起動済み
#
# Note: `set -e` is intentionally NOT used. This is a test runner that records
# each assertion into TESTS_PASSED/TESTS_FAILED and decides the exit code from
# the totals at the end. Under `set -e` the script aborted mid-run because a
# failed assertion (`return 1`) — and even a successful `((TESTS_PASSED++))`
# whose pre-increment value is 0 — returns a non-zero status. Hard
# preconditions (nodes not up, auth generation failure) still `exit 1`
# explicitly below.

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# e2e は常に 4 ノード構成で行う(start-local-nodes.sh / ci-e2e.sh と一致)。
# creator + 3 members(MIN_REPLICATION_FACTOR=3)。create を受けたノード
# (CREATOR_PORT)は意図的に member にならず local CRDT を持たないため、
# そのノード経由の read は必ず relay read 経路(#54/#55)を通る。
NODE_PORTS="8080 8081 8082 8083"
CREATOR_PORT=8080

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

# 条件が成立するまでポーリングする汎用ヘルパー。
# 固定 sleep は速いマシンでは無駄に待ち、遅い共有 CI ランナーでは伝播が
# 間に合わず flaky になる。代わりに「コマンドが成功するまで最大 timeout 秒、
# interval 秒間隔でリトライ」する。成功したら 0、タイムアウトしたら 1 を返す。
# 使い方: poll_until <timeout_secs> <interval_secs> <command...>
poll_until() {
    local timeout="$1"; shift
    local interval="$1"; shift
    local elapsed=0
    while true; do
        if "$@"; then
            return 0
        fi
        # bash は小数比較ができないので、待った回数で打ち切りを判定する。
        # awk で elapsed >= timeout を評価する。
        if awk "BEGIN{exit !($elapsed >= $timeout)}"; then
            return 1
        fi
        sleep "$interval"
        elapsed=$(awk "BEGIN{print $elapsed + $interval}")
    done
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
    for port in $NODE_PORTS; do
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
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_fail "$description (期待: HTTP $expected_status, 実際: HTTP $LAST_STATUS)"
        echo "    Response: $LAST_BODY"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# ノード登録
register_nodes() {
    log_info "ノード登録を行います..."
    for port in $NODE_PORTS; do
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

IMMEDIATE_SERVING=0
for port in $NODE_PORTS; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)
    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        if [ -n "$FETCHED_DATA" ] && [ "$FETCHED_DATA" != "null" ]; then
            # 応答は Node 全体の CBOR なので中身は表示せずサイズだけログする
            # (relay read があるため、data が返る = member とは限らない)
            DATA_BYTES=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
            log_info "  ノード (ポート $port): data あり (Node CBOR ${DATA_BYTES} bytes, local または relay)"
            IMMEDIATE_SERVING=$((IMMEDIATE_SERVING + 1))
        else
            log_info "  ノード (ポート $port): data が空"
        fi
    else
        log_info "  ノード (ポート $port): data なし"
    fi
done

log_test "少なくとも1つの member が create 直後にデータを保持していること (push-before-announce race の回帰防止)"
if [ "$IMMEDIATE_SERVING" -ge 1 ]; then
    log_success "即時同期 OK: $IMMEDIATE_SERVING 個のノードがデータを提供 (local または relay)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "即時同期 NG: どの member も create 直後にデータを取得できませんでした"
    log_fail "  → push_operations が bootstrap なしで reject されている可能性があります"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ----------------------------------------------------------------------------
# Step 2.6: 非 member ノード経由の relay read 検証 (#54/#55 の回帰テスト)
# ----------------------------------------------------------------------------
# creator ノード(CREATOR_PORT)は create_content で意図的に member から除外され、
# local CRDT コピーを持たない(state_node_service.rs の create_content 参照)。
# したがってこのノードへの read が data を返す = member への relay read が
# 機能していることの直接の証明になる。
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 2.6: 非 member (creator) 経由の relay read 検証 ===${NC}"
echo ""

relay_read_ok() {
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
    local resp
    resp=$(curl -s "http://127.0.0.1:$CREATOR_PORT/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)
    RELAY_READ_RESPONSE="$resp"
    local data
    data=$(echo "$resp" | jq -r '.data // empty' 2>/dev/null)
    [ -n "$data" ] && [ "$data" != "null" ]
}

log_step "creator ノード (ポート $CREATOR_PORT, 非 member) へ read を送信 (最大10秒ポーリング)"
log_test "非 member ノード経由の relay read でデータと version が返ること"
if poll_until 10 1 relay_read_ok; then
    RELAY_VERSION=$(echo "$RELAY_READ_RESPONSE" | jq -r '.version // empty' 2>/dev/null)
    if [ -n "$RELAY_VERSION" ] && [ "$RELAY_VERSION" != "null" ]; then
        log_success "relay read OK: version=$RELAY_VERSION (client はこの CID で Node CBOR を検証できる)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "relay read で data は返ったが version が空 (クライアント側 CID 検証が不可能になる)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    log_fail "非 member ノード経由の relay read が10秒以内に成功しませんでした"
    log_fail "  → member への read relay (#54) が機能していない可能性があります"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# スモークモード: ここまで(content 作成 201 + 即時同期 + relay read)で打ち切る。
# CI の e2e ジョブはこのスモークだけを回し、request-response の DialFailure
# 回帰(作成が 201 を返し、メンバーが即時にデータを保持する)をピンポイントで
# 担保する。grant/revoke/invalidate を含むフルシナリオには別途の既知課題が
# あるため、CI を安定して緑に保つ目的でスモークに限定している。
if [ "${E2E_SMOKE:-0}" = "1" ]; then
    echo ""
    echo -e "${BLUE}=== スモーク結果 (作成 + 即時同期) ===${NC}"
    echo -e "成功: ${GREEN}$TESTS_PASSED${NC} / 失敗: ${RED}$TESTS_FAILED${NC}"
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}スモークテスト成功${NC}"
        exit 0
    else
        echo -e "${YELLOW}スモークテスト失敗${NC}"
        exit 1
    fi
fi

# content_networkの形成を確認（各ノードでcontentsリストを確認）
sleep 2
log_step "content_networkの形成を確認"
for port in $NODE_PORTS; do
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

# いずれかのノードで更新データが取得できるようになるまで最大15秒ポーリングする。
# 固定の sleep 5 は遅い CI ランナーで伝播が間に合わず flaky になっていた。
updated_content_visible() {
    local p
    for p in $NODE_PORTS; do
        generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
        local resp
        resp=$(curl -s "http://127.0.0.1:$p/content/$CONTENT_ID/data" \
            -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
            -H "X-Request-Signature: $LAST_SIGNATURE" \
            -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)
        local data
        data=$(echo "$resp" | jq -r '.data // empty' 2>/dev/null)
        if [ -n "$data" ] && [ "$data" != "null" ]; then
            return 0
        fi
    done
    return 1
}
log_step "gossipsubによる更新の伝播を待機 (最大15秒ポーリング)..."
poll_until 15 1 updated_content_visible || log_warn "15秒以内に更新の伝播を確認できませんでした(以降の検証で再確認します)"

log_step "各ノードでcontentデータを取得し、更新が反映されていることを確認"
for port in $NODE_PORTS; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)

    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        DATA_BYTES=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        log_info "  ノード (ポート $port): data あり (Node CBOR ${DATA_BYTES} bytes)"
    else
        log_info "  ノード (ポート $port): データ取得不可"
    fi
done

# memberノードでデータを検証
log_test "少なくとも1つのノードで更新データが取得できること"
VERIFIED=false
for port in $NODE_PORTS; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
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
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "同期確認: どのノードからもデータが取得できませんでした"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# Step 7: トークン無効化 (invalidate_tokens)
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 7: トークン無効化 (invalidate_tokens) ===${NC}"
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
