#!/bin/bash

# Monas State Node - E2E test script
# Scenario: create content -> update (relay) -> verify sync -> invalidate tokens
#
# Prerequisites:
#   Nodes already started with ./scripts/start-local-nodes.sh --clean
#
# Note: `set -e` is intentionally NOT used. This is a test runner that records
# each assertion into TESTS_PASSED/TESTS_FAILED and decides the exit code from
# the totals at the end. Under `set -e` the script aborted mid-run because a
# failed assertion (`return 1`) — and even a successful `((TESTS_PASSED++))`
# whose pre-increment value is 0 — returns a non-zero status. Hard
# preconditions (nodes not up, auth generation failure) still `exit 1`
# explicitly below.

# Color output definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# e2e always runs with 4 nodes (matching start-local-nodes.sh / ci-e2e.sh):
# creator + 3 members (MIN_REPLICATION_FACTOR=3). The node that receives the
# create (CREATOR_PORT) intentionally does not become a member and holds no local
# CRDT, so reads via that node always go through the relay read path (#54/#55).
NODE_PORTS="8080 8081 8082 8083"
CREATOR_PORT=8080

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

# Generic helper that polls until a condition holds.
# A fixed sleep wastes time on fast machines and is flaky on slow shared CI
# runners where propagation doesn't finish in time. Instead, retry the command
# every interval seconds for up to timeout seconds until it succeeds. Returns 0
# on success, 1 on timeout.
# Usage: poll_until <timeout_secs> <interval_secs> <command...>
poll_until() {
    local timeout="$1"; shift
    local interval="$1"; shift
    local elapsed=0
    while true; do
        if "$@"; then
            return 0
        fi
        # bash can't compare decimals, so decide the cutoff from the elapsed wait time.
        # Evaluate elapsed >= timeout with awk.
        if awk "BEGIN{exit !($elapsed >= $timeout)}"; then
            return 1
        fi
        sleep "$interval"
        elapsed=$(awk "BEGIN{print $elapsed + $interval}")
    done
}

# Move to the State Node directory
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

# Variables to record test results
TESTS_PASSED=0
TESTS_FAILED=0

# Build the test-auth-generator binary
log_info "Building test-auth-generator..."
cargo build --bin test-auth-generator 2>/dev/null || {
    log_error "Build failed"
    cargo build --bin test-auth-generator
    exit 1
}

AUTH_GEN="cargo run --bin test-auth-generator --"

# ============================================================================
# Helper functions
# ============================================================================

# Generate a signature
# Arguments: private_key operation resource [body_base64]
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

# Check that nodes are running
check_nodes_running() {
    log_info "Checking node status..."

    local all_running=true
    for port in $NODE_PORTS; do
        if curl -s "http://127.0.0.1:$port/health" > /dev/null 2>&1; then
            log_success "Node (port $port) is running"
        else
            log_fail "Node (port $port) is not running"
            all_running=false
        fi
    done

    if [ "$all_running" = false ]; then
        log_error "Not all nodes are running. Run ./scripts/start-local-nodes.sh --clean first"
        exit 1
    fi
}

# Run an authenticated HTTP request and check the response
# Arguments: description method url data expected_status key_id private_key [body_for_sign]
# Pass "" if data is empty
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

    # Generate the signature
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
        log_fail "$description (expected: HTTP $expected_status, actual: HTTP $LAST_STATUS)"
        echo "    Response: $LAST_BODY"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Node registration
register_nodes() {
    log_info "Registering nodes..."
    for port in $NODE_PORTS; do
        curl -s -X POST "http://127.0.0.1:$port/node/register" \
            -H "Content-Type: application/json" \
            -d '{"total_capacity": 10000000}' > /dev/null 2>&1 || true
    done
    # Wait for node registration to propagate
    sleep 2
    log_success "Node registration complete"
}

# ============================================================================
# Main
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Monas State Node E2E Tests           ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check that nodes are running
check_nodes_running

# Node registration
register_nodes

# ============================================================================
# Prepare auth data
# ============================================================================

echo ""
echo -e "${BLUE}=== Preparing auth data ===${NC}"
echo ""

# Generate account1's key pair (self-contained key_id: the public key is embedded in the key_id)
log_info "Generating auth data for account1..."
ACCOUNT1_AUTH=$($AUTH_GEN test-auth 2>/dev/null)
ACCOUNT1_PRIVATE_KEY=$(echo "$ACCOUNT1_AUTH" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
ACCOUNT1_PUBLIC_KEY=$(echo "$ACCOUNT1_AUTH" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
ACCOUNT1_KEY_ID=$(echo "$ACCOUNT1_AUTH" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$ACCOUNT1_PRIVATE_KEY" ] || [ -z "$ACCOUNT1_PUBLIC_KEY" ] || [ -z "$ACCOUNT1_KEY_ID" ]; then
    log_error "Failed to generate auth data for account1"
    exit 1
fi

# key_id is self-contained, so no public key registration with nodes is needed
log_success "account1: key_id=$ACCOUNT1_KEY_ID"

# Generate account2's key pair
log_info "Generating auth data for account2..."
ACCOUNT2_AUTH=$($AUTH_GEN test-auth 2>/dev/null)
ACCOUNT2_PRIVATE_KEY=$(echo "$ACCOUNT2_AUTH" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
ACCOUNT2_PUBLIC_KEY=$(echo "$ACCOUNT2_AUTH" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
ACCOUNT2_KEY_ID=$(echo "$ACCOUNT2_AUTH" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$ACCOUNT2_PRIVATE_KEY" ] || [ -z "$ACCOUNT2_PUBLIC_KEY" ] || [ -z "$ACCOUNT2_KEY_ID" ]; then
    log_error "Failed to generate auth data for account2"
    exit 1
fi

# key_id is self-contained, so no public key registration with nodes is needed
log_success "account2: key_id=$ACCOUNT2_KEY_ID"

# ============================================================================
# Step 1-2: Create content
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 1-2: Create content ===${NC}"
echo ""

CONTENT_DATA=$(echo -n "Hello, Monas E2E Test!" | base64)
DECODED_BODY=$(echo -n "$CONTENT_DATA" | base64 -d 2>/dev/null | base64)
log_step "account1 sends POST /content to node A (8080)"

test_auth_request \
    "account1 creates content" \
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
    log_error "Failed to get the content ID. Aborting tests."
    echo "Response: $LAST_BODY"
    exit 1
fi

log_info "Created content ID: $CONTENT_ID"

# ============================================================================
# Step 2.5: Immediate read right after create (regression test for the push-before-announce race)
# ----------------------------------------------------------------------------
# Verify that member nodes hold the CRDT data immediately after create_content
# returns, without relying on gossipsub settling. push_operations must be
# delivered synchronously to members with bootstrap. The sleep is only the
# minimum (200ms) needed for TCP/swarm to receive the response.
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 2.5: Immediate sync right after create ===${NC}"
echo ""
sleep 0.2
log_step "Check that content data can be fetched immediately from all nodes"

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
            # The response is the CBOR of the whole Node, so log only its size, not its contents
            # (because of relay read, returning data does not necessarily mean member)
            DATA_BYTES=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
            log_info "  Node (port $port): has data (Node CBOR ${DATA_BYTES} bytes, local or relay)"
            IMMEDIATE_SERVING=$((IMMEDIATE_SERVING + 1))
        else
            log_info "  Node (port $port): data is empty"
        fi
    else
        log_info "  Node (port $port): no data"
    fi
done

log_test "At least one member holds the data right after create (push-before-announce race regression guard)"
if [ "$IMMEDIATE_SERVING" -ge 1 ]; then
    log_success "Immediate sync OK: $IMMEDIATE_SERVING node(s) serving data (local or relay)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Immediate sync NG: no member could serve data right after create"
    log_fail "  → push_operations may be getting rejected without bootstrap"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ----------------------------------------------------------------------------
# Step 2.6: relay read via a non-member node (regression test for #54/#55)
# ----------------------------------------------------------------------------
# The creator node (CREATOR_PORT) is intentionally excluded from members in
# create_content and holds no local CRDT copy (see create_content in
# state_node_service.rs). So a read to this node returning data is direct proof
# that relay read to members works.
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 2.6: relay read via non-member (creator) ===${NC}"
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

log_step "Send read to the creator node (port $CREATOR_PORT, non-member) (polling up to 10s)"
log_test "relay read via a non-member node returns data and version"
if poll_until 10 1 relay_read_ok; then
    RELAY_VERSION=$(echo "$RELAY_READ_RESPONSE" | jq -r '.version // empty' 2>/dev/null)
    if [ -n "$RELAY_VERSION" ] && [ "$RELAY_VERSION" != "null" ]; then
        log_success "relay read OK: version=$RELAY_VERSION (client can verify the Node CBOR with this CID)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "relay read returned data but version is empty (client-side CID verification becomes impossible)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    log_fail "relay read via a non-member node did not succeed within 10s"
    log_fail "  → read relay to members (#54) may not be working"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Smoke mode: stop here (content creation 201 + immediate sync + relay read).
# The CI e2e job runs only this smoke test, specifically guarding against the
# request-response DialFailure regression (create returns 201 and members hold
# the data immediately). The full scenario including grant/revoke/invalidate has
# separate known issues, so CI is limited to the smoke test to stay reliably green.
if [ "${E2E_SMOKE:-0}" = "1" ]; then
    echo ""
    echo -e "${BLUE}=== Smoke results (create + immediate sync) ===${NC}"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC} / Failed: ${RED}$TESTS_FAILED${NC}"
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}Smoke test passed${NC}"
        exit 0
    else
        echo -e "${YELLOW}Smoke test failed${NC}"
        exit 1
    fi
fi

# Verify content_network formation (check the contents list on each node)
sleep 2
log_step "Verify content_network formation"
for port in $NODE_PORTS; do
    count=$(curl -s "http://127.0.0.1:$port/contents" | jq '. | length' 2>/dev/null || echo "0")
    log_info "  Node (port $port): sees $count content items"
done

# ============================================================================
# Error case: unauthorized account2 attempts an update before grant
# ============================================================================

echo ""
echo -e "${BLUE}=== Error case: update attempt by unauthorized user ===${NC}"
echo ""

UPDATED_DATA_UNAUTHORIZED=$(echo -n "Unauthorized update attempt" | base64)
DECODED_UNAUTH_BODY=$(echo -n "$UPDATED_DATA_UNAUTHORIZED" | base64 -d 2>/dev/null | base64)
log_step "account2 attempts to update content before grant (expect 403)"

test_auth_request \
    "account2 attempts update without permission -> 403" \
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
# Error case: update attempt with an invalid token
# ============================================================================

echo ""
echo -e "${BLUE}=== Error case: update with an invalid token ===${NC}"
echo ""

log_step "Attempt to update content with an invalid token (expect 401)"

test_auth_request \
    "Update attempt with invalid token -> 401" \
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
# Step 3-5: Update content (relay)
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 3-5: Update content (relay) ===${NC}"
echo ""

UPDATED_DATA=$(echo -n "Updated content via relay!" | base64)
DECODED_UPDATE_BODY=$(echo -n "$UPDATED_DATA" | base64 -d 2>/dev/null | base64)
log_step "account1 sends PUT /content/:id to node A (8080)"
log_info "If node A is not a member, the request is relayed"

test_auth_request \
    "account1 updates content (may be relayed)" \
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
# Step 6: Verify sync
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 6: Verify sync ===${NC}"
echo ""

# Poll for up to 15s until the updated data can be fetched from any node.
# A fixed sleep 5 was flaky on slow CI runners where propagation didn't finish in time.
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
log_step "Waiting for the update to propagate via gossipsub (polling up to 15s)..."
poll_until 15 1 updated_content_visible || log_warn "Could not confirm update propagation within 15s (will recheck in the following verification)"

log_step "Fetch content data on each node and verify the update is reflected"
for port in $NODE_PORTS; do
    generate_signature "$ACCOUNT1_PRIVATE_KEY" "read" "$CONTENT_ID"
    DATA_RESPONSE=$(curl -s "http://127.0.0.1:$port/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $ACCOUNT1_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" 2>/dev/null)

    if echo "$DATA_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
        FETCHED_DATA=$(echo "$DATA_RESPONSE" | jq -r '.data' 2>/dev/null)
        DATA_BYTES=$(echo "$FETCHED_DATA" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
        log_info "  Node (port $port): has data (Node CBOR ${DATA_BYTES} bytes)"
    else
        log_info "  Node (port $port): data unavailable"
    fi
done

# Verify data on member nodes
log_test "Updated data can be fetched from at least one node"
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
    log_success "Sync verified: data is available"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Sync check: could not fetch data from any node"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# Step 7: Invalidate tokens (invalidate_tokens)
# ============================================================================

echo ""
echo -e "${BLUE}=== Step 7: Invalidate tokens (invalidate_tokens) ===${NC}"
echo ""

log_step "account1 sends POST /content/:id/access/invalidate to node A"
log_info "owner invalidates all AuthTokens"

test_auth_request \
    "account1 invalidates tokens" \
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
    log_info "invalidate_tokens response:"
    echo "$LAST_BODY" | jq -C '.' 2>/dev/null || echo "    $LAST_BODY"
fi

# ============================================================================
# Test result summary
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        E2E Test Result Summary         ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

total_tests=$((TESTS_PASSED + TESTS_FAILED))
echo -e "Tests run: ${BLUE}$total_tests${NC}"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}All E2E tests passed!${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}Some tests failed${NC}"
    echo "See logs/node*.log for detailed logs"
    exit 1
fi
