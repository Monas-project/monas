#!/bin/bash

# Monas State Node - authenticated feature test script
# Generates a P-256 key pair, registers it with each node, then tests authenticated requests

set -e

# Color output definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
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
    local add_members_count="$5"

    local sign_args="sign-request --private-key $private_key --operation $operation --resource $resource"
    if [ -n "$body_b64" ]; then
        sign_args="$sign_args --body $body_b64"
    fi
    if [ -n "$add_members_count" ]; then
        sign_args="$sign_args --add-members-count $add_members_count"
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
    for port in 8080 8081 8082 8083; do
        if curl -s "http://127.0.0.1:$port/health" > /dev/null 2>&1; then
            log_success "Node (port $port) is running"
        else
            log_fail "Node (port $port) is not running"
            all_running=false
        fi
    done

    if [ "$all_running" = false ]; then
        log_warn "Some nodes are not running. Testing with at least one node"
        if ! curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1 && \
           ! curl -s "http://127.0.0.1:8083/health" > /dev/null 2>&1; then
            log_error "No nodes are running. Run ./scripts/start-local-nodes.sh first"
            exit 1
        fi
    fi
}

# ============================================================================
# Main
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Monas State Node Authenticated Tests  ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check that nodes are running
check_nodes_running

# Choose the port to use (first running node)
TEST_PORT=8080
if ! curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1; then
    if curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1; then
        TEST_PORT=8081
    elif curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then
        TEST_PORT=8082
    elif curl -s "http://127.0.0.1:8083/health" > /dev/null 2>&1; then
        TEST_PORT=8083
    fi
fi

BASE_URL="http://127.0.0.1:$TEST_PORT"
log_info "Target node: $BASE_URL"

# ============================================================================
# Generate and register auth data
# ============================================================================

echo ""
echo -e "${BLUE}=== Generating auth data ===${NC}"
echo ""

log_info "Generating test key pair..."
AUTH_OUTPUT=$($AUTH_GEN test-auth 2>/dev/null)
TEST_PRIVATE_KEY=$(echo "$AUTH_OUTPUT" | grep "^PRIVATE_KEY=" | sed 's/^PRIVATE_KEY=//')
TEST_PUBLIC_KEY=$(echo "$AUTH_OUTPUT" | grep "^PUBLIC_KEY=" | sed 's/^PUBLIC_KEY=//')
TEST_KEY_ID=$(echo "$AUTH_OUTPUT" | grep "^KEY_ID=" | sed 's/^KEY_ID=//')

if [ -z "$TEST_PRIVATE_KEY" ] || [ -z "$TEST_PUBLIC_KEY" ] || [ -z "$TEST_KEY_ID" ]; then
    log_error "Failed to generate key pair"
    echo "$AUTH_OUTPUT"
    exit 1
fi

log_success "Generated key pair"
log_info "Key ID: $TEST_KEY_ID"

# key_id is self-contained, so no public key registration with nodes is needed
log_success "Self-contained key_id: no public key registration needed"

# ============================================================================
# Content creation test (authenticated)
# ============================================================================

echo ""
echo -e "${BLUE}=== Content creation test (authenticated) ===${NC}"
echo ""

# base64 representation of the base64-decoded binary data
CONTENT_B64="SGVsbG8sIFdvcmxkIQ=="  # "Hello, World!"

# Generate the signature for create (body-based)
# The HTTP API base64-decodes the JSON body, so the signature is over the decoded bytes
# Note: verify_caller_signature() is called in create_content(&data, ...), where data is the decoded bytes
# => pass the decoded bytes as the body
DECODED_BODY=$(echo -n "$CONTENT_B64" | base64 -d 2>/dev/null | base64)
generate_signature "$TEST_PRIVATE_KEY" "create" "content" "$DECODED_BODY"
CREATE_SIGNATURE="$LAST_SIGNATURE"
CREATE_TIMESTAMP="$LAST_TIMESTAMP"

log_test "Create new content"
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
    log_success "Create new content (HTTP 201)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "$response_body" | jq -C '.' 2>/dev/null || echo "$response_body"
    CONTENT_ID=$(echo "$response_body" | jq -r '.content_id // empty' 2>/dev/null)
else
    log_fail "Create new content (expected: HTTP 201, actual: HTTP $status_code)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "$response_body"
    CONTENT_ID=""
fi

if [ -n "$CONTENT_ID" ]; then
    log_info "Created content ID: $CONTENT_ID"

    echo ""
    echo -e "${BLUE}=== Content operation tests ===${NC}"
    echo ""

    # Update the content
    UPDATED_B64="VXBkYXRlZCBjb250ZW50"  # "Updated content"
    DECODED_UPDATED_BODY=$(echo -n "$UPDATED_B64" | base64 -d 2>/dev/null | base64)
    generate_signature "$TEST_PRIVATE_KEY" "update" "$CONTENT_ID" "$DECODED_UPDATED_BODY"

    log_test "Update content"
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
        log_success "Update content (HTTP 200)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Update content (expected: HTTP 200, actual: HTTP $UPDATE_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$UPDATE_BODY"
    fi

    # Resend the exact same signature, timestamp, and body as the previous update.
    # A freshness check alone would accept it since it is within the 5-minute window,
    # but mutation signatures are single-use, so it is rejected with 409. If accepted,
    # an attacker could later replay a signed old ciphertext update to roll back the latest version.
    log_test "Reject replayed update with the same signature"
    REPLAY_RESPONSE=$(curl -s -X PUT "$BASE_URL/content/$CONTENT_ID" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -d "{\"data\": \"$UPDATED_B64\"}" \
        -w "\n%{http_code}" 2>/dev/null)
    REPLAY_STATUS=$(echo "$REPLAY_RESPONSE" | tail -n1)
    if [ "$REPLAY_STATUS" = "409" ]; then
        log_success "Reject replayed update (HTTP 409)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Reject replayed update (expected: HTTP 409, actual: HTTP $REPLAY_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$REPLAY_RESPONSE" | sed '$d'
    fi

    # Add members (count form)
    # count is covered by the signature; substituting the body fails signature verification
    generate_signature "$TEST_PRIVATE_KEY" "manage" "$CONTENT_ID" "" "1"

    log_test "Add a member to the content network"
    MEMBER_RESPONSE=$(curl -s -X POST "$BASE_URL/content/$CONTENT_ID/members" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -d '{"count": 1}' \
        -w "\n%{http_code}" 2>/dev/null)
    MEMBER_STATUS=$(echo "$MEMBER_RESPONSE" | tail -n1)
    MEMBER_BODY=$(echo "$MEMBER_RESPONSE" | sed '$d')
    # This script sends directly to the node that created the content. The creating
    # node does not make itself a member (it acts as a relay), so add_members returning
    # 403 from the member check is the expected path. 200/503 means this node was a member.
    #
    # Since this 403 comes from the member check, we cannot verify here that count is
    # bound to the signature. The unit test
    # (`test_add_members_count_cannot_be_substituted`) covers that.
    if [ "$MEMBER_STATUS" = "403" ]; then
        log_success "Add member: rejected because the creating node is not a member (HTTP 403 - expected)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    elif [ "$MEMBER_STATUS" = "200" ]; then
        log_success "Add member succeeded (HTTP 200)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "$MEMBER_BODY" | jq -C '.' 2>/dev/null || echo "$MEMBER_BODY"
    elif [ "$MEMBER_STATUS" = "503" ]; then
        log_warn "Add member: no available nodes found via DHT peer discovery (HTTP 503 - expected in small clusters)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Add member (expected: HTTP 403, 200 or 503, actual: HTTP $MEMBER_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$MEMBER_BODY"
    fi

    echo ""
    echo -e "${BLUE}=== CRDT operation tests ===${NC}"
    echo ""

    # Fetch CRDT data (with auth headers)
    generate_signature "$TEST_PRIVATE_KEY" "read" "$CONTENT_ID"

    log_test "Fetch CRDT data"
    DATA_RESPONSE=$(curl -s -X GET "$BASE_URL/content/$CONTENT_ID/data" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    DATA_STATUS=$(echo "$DATA_RESPONSE" | tail -n1)
    DATA_BODY=$(echo "$DATA_RESPONSE" | sed '$d')
    if [ "$DATA_STATUS" = "200" ]; then
        log_success "Fetch CRDT data (HTTP 200)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Fetch CRDT data (expected: HTTP 200, actual: HTTP $DATA_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$DATA_BODY"
    fi

    # Fetch CRDT history (with auth headers)
    generate_signature "$TEST_PRIVATE_KEY" "read" "$CONTENT_ID"

    log_test "Fetch CRDT history"
    HIST_RESPONSE=$(curl -s -X GET "$BASE_URL/content/$CONTENT_ID/history" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    HIST_STATUS=$(echo "$HIST_RESPONSE" | tail -n1)
    HIST_BODY=$(echo "$HIST_RESPONSE" | sed '$d')
    if [ "$HIST_STATUS" = "200" ]; then
        log_success "Fetch CRDT history (HTTP 200)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Fetch CRDT history (expected: HTTP 200, actual: HTTP $HIST_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$HIST_BODY"
    fi

    echo ""
    echo -e "${BLUE}=== Content deletion test ===${NC}"
    echo ""

    # Delete the content
    generate_signature "$TEST_PRIVATE_KEY" "delete" "$CONTENT_ID"

    log_test "Delete content"
    DEL_RESPONSE=$(curl -s -X DELETE "$BASE_URL/content/$CONTENT_ID" \
        -H "Authorization: Bearer $TEST_KEY_ID" \
        -H "X-Request-Signature: $LAST_SIGNATURE" \
        -H "X-Request-Timestamp: $LAST_TIMESTAMP" \
        -w "\n%{http_code}" 2>/dev/null)
    DEL_STATUS=$(echo "$DEL_RESPONSE" | tail -n1)
    DEL_BODY=$(echo "$DEL_RESPONSE" | sed '$d')
    if [ "$DEL_STATUS" = "200" ]; then
        log_success "Delete content (HTTP 200)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "Delete content (expected: HTTP 200, actual: HTTP $DEL_STATUS)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "$DEL_BODY"
    fi
fi

# ============================================================================
# Multi-node sync test
# ============================================================================

echo ""
echo -e "${BLUE}=== Multi-node sync test ===${NC}"
echo ""

# Run the sync test only if all 3 nodes are running
if curl -s "http://127.0.0.1:8080/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8081/health" > /dev/null 2>&1 && \
   curl -s "http://127.0.0.1:8082/health" > /dev/null 2>&1; then

    log_test "Create content on node 1"

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
        log_success "Content created successfully"

        # Wait for sync
        log_info "Waiting for P2P sync (3s)..."
        sleep 3

        # Check content on each node
        log_test "Check the content list on each node"
        for port in 8080 8081 8082 8083; do
            count=$(curl -s "http://127.0.0.1:$port/contents" | jq '. | length' 2>/dev/null || echo "0")
            log_info "Node (port $port): $count content items"
        done
    fi
else
    log_error "Not all nodes are running, so the sync test cannot run"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# Authentication error tests
# ============================================================================

echo ""
echo -e "${BLUE}=== Authentication error tests ===${NC}"
echo ""

# Request with an invalid token
log_test "Request with an invalid token (expect 401)"
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
    log_success "Invalid token was correctly rejected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Invalid token was not rejected (HTTP $status_code)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Request without a signature
log_test "Request without a signature (expect 401)"
response=$(curl -s -X POST "$BASE_URL/content" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TEST_KEY_ID" \
    -d '{"data": "dGVzdA=="}' \
    -w "\n%{http_code}" 2>/dev/null)

status_code=$(echo "$response" | tail -n1)
if [ "$status_code" = "401" ]; then
    log_success "Unsigned request was correctly rejected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Unsigned request was not rejected (HTTP $status_code)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# Test result summary
# ============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        Test Result Summary             ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

total_tests=$((TESTS_PASSED + TESTS_FAILED))
echo -e "Tests run: ${BLUE}$total_tests${NC}"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}Some tests failed${NC}"
    echo "See logs/node*.log for detailed logs"
    exit 1
fi
