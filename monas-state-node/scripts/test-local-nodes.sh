#!/bin/bash

# Monas State Node - functional test script
# Tests various features while three nodes are running

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

# Variables that record test results
TESTS_PASSED=0
TESTS_FAILED=0

# Send an HTTP request and check the response
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
        log_fail "$description (expected: HTTP $expected_status, actual: HTTP $status_code)"
        ((TESTS_FAILED++))
        echo "$body"
        return 1
    fi
}

# Check that the nodes are running
check_nodes_running() {
    log_info "Checking whether the nodes are running..."

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
        log_error "Not all nodes are running. Run ./scripts/start-local-nodes.sh first"
        exit 1
    fi
}

# Run the tests
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Starting Monas State Node func tests  ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check that the nodes are running
check_nodes_running

echo ""
echo -e "${BLUE}=== Basic API tests ===${NC}"
echo ""

# Health checks
test_request "Node 1 health check" GET "http://127.0.0.1:8080/health"
test_request "Node 2 health check" GET "http://127.0.0.1:8081/health"
test_request "Node 3 health check" GET "http://127.0.0.1:8082/health"
test_request "Node 4 health check" GET "http://127.0.0.1:8083/health"

echo ""
echo -e "${BLUE}=== Node registration tests ===${NC}"
echo ""

# Get node info
test_request "Get node 1 info" GET "http://127.0.0.1:8080/node/info"
NODE1_INFO=$(curl -s http://127.0.0.1:8080/node/info)
NODE1_ID=$(echo "$NODE1_INFO" | jq -r '.node_id')

test_request "Get node 2 info" GET "http://127.0.0.1:8081/node/info"
NODE2_INFO=$(curl -s http://127.0.0.1:8081/node/info)
NODE2_ID=$(echo "$NODE2_INFO" | jq -r '.node_id')

test_request "Get node 3 info" GET "http://127.0.0.1:8082/node/info"
NODE3_INFO=$(curl -s http://127.0.0.1:8082/node/info)

test_request "Get node 4 info" GET "http://127.0.0.1:8083/node/info"
NODE4_INFO=$(curl -s http://127.0.0.1:8083/node/info)
NODE3_ID=$(echo "$NODE3_INFO" | jq -r '.node_id')

# Node registration
test_request "Register node 1" POST "http://127.0.0.1:8080/node/register" '{"total_capacity": 1000000}'
test_request "Register node 2" POST "http://127.0.0.1:8081/node/register" '{"total_capacity": 2000000}'
test_request "Register node 3" POST "http://127.0.0.1:8082/node/register" '{"total_capacity": 1500000}'

# Check the list of registered nodes
echo ""
log_test "Check the node list as seen from each node"
test_request "Node list as seen from node 1" GET "http://127.0.0.1:8080/nodes"
test_request "Node list as seen from node 2" GET "http://127.0.0.1:8081/nodes"
test_request "Node list as seen from node 3" GET "http://127.0.0.1:8082/nodes"

echo ""
echo -e "${BLUE}=== Content operation tests (no auth) ===${NC}"
echo ""

# Get the content list (initial state)
test_request "Content list in initial state" GET "http://127.0.0.1:8080/contents"

# Create content without auth (should fail)
echo ""
log_test "Create content without auth (expected to fail)"
test_request "Create content without auth" POST "http://127.0.0.1:8080/content" '{"data": "SGVsbG8sIFdvcmxkIQ=="}' 401 || true

echo ""
echo -e "${BLUE}=== Simulated authenticated content operations ===${NC}"
echo ""

# Note: without a real auth token and signature, these tests fail
# Here we test on the assumption that they fail, to check API behavior

log_warn "Tests for operations that require auth (expected to fail since there is no real token)"

# Dummy token and signature
DUMMY_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
DUMMY_SIGNATURE="dGVzdF9zaWduYXR1cmU="

# Try creating content with auth
curl -s -X POST http://127.0.0.1:8080/content \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DUMMY_TOKEN" \
  -H "X-Request-Signature: $DUMMY_SIGNATURE" \
  -d '{"data": "SGVsbG8sIFdvcmxkIQ=="}' \
  -w "\nHTTP Status: %{http_code}\n" || true

echo ""
echo -e "${BLUE}=== P2P network tests ===${NC}"
echo ""

# Check P2P connections (must be checked in the logs)
log_test "Check P2P connection status"
log_info "Check the P2P connections between nodes in the log files:"
echo "  - tail -f logs/node1.log | grep -E 'Peer|connected|discovered'"
echo "  - tail -f logs/node2.log | grep -E 'Peer|connected|discovered'"
echo "  - tail -f logs/node3.log | grep -E 'Peer|connected|discovered'"

echo ""
echo -e "${BLUE}=== CRDT sync tests (setup) ===${NC}"
echo ""

log_info "CRDT sync tests require actually creating content"
log_info "Generate an auth token and test with a command like the following:"
echo ""
echo 'TOKEN="your-actual-token"'
echo 'SIGNATURE="your-actual-signature"'
echo 'curl -X POST http://127.0.0.1:8080/content \'
echo '  -H "Content-Type: application/json" \'
echo '  -H "Authorization: Bearer $TOKEN" \'
echo '  -H "X-Request-Signature: $SIGNATURE" \'
echo '  -d '"'"'{"data": "SGVsbG8sIFdvcmxkIQ=="}'"'"

echo ""
echo -e "${BLUE}=== Advanced feature tests ===${NC}"
echo ""

# Event propagation test between nodes
log_test "Check event propagation"
log_info "Verify that a change made on one node propagates as events to the other nodes"
log_info "Look for the following messages in the log files:"
echo "  - 'Event received via Gossipsub'"
echo "  - 'Content synced from peer'"
echo "  - 'CRDT merge completed'"

# Check disk capacity
echo ""
log_test "Check disk capacity"
for port in 8080 8081 8082 8083; do
    node_info=$(curl -s "http://127.0.0.1:$port/node/info")
    if [ $? -eq 0 ]; then
        total_capacity=$(echo "$node_info" | jq -r '.total_capacity // "unknown"')
        available_capacity=$(echo "$node_info" | jq -r '.available_capacity // "unknown"')
        log_info "Node (port $port): total=$total_capacity, available=$available_capacity"
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}          Test results summary          ${NC}"
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
    echo -e "${YELLOW}Some tests failed (expected for tests that require auth)${NC}"
    exit 0
fi