#!/bin/bash

# Monas State Node - test authentication data generator script
# Generates a P-256 key pair, an AuthToken token, and request signatures

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

# Move to the State Node directory
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

# Build the binary
log_info "Building test-auth-generator..."
cargo build --bin test-auth-generator 2>/dev/null || {
    log_error "Build failed. Check the Cargo error messages."
    cargo build --bin test-auth-generator
    exit 1
}

# Define the cargo run command as a function
run_test_auth_generator() {
    cargo run --bin test-auth-generator -- "$@"
}

# Handle the command
if [ $# -eq 0 ] || [ "$1" == "help" ] || [ "$1" == "--help" ]; then
    echo ""
    echo -e "${BLUE}=== Test Auth Generator ===${NC}"
    echo ""
    echo "Usage: $0 <command> [args...]"
    echo ""
    echo "Commands:"
    echo "  generate-token [content_id]  - Generate an AuthToken"
    echo "  generate-signature <data>    - Generate a request signature"
    echo "  generate-keys                - Generate a new P-256 key pair"
    echo "  test-auth                    - Generate a complete set of test auth data"
    echo "  export                       - Export auth data as environment variables"
    echo ""
    echo "Examples:"
    echo "  $0 test-auth                     # Generate a complete set of test auth data"
    echo "  $0 generate-token content123     # Generate a token for a specific content ID"
    echo "  $0 export > test-auth.env        # Save as an environment variable file"
    echo ""
    exit 0
fi

command="$1"
shift

case "$command" in
    "generate-token")
        log_info "Generating AuthToken..."
        run_test_auth_generator generate-token "$@"
        ;;

    "generate-signature")
        if [ $# -eq 0 ]; then
            log_error "Specify the data to sign"
            exit 1
        fi
        log_info "Generating request signature..."
        run_test_auth_generator generate-signature "$@"
        ;;

    "generate-keys")
        log_info "Generating P-256 key pair..."
        run_test_auth_generator generate-keys
        ;;

    "test-auth")
        log_info "Generating complete test auth data..."
        run_test_auth_generator test-auth
        ;;

    "export")
        # Export as environment variables (in a form a script can source)
        OUTPUT=$(run_test_auth_generator test-auth 2>&1)
        echo "$OUTPUT" | grep "^export " | while read line; do
            echo "$line"
        done
        echo ""
        echo "# Usage:"
        echo "# source <(./scripts/generate-test-auth.sh export)"
        echo "# or"
        echo "# ./scripts/generate-test-auth.sh export > test-auth.env"
        echo "# source test-auth.env"
        ;;

    *)
        log_error "Unknown command: $command"
        echo "Run '$0 help' for details"
        exit 1
        ;;
esac