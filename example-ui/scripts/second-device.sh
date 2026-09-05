#!/usr/bin/env bash
# Run a second, independent gateway + monas-account pair on :3001 / :4003 —
# "another person's device" for the cross-device share journey (J-4).
#
# Independence is the point: the pair has its own persistence dir (CEK store,
# sender pins, shares) and its own signing key, so nothing the first device
# knows leaks into the second. Both talk to the same state node.
#
#   MONAS_STATE_NODE_URL=https://node1.monas-demo.net ./scripts/second-device.sh
#
# Then in the browser context that plays the second device, set the endpoints
# (Settings, or localStorage "monas.endpoints.v2") to
#   {"gateway":"/api2","accountService":"/account-api2"}
# — vite proxies those to this pair. Ctrl-C stops both.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_NODE="${MONAS_STATE_NODE_URL:?set MONAS_STATE_NODE_URL to the node the first gateway uses}"
PERSIST="${MONAS_PERSISTENCE_DIR2:-$(mktemp -d "${TMPDIR:-/tmp}/monas-device2.XXXXXX")}"
GW_PORT="${MONAS_API_PORT2:-3001}"
ACCT_PORT="${MONAS_ACCOUNT_PORT2:-4003}"

echo "second device: gateway :$GW_PORT, account :$ACCT_PORT, persistence $PERSIST"

MONAS_ACCOUNT_PORT="$ACCT_PORT" "$ROOT/target/debug/monas-account" &
ACCT_PID=$!
MONAS_API_PORT="$GW_PORT" \
MONAS_STATE_NODE_URL="$STATE_NODE" \
MONAS_ACCOUNT_URL="http://127.0.0.1:$ACCT_PORT" \
MONAS_PERSISTENCE_DIR="$PERSIST" \
  "$ROOT/target/debug/monas-gateway" &
GW_PID=$!

trap 'kill $ACCT_PID $GW_PID 2>/dev/null || true' EXIT INT TERM
wait
