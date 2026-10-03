#!/usr/bin/env bash
# Run a second, independent gateway on :3001 — "another person's device" for
# the cross-device share journey (J-4).
#
# Independence is the point: it has its own persistence dir (signing account,
# CEK store, sender pins, shares), so nothing the first device knows leaks
# into the second. Both talk to the state-node network.
#
#   MONAS_STATE_NODE_URL=https://node2.monas-demo.net ./scripts/second-device.sh
#
# Then in the browser context that plays the second device, set the endpoint
# (Settings, or localStorage "monas.endpoints.v2") to {"gateway":"/api2"} —
# vite proxies it to this gateway. Create the account from that context.
# Ctrl-C stops it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_NODE="${MONAS_STATE_NODE_URL:?set MONAS_STATE_NODE_URL to a state node}"
PERSIST="${MONAS_PERSISTENCE_DIR2:-$(mktemp -d "${TMPDIR:-/tmp}/monas-device2.XXXXXX")}"
GW_PORT="${MONAS_API_PORT2:-3001}"

echo "second device: gateway :$GW_PORT, persistence $PERSIST"

MONAS_API_PORT="$GW_PORT" \
MONAS_STATE_NODE_URL="$STATE_NODE" \
MONAS_PERSISTENCE_DIR="$PERSIST" \
  exec "$ROOT/target/debug/monas-gateway"
