#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STATE_NODE_LISTEN="${STATE_NODE_LISTEN:-127.0.0.1:8080}"
MONAS_API_PORT="${MONAS_API_PORT:-3000}"
MONAS_STATE_NODE_URL="${MONAS_STATE_NODE_URL:-http://${STATE_NODE_LISTEN}}"

cd "${ROOT_DIR}"
export MONAS_STATE_NODE_URL
export MONAS_API_PORT
exec cargo run -p monas-gateway


