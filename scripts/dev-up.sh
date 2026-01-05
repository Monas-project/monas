#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"${ROOT_DIR}/scripts/state-node-up.sh"
"${ROOT_DIR}/scripts/gateway-up.sh"

echo ""
echo "OK:"
echo "- monas-state-node log: ${ROOT_DIR}/.dev/logs/state-node.log"
echo "- monas-gateway   log: ${ROOT_DIR}/.dev/logs/monas-gateway.log"
echo ""
echo "Try:"
echo "  curl http://127.0.0.1:${MONAS_API_PORT:-3000}/health"
echo ""
echo "Stop:"
echo "  ${ROOT_DIR}/scripts/dev-down.sh"


