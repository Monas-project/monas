#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="${ROOT_DIR}/.dev"
LOG_DIR="${DEV_DIR}/logs"
PID_DIR="${DEV_DIR}/pids"

mkdir -p "${LOG_DIR}" "${PID_DIR}"

STATE_NODE_LISTEN="${STATE_NODE_LISTEN:-127.0.0.1:8080}"
MONAS_API_PORT="${MONAS_API_PORT:-3000}"
MONAS_STATE_NODE_URL="${MONAS_STATE_NODE_URL:-http://${STATE_NODE_LISTEN}}"

echo "Starting monas-gateway on 127.0.0.1:${MONAS_API_PORT} (MONAS_STATE_NODE_URL=${MONAS_STATE_NODE_URL})"
(
  cd "${ROOT_DIR}"
  export MONAS_STATE_NODE_URL
  export MONAS_API_PORT
  exec cargo run -p monas-gateway
) >"${LOG_DIR}/monas-gateway.log" 2>&1 &
echo $! >"${PID_DIR}/monas-gateway.pid"

echo "OK: monas-gateway pid=$(cat "${PID_DIR}/monas-gateway.pid") log=${LOG_DIR}/monas-gateway.log"


