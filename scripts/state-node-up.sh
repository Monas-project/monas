#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="${ROOT_DIR}/.dev"
LOG_DIR="${DEV_DIR}/logs"
PID_DIR="${DEV_DIR}/pids"

mkdir -p "${LOG_DIR}" "${PID_DIR}"

STATE_NODE_LISTEN="${STATE_NODE_LISTEN:-127.0.0.1:8080}"

echo "Starting monas-state-node on ${STATE_NODE_LISTEN}"
(
  cd "${ROOT_DIR}"
  exec cargo run -p monas-state-node --bin state-node -- -l "${STATE_NODE_LISTEN}"
) >"${LOG_DIR}/state-node.log" 2>&1 &
echo $! >"${PID_DIR}/state-node.pid"

echo "OK: state-node pid=$(cat "${PID_DIR}/state-node.pid") log=${LOG_DIR}/state-node.log"


