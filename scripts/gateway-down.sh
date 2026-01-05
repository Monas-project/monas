#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/.dev/pids"
pid_file="${PID_DIR}/monas-gateway.pid"

if [[ -f "${pid_file}" ]]; then
  pid="$(cat "${pid_file}")"
  if kill -0 "${pid}" >/dev/null 2>&1; then
    echo "Stopping monas-gateway (pid=${pid})"
    kill "${pid}" || true
  else
    echo "monas-gateway not running (pid=${pid})"
  fi
  rm -f "${pid_file}"
else
  echo "No pid file for monas-gateway"
fi


