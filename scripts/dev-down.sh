#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/.dev/pids"

kill_if_running() {
  local name="$1"
  local pid_file="${PID_DIR}/${name}.pid"
  if [[ -f "${pid_file}" ]]; then
    local pid
    pid="$(cat "${pid_file}")"
    if kill -0 "${pid}" >/dev/null 2>&1; then
      echo "Stopping ${name} (pid=${pid})"
      kill "${pid}" || true
    else
      echo "${name} not running (pid=${pid})"
    fi
    rm -f "${pid_file}"
  else
    echo "No pid file for ${name}"
  fi
}

"${ROOT_DIR}/scripts/gateway-down.sh" || true
"${ROOT_DIR}/scripts/state-node-down.sh" || true

echo "Done."


