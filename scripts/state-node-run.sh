#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_NODE_LISTEN="${STATE_NODE_LISTEN:-127.0.0.1:8080}"

cd "${ROOT_DIR}"
exec cargo run -p monas-state-node --bin state-node -- -l "${STATE_NODE_LISTEN}"


