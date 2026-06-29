#!/bin/bash

# Monas State Node - BFT検証向け停止スクリプト
# start-local-nodes-bft.sh で起動したノードのみを対象に停止する。

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

PID_FILE="$STATE_NODE_DIR/.local-nodes-bft.pids"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     BFTノード停止を開始します         ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ ! -f "$PID_FILE" ]; then
    log_warn "PIDファイルが見つかりません: $PID_FILE"
    log_warn "ポート解放確認のみ行います"
else
    while IFS= read -r pid; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_info "PID $pid を停止します..."
            kill "$pid" 2>/dev/null || true
            sleep 0.3
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "PID $pid を強制終了します"
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
    done < "$PID_FILE"

    rm -f "$PID_FILE"
    log_info "PIDファイルを削除しました"
fi

for port in 8080 8081 8082 8083; do
    if lsof -i:"$port" > /dev/null 2>&1; then
        log_warn "ポート $port はまだ使用中です"
        lsof -i:"$port" || true
    else
        log_info "ポート $port は解放済みです"
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     BFTノード停止が完了しました       ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
