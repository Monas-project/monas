#!/bin/bash

# Monas State Node - クリーンアップスクリプト
# 実行中のノードを停止し、データファイルを削除します

set -e

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ログ関数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# State Nodeディレクトリに移動
STATE_NODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STATE_NODE_DIR"

log_info "State Nodeディレクトリ: $STATE_NODE_DIR"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     State Node クリーンアップ開始      ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# PIDファイルの確認
PID_FILE="$STATE_NODE_DIR/.local-nodes.pids"

# 実行中のノードを停止
if [ -f "$PID_FILE" ]; then
    log_info "実行中のノードを停止しています..."

    while IFS= read -r pid; do
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                log_info "PID $pid のプロセスを停止します..."
                kill "$pid" 2>/dev/null || true

                # プロセスが終了するのを待つ（最大5秒）
                for i in {1..10}; do
                    if ! kill -0 "$pid" 2>/dev/null; then
                        log_info "PID $pid が停止しました"
                        break
                    fi
                    if [ $i -eq 10 ]; then
                        log_warn "PID $pid の通常停止に失敗しました。強制終了します..."
                        kill -9 "$pid" 2>/dev/null || true
                    fi
                    sleep 0.5
                done
            else
                log_info "PID $pid は既に停止しています"
            fi
        fi
    done < "$PID_FILE"

    rm -f "$PID_FILE"
    log_info "PIDファイルを削除しました"
else
    log_info "PIDファイルが見つかりません。実行中のノードはないようです"
fi

# ポートが使用されているか確認
log_info "ポートの使用状況を確認しています..."
for port in 8080 8081 8082; do
    if lsof -i:$port > /dev/null 2>&1; then
        log_warn "ポート $port がまだ使用されています"
        # ポートを使用しているプロセスを表示
        lsof -i:$port || true
    else
        log_info "ポート $port は解放されています"
    fi
done

# データディレクトリの削除
if [ "$1" = "--all" ] || [ "$1" = "--data" ]; then
    log_warn "データディレクトリを削除しています..."

    for node in node1 node2 node3; do
        if [ -d "data/$node" ]; then
            rm -rf "data/$node"
            log_info "data/$node を削除しました"
        else
            log_info "data/$node は存在しません"
        fi
    done

    # dataディレクトリが空なら削除
    if [ -d "data" ]; then
        if [ -z "$(ls -A data 2>/dev/null)" ]; then
            rmdir "data"
            log_info "dataディレクトリを削除しました"
        fi
    fi
else
    log_info "データディレクトリは保持されます (削除する場合は --data オプションを使用)"
fi

# ログファイルの削除
if [ "$1" = "--all" ] || [ "$1" = "--logs" ]; then
    log_warn "ログファイルを削除しています..."

    if [ -d "logs" ]; then
        rm -f logs/node*.log
        log_info "ログファイルを削除しました"

        # logsディレクトリが空なら削除
        if [ -z "$(ls -A logs 2>/dev/null)" ]; then
            rmdir "logs"
            log_info "logsディレクトリを削除しました"
        fi
    else
        log_info "logsディレクトリは存在しません"
    fi
else
    log_info "ログファイルは保持されます (削除する場合は --logs オプションを使用)"
fi

# すべて削除
if [ "$1" = "--all" ]; then
    log_info "すべてのテストデータがクリーンアップされました"
fi

# プロセスの確認
log_info "残存プロセスを確認しています..."
remaining_processes=false

for pattern in "state-node" "state_node"; do
    if pgrep -f "$pattern" > /dev/null 2>&1; then
        log_warn "まだ実行中の $pattern プロセスがあります:"
        pgrep -f "$pattern" -l || true
        remaining_processes=true
    fi
done

if [ "$remaining_processes" = false ]; then
    log_info "State Node関連のプロセスはすべて停止しています"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}      クリーンアップが完了しました      ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 使用方法の表示
if [ -z "$1" ]; then
    echo "使用方法:"
    echo "  $0           # ノードの停止のみ"
    echo "  $0 --data    # ノードの停止とデータ削除"
    echo "  $0 --logs    # ノードの停止とログ削除"
    echo "  $0 --all     # すべて削除（データとログ）"
    echo ""
fi

exit 0