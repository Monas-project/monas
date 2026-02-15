#!/bin/bash

# Monas State Node - テスト用認証データ生成スクリプト
# P-256鍵ペア、AuthTokenトークン、リクエスト署名を生成します

set -e

# カラー出力の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

# バイナリのビルド
log_info "test-auth-generatorをビルドしています..."
cargo build --bin test-auth-generator 2>/dev/null || {
    log_error "ビルドに失敗しました。Cargoのエラーメッセージを確認してください。"
    cargo build --bin test-auth-generator
    exit 1
}

# cargo runコマンドを関数として定義
run_test_auth_generator() {
    cargo run --bin test-auth-generator -- "$@"
}

# コマンドの処理
if [ $# -eq 0 ] || [ "$1" == "help" ] || [ "$1" == "--help" ]; then
    echo ""
    echo -e "${BLUE}=== Test Auth Generator ===${NC}"
    echo ""
    echo "使用方法: $0 <command> [args...]"
    echo ""
    echo "コマンド:"
    echo "  generate-token [content_id]  - AuthTokenを生成"
    echo "  generate-signature <data>    - リクエスト署名を生成"
    echo "  generate-keys                - 新しいP-256鍵ペアを生成"
    echo "  test-auth                    - 完全なテスト認証データを生成"
    echo "  export                       - 環境変数として認証データをエクスポート"
    echo ""
    echo "例:"
    echo "  $0 test-auth                     # 完全なテスト認証データを生成"
    echo "  $0 generate-token content123     # 特定のコンテンツIDのトークン生成"
    echo "  $0 export > test-auth.env        # 環境変数ファイルとして保存"
    echo ""
    exit 0
fi

command="$1"
shift

case "$command" in
    "generate-token")
        log_info "AuthTokenを生成しています..."
        run_test_auth_generator generate-token "$@"
        ;;

    "generate-signature")
        if [ $# -eq 0 ]; then
            log_error "署名するデータを指定してください"
            exit 1
        fi
        log_info "リクエスト署名を生成しています..."
        run_test_auth_generator generate-signature "$@"
        ;;

    "generate-keys")
        log_info "P-256鍵ペアを生成しています..."
        run_test_auth_generator generate-keys
        ;;

    "test-auth")
        log_info "完全なテスト認証データを生成しています..."
        run_test_auth_generator test-auth
        ;;

    "export")
        # 環境変数形式でエクスポート（スクリプトから source できる形式）
        OUTPUT=$(run_test_auth_generator test-auth 2>&1)
        echo "$OUTPUT" | grep "^export " | while read line; do
            echo "$line"
        done
        echo ""
        echo "# 使用方法:"
        echo "# source <(./scripts/generate-test-auth.sh export)"
        echo "# または"
        echo "# ./scripts/generate-test-auth.sh export > test-auth.env"
        echo "# source test-auth.env"
        ;;

    *)
        log_error "未知のコマンド: $command"
        echo "詳細は '$0 help' を実行してください"
        exit 1
        ;;
esac