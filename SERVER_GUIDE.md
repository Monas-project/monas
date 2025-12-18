# Monas Content サーバー起動ガイド

このガイドでは、monas-contentサーバーを起動して、コンテンツの作成・更新・取得を試す方法を説明します。

## クイックスタート

### 1. サーバーを起動

```bash
cd /Users/yu-da1/Desktop/myCode/monas
cargo run --bin monas-content
```

別のターミナルで、サーバーが起動していることを確認：

```bash
curl http://127.0.0.1:4001/health
# 応答: ok
```

### 2. テストスクリプトを実行

```bash
# jqが必要な場合: brew install jq
./test_server.sh
```

これで基本的な動作確認が完了します！

## 1. サーバーの起動

### 基本的な起動方法

```bash
# プロジェクトルートから実行
cd /Users/yu-da1/Desktop/myCode/monas
cargo run --bin monas-content
```

デフォルトでは `http://127.0.0.1:4001` でサーバーが起動します。

### ポート番号の変更

環境変数 `MONAS_CONTENT_PORT` でポート番号を変更できます：

```bash
MONAS_CONTENT_PORT=8080 cargo run --bin monas-content
```

## 2. 基本的なAPIの使い方

### ヘルスチェック

```bash
curl http://127.0.0.1:4001/health
# 応答: ok
```

### コンテンツの作成

```bash
curl -X POST http://127.0.0.1:4001/contents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-document",
    "path": "documents/test.txt",
    "content_base64": "'$(echo -n "Hello, World!" | base64)'"
  }'
```

**レスポンス例:**
```json
{
  "content_id": "5d6444d143d102cc1afb75a21259229d98a654afee2f2964153a959c2a280435",
  "name": "test-document",
  "path": "documents/test.txt",
  "status": "Active"
}
```

### コンテンツの取得（fetch）

```bash
# 上記で取得したcontent_idを使用
curl "http://127.0.0.1:4001/contents/5d6444d143d102cc1afb75a21259229d98a654afee2f2964153a959c2a280435/fetch"
```

**レスポンス例:**
```json
{
  "content_id": "5d6444d143d102cc1afb75a21259229d98a654afee2f2964153a959c2a280435",
  "series_id": "...",
  "name": "test-document",
  "path": "documents/test.txt",
  "status": "Active",
  "content_base64": "SGVsbG8sIFdvcmxkIQ=="
}
```

### コンテンツの更新

```bash
curl -X PATCH http://127.0.0.1:4001/contents/5d6444d143d102cc1afb75a21259229d98a654afee2f2964153a959c2a280435 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "updated-document",
    "content_base64": "'$(echo -n "Updated content!" | base64)'"
  }'
```

### コンテンツの削除

```bash
curl -X DELETE "http://127.0.0.1:4001/contents/5d6444d143d102cc1afb75a21259229d98a654afee2f2964153a959c2a280435"
```

## 3. Google Driveを使うための設定

### 3.1 Google Cloud ConsoleでOAuth認証情報を取得

1. [Google Cloud Console](https://console.cloud.google.com/)にアクセス
2. 新しいプロジェクトを作成（または既存のプロジェクトを選択）
3. 「APIとサービス」→「認証情報」に移動
4. 「認証情報を作成」→「OAuth クライアント ID」を選択
5. アプリケーションの種類を選択（デスクトップアプリまたはウェブアプリ）
6. クライアントIDとクライアントシークレットを取得

### 3.2 OAuth 2.0 アクセストークンの取得

Google Drive APIを使用するには、OAuth 2.0アクセストークンが必要です。

#### 方法1: Google OAuth Playgroundを使用（簡単）

1. [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)にアクセス
2. 左側の「Drive API v3」を選択
3. 必要なスコープを選択（例：`https://www.googleapis.com/auth/drive.file`）
4. 「Authorize APIs」をクリックして認証
5. 「Exchange authorization code for tokens」をクリック
6. 表示された「Access token」をコピー

#### 方法2: gcloud CLIを使用

```bash
# gcloud CLIをインストール（未インストールの場合）
# macOS: brew install google-cloud-sdk

# 認証
gcloud auth application-default login

# アクセストークンを取得
gcloud auth print-access-token
```

#### 方法3: プログラムで取得（推奨）

Pythonスクリプトを使用してアクセストークンを取得する例：

```python
# get_google_token.py
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os

SCOPES = ['https://www.googleapis.com/auth/drive.file']

def get_access_token():
    creds = None
    # token.json があれば読み込む
    if os.path.exists('token.json'):
        from google.oauth2.credentials import Credentials
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # 認証情報がない、または無効な場合は再認証
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # credentials.json をダウンロードして配置（Google Cloud Consoleから）
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # トークンを保存
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    return creds.token

if __name__ == '__main__':
    print(get_access_token())
```

必要なパッケージのインストール：
```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

### 3.3 サーバーにGoogle Driveを接続

取得したアクセストークンを使用して、API経由でGoogle Driveを接続できます：

```bash
curl -X POST http://127.0.0.1:4001/providers/google-drive/connect \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "ya29.a0AfH6SMBx..."
  }'
```

**レスポンス例:**
```json
{
  "provider": "google-drive",
  "message": "Successfully connected to google-drive"
}
```

### 3.4 接続済みプロバイダーの確認

接続済みのプロバイダー一覧を確認できます：

```bash
curl http://127.0.0.1:4001/providers
```

**レスポンス例:**
```json
{
  "providers": ["local", "google-drive"],
  "default_provider": "local"
}
```

### 3.5 プロバイダーの切断

不要になったプロバイダーを切断できます：

```bash
curl -X DELETE http://127.0.0.1:4001/providers/google-drive/disconnect
```

## 4. プロバイダー指定でのコンテンツ操作

特定のストレージプロバイダー（例：Google Drive）に保存する場合：

```bash
curl -X POST http://127.0.0.1:4001/contents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cloud-document",
    "path": "documents/cloud.txt",
    "content_base64": "'$(echo -n "Cloud content" | base64)'",
    "provider": "google-drive"
  }'
```

## 5. トラブルシューティング

### サーバーが起動しない

- Rustツールチェーンがインストールされているか確認: `rustc --version`
- 依存関係が正しくインストールされているか確認: `cargo build`

### Google Drive接続エラー

- アクセストークンが有効か確認（通常1時間で期限切れ）
- 必要なスコープが付与されているか確認
- `cloud-connectivity` featureが有効になっているか確認

### コンテンツが見つからない

- `content_id`が正しいか確認
- プロバイダーが正しく指定されているか確認（デフォルトは`local`）

## 6. 次のステップ

- Google Drive接続用のAPIエンドポイントを追加する
- アクセストークンの自動リフレッシュ機能を実装する
- 複数のストレージプロバイダーを管理するUIを追加する
