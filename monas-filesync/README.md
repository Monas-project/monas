# Monas Filesync 利用ガイド

`monas-filesync` は Google Drive / OneDrive / IPFS / ローカルなど複数ストレージを同じ API で扱うためのライブラリです。本ドキュメントでは設定ファイルの用意から環境変数によるシークレット注入までをまとめます。

## クイックスタート

1. 雛形コピー  
   ```bash
   cd monas-filesync
   cp filesync.toml.example filesync.toml
   ```
2. `filesync.toml` を編集して各プロバイダのブロックを設定  
3. クラウド連携を使う場合は `cloud-connectivity` フィーチャーを有効化  
   ```bash
   cargo test -p monas-filesync --features cloud-connectivity
   ```
4. 実行コードで `FilesyncConfig::from_file_with_env("filesync.toml")?` を呼び、`Registry` (`src/infrastructure/registry.rs`) に渡す

## 設定ブロック

`filesync.toml` は `src/infrastructure/config.rs` に定義された `FilesyncConfig` の構造に従います。

### `[ipfs]`
- `gateway`: IPFS コンテンツを取得する際の HTTP ゲートウェイ URL（デフォルト `https://ipfs.io`）。

### `[google_drive]`
- `api_endpoint`: Google Drive API のベース URL（デフォルト `https://www.googleapis.com/drive/v3`）。
- `client_id` / `client_secret`: 将来の OAuth フロー用の任意項目。自前の認証を組み込む場合のみ設定します。
- 実際のアクセストークンは実行時の `AuthSession.access_token` から渡されます。

### `[onedrive]`
- `api_endpoint`: Microsoft Graph API のベース URL（デフォルト `https://graph.microsoft.com/v1.0`）。
- `client_id` / `client_secret`: こちらも任意項目。現状は設定できるだけでプロバイダ側ではまだ利用していません。

### `[local]`
- `base_path`: 任意のルートパス。指定すると `local://foo/bar.txt` といった相対 URI がこのディレクトリ配下に解決されます。未指定なら URI のパスをそのまま使用します。

## 環境変数による上書き

シークレットや環境依存の値は `filesync.toml` に書かず、以下の環境変数で上書きできます。未設定の場合はファイル値（もしくはデフォルト値）が利用されます。

| 環境変数 | 対応フィールド |
| --- | --- |
| `MONAS_IPFS_GATEWAY` | `ipfs.gateway` |
| `MONAS_GOOGLE_DRIVE_API_ENDPOINT` | `google_drive.api_endpoint` |
| `MONAS_GOOGLE_DRIVE_CLIENT_ID` | `google_drive.client_id` |
| `MONAS_GOOGLE_DRIVE_CLIENT_SECRET` | `google_drive.client_secret` |
| `MONAS_ONEDRIVE_API_ENDPOINT` | `onedrive.api_endpoint` |
| `MONAS_ONEDRIVE_CLIENT_ID` | `onedrive.client_id` |
| `MONAS_ONEDRIVE_CLIENT_SECRET` | `onedrive.client_secret` |
| `MONAS_LOCAL_BASE_PATH` | `local.base_path` |

実行例:

```bash
export MONAS_GOOGLE_DRIVE_CLIENT_ID="xxx.apps.googleusercontent.com"
export MONAS_GOOGLE_DRIVE_CLIENT_SECRET="super-secret"
export MONAS_LOCAL_BASE_PATH="/srv/monas-files"
```

```rust
use monas_filesync::infrastructure::config::FilesyncConfig;

let config = FilesyncConfig::from_file_with_env("filesync.toml")?;
// もしくはファイルを使わず環境変数だけで構築したい場合
let config = FilesyncConfig::from_env();
```

## `FilesyncConfig` の主要 API

- `from_file(path) -> Result<Self, ConfigError>`  
  指定パスの TOML を読み込む基本メソッド。

- `from_file_with_env(path) -> Result<Self, ConfigError>`  
  ファイル読込後に `apply_env_overrides` を実行。設定ファイルと環境変数を併用する場合はこちら。

- `from_env() -> Self`  
  ファイルレスでデフォルト＋環境変数だけから構築。

- `from_toml_str(src) -> Result<Self, ConfigError>`  
  文字列から直接パース。テストや外部ストレージからの読込に便利。

- `to_file(path) -> Result<(), ConfigError>`  
  現在の設定を TOML として書き出す。

- `apply_env_overrides(&mut self)`  
  既存の `FilesyncConfig` に環境変数を適用。CI/CD で直前にシークレットを差し替える用途などに使います。

いずれのメソッドも `ConfigError` を返すので、`?` 演算子や `match` でエラーハンドリングしてください。

## シークレット運用の推奨フロー

1. OAuth クライアント ID/Secret やアクセストークンは Secret Manager や環境変数に保存  
2. プロセス起動時に `MONAS_*` 環境変数として注入  
3. `FilesyncConfig::from_file_with_env`（または `from_env`）を呼び、`Registry` へ設定を渡す  
4. 実際の API 呼び出しでは `AuthSession.access_token` に有効なトークンをセットして各プロバイダを利用

この構成にすれば、設定ファイルをリポジトリに置いたままでもシークレットは外部で安全に管理できます。
