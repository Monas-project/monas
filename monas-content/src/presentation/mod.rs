use std::sync::Arc;

use axum::{routing::get, Router};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::{
    application_service::{
        content_service::{
            ContentCreatedOperation, ContentDeletedOperation, ContentService,
            ContentUpdatedOperation, StateNodeClient, StateNodeClientError,
        },
        share_service::ShareService,
    },
    domain::{
        content::encryption::ContentEncryptionKey,
        KeyId,
    },
    infrastructure::{
        content_id::Sha256ContentIdGenerator,
        encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
        key_store::InMemoryContentEncryptionKeyStore,
        key_wrapping::HpkeV1KeyWrapping,
        public_key_directory::InMemoryPublicKeyDirectory,
        repository::InMemoryContentRepository,
        share_repository::InMemoryShareRepository,
    },
};

mod content;
mod share;

// ============================================================================
// Base64デコードヘルパー関数
// ============================================================================

/// base64エンコードされたバイト列をデコードする汎用ヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされた文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたバイト列
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    BASE64_STANDARD.decode(base64_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {field_name}: {e}"),
        )
    })
}

/// base64エンコードされたKeyIdをデコードするヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされたKeyId文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたKeyId
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_key_id_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<KeyId, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(KeyId::new(bytes))
}

/// base64エンコードされたContentEncryptionKeyをデコードするヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされたCEK文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたContentEncryptionKey
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_cek_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<ContentEncryptionKey, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(ContentEncryptionKey(bytes))
}

/// base64エンコードされたバイト列をデコードするヘルパー関数（Option対応）。
///
/// # 引数
/// - `base64_str_opt`: base64エンコードされた文字列（Option）
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - `None`の場合: `Ok(None)`
/// - `Some(base64_str)`の場合: デコード結果を`Some`でラップ
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_base64_optional(
    base64_str_opt: Option<&str>,
    field_name: &str,
) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
    match base64_str_opt {
        Some(base64_str) => decode_base64(base64_str, field_name).map(Some),
        None => Ok(None),
    }
}

/// v1 用のダミー `StateNodeClient` 実装。
/// 実際には何も送信せず、ログ出力だけ行う想定のため、ここでは単に `Ok(())` を返す。
#[derive(Clone, Default)]
struct NoopStateNodeClient;

impl StateNodeClient for NoopStateNodeClient {
    fn send_content_created(
        &self,
        _operation: &ContentCreatedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }

    fn send_content_updated(
        &self,
        _operation: &ContentUpdatedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }

    fn send_content_deleted(
        &self,
        _operation: &ContentDeletedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    pub content_service: Arc<
        ContentService<
            Sha256ContentIdGenerator,
            InMemoryContentRepository,
            NoopStateNodeClient,
            OsRngContentEncryptionKeyGenerator,
            Aes256CtrContentEncryption,
            InMemoryContentEncryptionKeyStore,
            InMemoryShareRepository,
        >,
    >,
    pub share_service: Arc<
        ShareService<
            InMemoryShareRepository,
            InMemoryContentRepository,
            InMemoryContentEncryptionKeyStore,
            InMemoryPublicKeyDirectory,
            HpkeV1KeyWrapping,
        >,
    >,
}

async fn health() -> &'static str {
    "ok"
}

pub fn create_router() -> Router {
    // 共通の infra 実装を生成し、ContentService / ShareService の両方で共有する。
    let content_repository = InMemoryContentRepository::default();
    let cek_store = InMemoryContentEncryptionKeyStore::default();
    let public_key_directory = InMemoryPublicKeyDirectory::default();
    let share_repository = InMemoryShareRepository::default();

    let content_service = ContentService {
        content_id_generator: Sha256ContentIdGenerator,
        content_repository: content_repository.clone(),
        state_node_client: NoopStateNodeClient,
        key_generator: OsRngContentEncryptionKeyGenerator,
        encryptor: Aes256CtrContentEncryption,
        cek_store: cek_store.clone(),
        share_repository: share_repository.clone(),
    };

    let share_service = ShareService {
        share_repository,
        content_repository,
        cek_store,
        public_key_directory,
        key_wrapper: HpkeV1KeyWrapping,
    };

    let state = Arc::new(AppState {
        content_service: Arc::new(content_service),
        share_service: Arc::new(share_service),
    });

    Router::new()
        .route("/health", get(health))
        .merge(content::routes())
        .merge(share::routes())
        .with_state(state)
}
