//! プレゼンテーション層（API ルーター）。
//!
//! `filesync` feature が有効な場合のみコンパイルされる。

#![cfg(feature = "filesync")]

use std::sync::Arc;

use axum::{routing::get, Router};

use crate::{
    application_service::{
        content_service::{
            ContentCreatedOperation, ContentDeletedOperation, ContentService,
            ContentUpdatedOperation, StateNodeClient, StateNodeClientError,
        },
        share_service::ShareService,
    },
    infrastructure::{
        content_id::Sha256ContentIdGenerator,
        encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
        key_store::InMemoryContentEncryptionKeyStore,
        key_wrapping::HpkeV1KeyWrapping,
        public_key_directory::InMemoryPublicKeyDirectory,
        share_repository::InMemoryShareRepository,
        MultiStorageRepository,
    },
};

mod content;
mod share;

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
            MultiStorageRepository,
            NoopStateNodeClient,
            OsRngContentEncryptionKeyGenerator,
            Aes256CtrContentEncryption,
            InMemoryContentEncryptionKeyStore,
        >,
    >,
    pub share_service: Arc<
        ShareService<
            InMemoryShareRepository,
            MultiStorageRepository,
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
    let registry = Arc::new(monas_filesync::init_registry_default());
    let content_repository = MultiStorageRepository::in_memory(registry, "local");

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
