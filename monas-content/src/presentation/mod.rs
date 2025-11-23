use std::sync::Arc;

use axum::{routing::get, Router};

use crate::{
    application_service::{content_service::ContentService, share_service::ShareService},
    infrastructure::{
        content_id::Sha256ContentIdGenerator,
        encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
        key_store::InMemoryContentEncryptionKeyStore,
        key_wrapping::HpkeV1KeyWrapping,
        public_key_directory::InMemoryPublicKeyDirectory,
        repository::InMemoryContentRepository,
        share_repository::InMemoryShareRepository,
        state_node_client::NoopStateNodeClient,
    },
};

mod content;
mod share;

#[derive(Clone)]
pub struct AppState {
    pub content_service: Arc<
        ContentService<
            Sha256ContentIdGenerator,
            InMemoryContentRepository,
            NoopStateNodeClient,
            OsRngContentEncryptionKeyGenerator,
            Aes256CtrContentEncryption,
            InMemoryContentEncryptionKeyStore,
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
