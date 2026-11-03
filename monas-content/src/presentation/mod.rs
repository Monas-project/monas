//! プレゼンテーション層（API ルーター）。
//!
//! `filesync` feature が有効な場合のみコンパイルされる。

#![cfg(feature = "filesync")]

use std::sync::Arc;

use axum::{routing::get, Router};

use crate::{
    application_service::{content_service::ContentService, share_service::ShareService},
    infrastructure::{
        content_id::Sha256ContentIdGenerator,
        encryption::{Aes256GcmContentEncryption, OsRngContentEncryptionKeyGenerator},
        key_store::InMemoryContentEncryptionKeyStore,
        key_wrapping::HpkeV1KeyWrapping,
        public_key_directory::InMemoryPublicKeyDirectory,
        share_repository::InMemoryShareRepository,
        MultiStorageRepository,
    },
};

mod base64_helpers;
mod content;
mod share;

use base64_helpers::{
    decode_base64, decode_base64_optional, decode_cek_base64, decode_key_id_base64,
};

/// ファイル単位の書き込みロック。
///
/// 記録・CEK・共有設定はファイルのキーごとに 1 件で、更新・削除・再暗号化・
/// 共有・revoke はそれぞれ「読んで書き戻す」。同じファイルへの書き込みが
/// 並行すると、記録と CEK の最後の書き込みが別々の要求のものになり得る
/// (例: 更新の本文 + 再暗号化の新 CEK で復号できなくなる)。SDK のファイル
/// 単位ロックと同じく、同じファイルへの書き込みを 1 つずつにする。
#[derive(Default)]
struct FileLocks {
    held: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl FileLocks {
    async fn lock(&self, file_id: &str) -> FileLockGuard<'_> {
        let mutex = {
            let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
            held.entry(file_id.to_string()).or_default().clone()
        };
        let guard = mutex.clone().lock_owned().await;
        FileLockGuard {
            locks: self,
            file_id: file_id.to_string(),
            mutex,
            _guard: Some(guard),
        }
    }
}

/// drop で表から自分のエントリを消す(誰も待っていなければ)。表は書き込み中の
/// ファイル数までしか伸びない。
struct FileLockGuard<'a> {
    locks: &'a FileLocks,
    file_id: String,
    mutex: Arc<tokio::sync::Mutex<()>>,
    _guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for FileLockGuard<'_> {
    fn drop(&mut self) {
        self._guard.take();
        let mut held = self.locks.held.lock().unwrap_or_else(|p| p.into_inner());
        // 表と自分の分だけなら、他に保持者も待機者もいない。
        if Arc::strong_count(&self.mutex) == 2 {
            held.remove(&self.file_id);
        }
    }
}

#[derive(Clone)]
struct AppState {
    file_locks: Arc<FileLocks>,
    pub content_service: Arc<
        ContentService<
            Sha256ContentIdGenerator,
            MultiStorageRepository,
            OsRngContentEncryptionKeyGenerator,
            Aes256GcmContentEncryption,
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
        key_generator: OsRngContentEncryptionKeyGenerator,
        encryptor: Aes256GcmContentEncryption,
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
        file_locks: Arc::new(FileLocks::default()),
        content_service: Arc::new(content_service),
        share_service: Arc::new(share_service),
    });

    Router::new()
        .route("/health", get(health))
        .merge(content::routes())
        .merge(share::routes())
        .with_state(state)
}
