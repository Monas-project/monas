//! Presentation layer (API router).
//!
//! Compiled only when the `filesync` feature is enabled.

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

/// Per-file write lock.
///
/// There is one record, CEK, and share setting per file key, and update, delete, re-encrypt,
/// share, and revoke each "read and write back". If writes to the same file run concurrently,
/// the last writes of the record and the CEK can come from different requests
/// (e.g. the body from an update + the new CEK from a re-encrypt makes it undecryptable). Like
/// the SDK's per-file lock, this serializes writes to the same file.
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

/// On drop, removes its own entry from the table (if no one is waiting). The table grows only up
/// to the number of files being written.
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
        // If only the table and this guard hold it, there are no other holders or waiters.
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
    // Create the common infra implementations and share them between ContentService / ShareService.
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
