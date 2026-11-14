use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::content_service::{
    ContentEncryptionKeyStore, ContentEncryptionKeyStoreError,
};
use crate::domain::{content::encryption::ContentEncryptionKey, content_id::ContentId};

/// In-memory implementation that stores CEKs in an in-process `HashMap`.
///
/// - Not persisted; discarded when the process exits.
/// - Intended for local development, tests, and PoCs.
#[derive(Clone, Default)]
pub struct InMemoryContentEncryptionKeyStore {
    inner: Arc<Mutex<HashMap<String, ContentEncryptionKey>>>,
}

impl ContentEncryptionKeyStore for InMemoryContentEncryptionKeyStore {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

        guard.insert(content_id.as_str().to_string(), key.clone());
        Ok(())
    }

    fn load(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

        Ok(guard.get(content_id.as_str()).cloned())
    }

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

        guard.remove(content_id.as_str());
        Ok(())
    }
}

/// CEK store implementation backed by sled.
///
/// - Key: `"cek:{content_id.as_str()}"` (UTF-8 string)
/// - Value: CEK bytes (`ContentEncryptionKey.0`)
///
/// NOTE:
/// - Even when sharing the same DB file with other sled-based stores (e.g. `SledShareRepository`),
///   the key space is separated by the prefix.
/// - The sled implementation is only a provisional, local-use implementation;
///   it may be replaced by another KVS / storage in production.
pub struct SledContentEncryptionKeyStore {
    db: sled::Db,
}

impl SledContentEncryptionKeyStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ContentEncryptionKeyStoreError> {
        let db =
            sled::open(path).map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    /// Builds an instance that shares an existing `sled::Db` handle.
    ///
    /// sled takes an exclusive flock per path, so the same process cannot `sled::open` the same
    /// directory twice. To colocate the CEK store and the Share repository in the same DB file,
    /// `sled::open` once on the outside and pass the resulting `sled::Db` through this
    /// constructor.
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
    }
}

impl ContentEncryptionKeyStore for SledContentEncryptionKeyStore {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError> {
        let sled_key = format!("cek:{}", content_id.as_str());
        self.db
            .insert(sled_key, key.0.clone())
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn load(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError> {
        let sled_key = format!("cek:{}", content_id.as_str());
        let opt = self
            .db
            .get(sled_key)
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

        Ok(opt.map(|ivec| ContentEncryptionKey(ivec.to_vec())))
    }

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError> {
        let sled_key = format!("cek:{}", content_id.as_str());
        self.db
            .remove(sled_key)
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        Ok(())
    }
}
