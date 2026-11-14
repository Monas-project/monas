use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::{ShareRepository, ShareRepositoryError};
use crate::domain::content_id::ContentId;
use crate::domain::share::Share;

/// Simple in-memory ShareRepository implementation.
///
/// - key: `content_id.as_str()`
/// - value: `Share`
#[derive(Clone, Default)]
pub struct InMemoryShareRepository {
    inner: Arc<Mutex<HashMap<String, Share>>>,
}

impl ShareRepository for InMemoryShareRepository {
    fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        Ok(guard.get(content_id.as_str()).cloned())
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        guard.insert(share.content_id().as_str().to_string(), share.clone());
        Ok(())
    }
}

/// ShareRepository implementation backed by sled.
///
/// - Key: `"share:{content_id.as_str()}"` (UTF-8 string)
/// - Value: `Share` serialized as JSON bytes
///
/// NOTE:
/// - Assumes it **may share the same DB file** with other sled-based stores such as the CEK store,
///   so the key space is separated by the `"share:"` prefix.
#[derive(Clone)]
pub struct SledShareRepository {
    db: sled::Db,
}

impl SledShareRepository {
    /// Opens a sled DB at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ShareRepositoryError> {
        let db = sled::open(path).map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    /// Builds an instance that shares an existing `sled::Db` handle.
    ///
    /// Use this to share the same DB file with the CEK store
    /// (pass the same `sled::Db` as to `SledContentEncryptionKeyStore::with_db`).
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
    }
}

impl ShareRepository for SledShareRepository {
    fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        let sled_key = format!("share:{}", content_id.as_str());
        let opt = self
            .db
            .get(sled_key)
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        if let Some(ivec) = opt {
            let share: Share = serde_json::from_slice(&ivec)
                .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
            Ok(Some(share))
        } else {
            Ok(None)
        }
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        let key = format!("share:{}", share.content_id().as_str());
        let value =
            serde_json::to_vec(share).map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        self.db
            .insert(key, value)
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        Ok(())
    }
}
