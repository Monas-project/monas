use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::content_service::{
    ContentEncryptionKeyStore, ContentEncryptionKeyStoreError,
};
use crate::domain::{content::encryption::ContentEncryptionKey, content_id::ContentId};

/// プロセス内の `HashMap` に CEK を保存するインメモリ実装。
///
/// - 永続化は行わず、プロセス終了とともに破棄される。
/// - ローカル開発やテスト、PoC 用途を想定。
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

/// sled を用いた CEK ストア実装。
///
/// - キー: `content_id.as_str()`（UTF-8 文字列）
/// - 値: CEK のバイト列（`ContentEncryptionKey.0`）
//
// NOTE: sled 実装はあくまでローカル用の暫定実装であり、
//       本番環境では別の KVS / ストレージに置き換える可能性がある。
pub struct SledContentEncryptionKeyStore {
    db: sled::Db,
}

impl SledContentEncryptionKeyStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ContentEncryptionKeyStoreError> {
        let db =
            sled::open(path).map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        Ok(Self { db })
    }
}

impl ContentEncryptionKeyStore for SledContentEncryptionKeyStore {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError> {
        self.db
            .insert(content_id.as_str(), key.0.clone())
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
        let opt = self
            .db
            .get(content_id.as_str())
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

        Ok(opt.map(|ivec| ContentEncryptionKey(ivec.to_vec())))
    }

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError> {
        self.db
            .remove(content_id.as_str())
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;
        Ok(())
    }
}
