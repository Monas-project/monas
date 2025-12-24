use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::account_service::{
    AccountKeyStore, AccountKeyStoreError, StoredAccountKey,
};

/// プロセス内の `AccountKeyMaterial` を保存するインメモリ実装。
///
/// - 永続化は行わず、プロセス終了とともに破棄される。
/// - ローカル開発やテスト、PoC 用途を想定。
#[derive(Clone, Default)]
pub struct InMemoryAccountKeyStore {
    inner: Arc<Mutex<Option<StoredAccountKey>>>,
}

impl AccountKeyStore for InMemoryAccountKeyStore {
    fn save(&self, key: &StoredAccountKey) -> Result<(), AccountKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;

        *guard = Some(key.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<StoredAccountKey>, AccountKeyStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;

        Ok(guard.clone())
    }

    fn delete(&self) -> Result<(), AccountKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;

        *guard = None;
        Ok(())
    }
}

/// sled を用いたアカウント鍵ストア実装。
///
/// - キー: 固定文字列 `"account:signing_key"`（UTF-8 文字列）
/// - 値: 1 バイトのアルゴリズム識別子 + 公開鍵バイト列(65バイト) + 秘密鍵バイト列(32バイト)
pub struct SledAccountKeyStore {
    db: sled::Db,
}

impl SledAccountKeyStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AccountKeyStoreError> {
        let db = sled::open(path).map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    fn sled_key() -> &'static str {
        "account:signing_key"
    }
}

impl AccountKeyStore for SledAccountKeyStore {
    fn save(&self, key: &StoredAccountKey) -> Result<(), AccountKeyStoreError> {
        use crate::infrastructure::key_pair::KeyAlgorithm;

        let alg_tag = match key.algorithm {
            KeyAlgorithm::K256 => 1u8,
            KeyAlgorithm::P256 => 2u8,
        };

        // 現状どちらのアルゴリズムも secp256 系で、
        // - public_key: 65 bytes
        // - secret_key: 32 bytes
        let mut value = Vec::with_capacity(1 + key.public_key.len() + key.secret_key.len());
        value.push(alg_tag);
        value.extend_from_slice(&key.public_key);
        value.extend_from_slice(&key.secret_key);

        self.db
            .insert(Self::sled_key(), value)
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;

        Ok(())
    }

    fn load(&self) -> Result<Option<StoredAccountKey>, AccountKeyStoreError> {
        use crate::infrastructure::key_pair::KeyAlgorithm;

        let opt = self
            .db
            .get(Self::sled_key())
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;

        let Some(ivec) = opt else {
            return Ok(None);
        };

        let bytes = ivec.as_ref();
        if bytes.len() < 1 + 65 + 32 {
            return Err(AccountKeyStoreError::InvalidKeyData(
                "value too short".to_string(),
            ));
        }

        let alg_tag = bytes[0];
        let algorithm = match alg_tag {
            1 => KeyAlgorithm::K256,
            2 => KeyAlgorithm::P256,
            other => {
                return Err(AccountKeyStoreError::InvalidKeyData(format!(
                    "unknown algorithm tag: {other}"
                )))
            }
        };

        let public_key = bytes[1..1 + 65].to_vec();
        let secret_key = bytes[1 + 65..].to_vec();

        Ok(Some(StoredAccountKey {
            algorithm,
            public_key,
            secret_key,
        }))
    }

    fn delete(&self) -> Result<(), AccountKeyStoreError> {
        self.db
            .remove(Self::sled_key())
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| AccountKeyStoreError::Storage(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_service::account_service::StoredAccountKey;
    use crate::infrastructure::key_pair::KeyAlgorithm;

    #[test]
    fn in_memory_store_save_load_delete() {
        let store = InMemoryAccountKeyStore::default();

        let stored = StoredAccountKey {
            algorithm: KeyAlgorithm::K256,
            public_key: vec![0; 65],
            secret_key: vec![1; 32],
        };

        // save
        store.save(&stored).unwrap();

        // load
        let loaded = store.load().unwrap().expect("should exist");
        assert_eq!(loaded.algorithm, stored.algorithm);
        assert_eq!(loaded.secret_key, stored.secret_key);

        // delete
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn sled_store_save_load_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("account_db");
        let store = SledAccountKeyStore::open(&path).expect("open sled");

        let stored = StoredAccountKey {
            algorithm: KeyAlgorithm::P256,
            public_key: vec![0; 65],
            // 実際の鍵サイズ(32バイト)に合わせてテストデータを用意する
            secret_key: vec![2; 32],
        };

        // save
        store.save(&stored).unwrap();

        // load
        let loaded = store.load().unwrap().expect("should exist");
        assert_eq!(loaded.algorithm, stored.algorithm);
        assert_eq!(loaded.secret_key, stored.secret_key);

        // delete
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
