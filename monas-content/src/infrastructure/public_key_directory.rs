use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::{PublicKeyDirectory, PublicKeyDirectoryError};
use crate::domain::share::KeyId;
use sha2::{Digest, Sha256};

/// テストや PoC 用のインメモリ公開鍵ディレクトリ実装。
///
/// - key: `KeyId`（バイト列そのもの）
/// - value: HPKE 用の公開鍵バイト列（P-256 の uncompressed など）
#[derive(Clone, Default)]
pub struct InMemoryPublicKeyDirectory {
    inner: Arc<Mutex<HashMap<KeyId, Vec<u8>>>>,
}

impl InMemoryPublicKeyDirectory {
    /// 直接 KeyId を指定して登録したい場合のヘルパ（主にテスト用）。
    pub fn insert(&self, key_id: KeyId, public_key: Vec<u8>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key_id, public_key);
        }
    }
}

impl InMemoryPublicKeyDirectory {
    /// SHA-256 の先頭 16 バイトから KeyId を計算する。
    fn hash_to_key_id(public_key: &[u8]) -> KeyId {
        let digest = Sha256::digest(public_key);
        let id_bytes = digest[..16].to_vec();
        KeyId::new(id_bytes)
    }
}

impl PublicKeyDirectory for InMemoryPublicKeyDirectory {
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId {
        Self::hash_to_key_id(public_key)
    }

    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
        let key_id = Self::hash_to_key_id(public_key);

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;

        guard.insert(key_id.clone(), public_key.to_vec());
        Ok(key_id)
    }

    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;

        Ok(guard.get(key_id).cloned())
    }

    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;

        guard.remove(key_id);
        Ok(())
    }
}

/// sled を用いた公開鍵ディレクトリ実装。
///
/// - キー: `"pubkey:{hex(key_id.as_bytes())}"`（UTF-8 文字列）
/// - 値: HPKE 用の公開鍵バイト列
///
/// NOTE:
/// - `"pubkey:"` プレフィックスによりキー空間を分離している。
#[derive(Clone)]
pub struct SledPublicKeyDirectory {
    db: sled::Db,
}

impl SledPublicKeyDirectory {
    /// 指定されたパスに sled DB を開く。
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, PublicKeyDirectoryError> {
        let db = sled::open(path).map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
        Ok(Self { db })
    }

    fn make_key(key_id: &KeyId) -> String {
        format!("pubkey:{}", hex::encode(key_id.as_bytes()))
    }

    fn compute_key_id_internal(public_key: &[u8]) -> KeyId {
        let digest = Sha256::digest(public_key);
        let id_bytes = digest[..16].to_vec();
        KeyId::new(id_bytes)
    }
}

impl PublicKeyDirectory for SledPublicKeyDirectory {
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId {
        Self::compute_key_id_internal(public_key)
    }

    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
        let key_id = Self::compute_key_id_internal(public_key);
        let sled_key = Self::make_key(&key_id);

        self.db
            .insert(sled_key, public_key)
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;

        Ok(key_id)
    }

    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError> {
        let sled_key = Self::make_key(key_id);
        let opt = self
            .db
            .get(sled_key)
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;

        Ok(opt.map(|ivec| ivec.to_vec()))
    }

    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError> {
        let sled_key = Self::make_key(key_id);
        self.db
            .remove(sled_key)
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
        Ok(())
    }
}
