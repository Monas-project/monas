use std::collections::HashMap;
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

impl PublicKeyDirectory for InMemoryPublicKeyDirectory {
    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
        // シンプルに SHA-256 の先頭 16 バイトを KeyId として利用する。
        let digest = Sha256::digest(public_key);
        let id_bytes = digest[..16].to_vec();
        let key_id = KeyId::new(id_bytes);

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
}
