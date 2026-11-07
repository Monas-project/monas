use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::{PublicKeyDirectory, PublicKeyDirectoryError};
use crate::domain::share::KeyId;
use sha2::{Digest, Sha256};

/// In-memory public key directory implementation for tests and PoCs.
///
/// - key: `KeyId` (the raw bytes)
/// - value: public key bytes for HPKE (e.g. P-256 uncompressed)
#[derive(Clone, Default)]
pub struct InMemoryPublicKeyDirectory {
    inner: Arc<Mutex<HashMap<KeyId, Vec<u8>>>>,
}

impl InMemoryPublicKeyDirectory {
    /// Helper for registering with an explicitly specified KeyId (mainly for tests).
    pub fn insert(&self, key_id: KeyId, public_key: Vec<u8>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key_id, public_key);
        }
    }
}

impl InMemoryPublicKeyDirectory {
    /// Computes the KeyId from the first 16 bytes of SHA-256.
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

/// Public key directory implementation backed by sled.
///
/// - Key: `"pubkey:{hex(key_id.as_bytes())}"` (UTF-8 string)
/// - Value: public key bytes for HPKE
///
/// NOTE:
/// - The key space is separated by the `"pubkey:"` prefix.
#[derive(Clone)]
pub struct SledPublicKeyDirectory {
    db: sled::Db,
}

impl SledPublicKeyDirectory {
    /// Opens a sled DB at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, PublicKeyDirectoryError> {
        let db = sled::open(path).map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
        Ok(Self { db })
    }

    /// Builds an instance that shares an existing `sled::Db` handle.
    ///
    /// Use this when sharing the same sled DB with `SledContentEncryptionKeyStore` /
    /// `SledShareRepository` (the key space is separated by the `pubkey:` prefix).
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
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
