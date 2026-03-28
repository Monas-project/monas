use crate::infrastructure::key_pair::KeyAlgorithm;

#[derive(Clone)]
pub struct StoredAccountKey {
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub trait AccountKeyStore {
    fn save(&self, key: &StoredAccountKey) -> Result<(), AccountKeyStoreError>;
    fn load(&self) -> Result<Option<StoredAccountKey>, AccountKeyStoreError>;
    fn delete(&self) -> Result<(), AccountKeyStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AccountKeyStoreError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid key data: {0}")]
    InvalidKeyData(String),
}
