use crate::domain::account::Account;
use crate::infrastructure::key_pair::{KeyAlgorithm, KeyPairError, KeyPairGenerateFactory};

#[derive(Debug, thiserror::Error)]
pub enum AccountServiceError {
    #[error("persistence error: {0}")]
    PersistenceError(String),

    #[error("key store error: {0}")]
    KeyStore(#[from] AccountKeyStoreError),
}

pub struct AccountService;

pub enum KeyTypeMapper {
    K256,
    P256,
}

impl From<KeyTypeMapper> for KeyAlgorithm {
    fn from(mapper: KeyTypeMapper) -> Self {
        match mapper {
            KeyTypeMapper::K256 => KeyAlgorithm::K256,
            KeyTypeMapper::P256 => KeyAlgorithm::P256,
        }
    }
}

impl AccountService {
    /// 鍵ペアを生成し、アカウントを構築したうえで必ず永続化するユースケース。
    pub fn create<S: AccountKeyStore>(
        store: &S,
        key_type: KeyTypeMapper,
    ) -> Result<Account, AccountServiceError> {
        let algorithm: KeyAlgorithm = key_type.into();
        let generated_key_pair = KeyPairGenerateFactory::generate(algorithm);
        let account = Account::new(generated_key_pair);

        let stored = StoredAccountKey {
            algorithm,
            public_key: account.public_key_bytes().to_vec(),
            secret_key: account.secret_key_bytes().to_vec(),
        };

        store.save(&stored)?;

        Ok(account)
    }

    pub fn delete<S: AccountKeyStore>(store: &S) -> Result<(), AccountServiceError> {
        store.delete()?;
        Ok(())
    }

    pub fn sign<S: AccountKeyStore>(
        store: &S,
        msg: &[u8],
    ) -> Result<(Vec<u8>, Option<u8>), SignError> {
        let stored = store.load()?.ok_or(SignError::NotFound)?;

        let key_pair = KeyPairGenerateFactory::from_key_bytes(
            stored.algorithm,
            &stored.public_key,
            &stored.secret_key,
        )?;

        let account = Account::new(key_pair);

        Ok(account.sign(msg))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("stored account key not found")]
    NotFound,
    #[error("key-store error: {0}")]
    KeyStore(#[from] AccountKeyStoreError),
    #[error("invalid secret key: {0}")]
    InvalidKey(#[from] KeyPairError),
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::key_store::InMemoryAccountKeyStore;

    #[test]
    fn create_k256_stores_valid_account() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);
    }

    #[test]
    fn create_p256_stores_valid_account() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);
    }

    #[test]
    fn sign_uses_stored_key() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        let msg = b"sign-test-message";

        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_account, _rec_id2) = account.sign(msg);

        assert_eq!(sig_from_service, sig_from_account);
    }

    #[test]
    fn sign_uses_stored_key_p256() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        let msg = b"sign-test-message-p256";

        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_account, _rec_id2) = account.sign(msg);

        assert_eq!(sig_from_service, sig_from_account);
    }

    // memo: 鍵自体は複数の管理可能になるかもしれないため以下のテストケースは削除される可能性がある。
    #[test]
    fn sign_uses_latest_created_key() {
        let store = InMemoryAccountKeyStore::default();

        AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        let msg = b"override-test-message";

        let account_latest = AccountService::create(&store, KeyTypeMapper::P256).unwrap();

        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_latest, _rec_id2) = account_latest.sign(msg);

        assert_eq!(sig_from_service, sig_from_latest);
    }

    #[test]
    fn sign_returns_not_found_if_key_missing() {
        let store = InMemoryAccountKeyStore::default();
        let err = AccountService::sign(&store, b"msg").unwrap_err();
        matches!(err, SignError::NotFound);
    }

    #[test]
    fn delete_removes_stored_key() {
        let store = InMemoryAccountKeyStore::default();

        AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        AccountService::delete(&store).unwrap();

        let err = AccountService::sign(&store, b"after-delete").unwrap_err();
        matches!(err, SignError::NotFound);
    }
}
