use crate::application_service::content_service::{
    ContentEncryptionKeyStoreError, ContentRepositoryError,
};
use crate::domain::content_id::ContentId;
use crate::domain::share::{KeyId, Share, ShareError};

/// Port for persisting the share state (ACL).
///
/// - key: the file's key (`Content::series_id`). `Share::content_id` is also this value.
/// - value: the `Share` for that file
///
/// There is one share setting per file. Keying by plainCid (the hash of the body) would pick up
/// stale settings when the body is reverted to earlier contents, and would mix settings with
/// other files that have the same body.
pub trait ShareRepository {
    fn load(&self, series_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError>;

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError>;
}

/// Blanket impl so that `Arc<dyn ShareRepository + Send + Sync>` can be passed directly as a
/// type parameter of `ShareService`.
impl<T: ShareRepository + ?Sized> ShareRepository for std::sync::Arc<T> {
    fn load(&self, series_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        (**self).load(series_id)
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        (**self).save(share)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShareRepositoryError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// Port for managing KeyIds and HPKE public key bytes.
///
/// - Implementations are expected to be a local key store / State Node / external KMS, etc.
pub trait PublicKeyDirectory {
    /// Computes a KeyId from a public key (no side effects).
    ///
    /// - This operation does not persist anything; it only computes the KeyId.
    /// - Used for validation and precomputation.
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId;

    /// Registers a new public key and returns the corresponding KeyId.
    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError>;

    /// Gets the public key bytes for an existing KeyId.
    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError>;

    /// Deletes the public key for the given KeyId.
    ///
    /// - Used for compensating transactions (rollback).
    /// - Deleting a non-existent KeyId is not an error (idempotent).
    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError>;
}

/// Blanket impl so that `Arc<dyn PublicKeyDirectory + Send + Sync>` can be passed directly as a
/// type parameter of `ShareService`.
impl<T: PublicKeyDirectory + ?Sized> PublicKeyDirectory for std::sync::Arc<T> {
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId {
        (**self).compute_key_id(public_key)
    }

    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
        (**self).register_public_key(public_key)
    }

    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError> {
        (**self).find_public_key(key_id)
    }

    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError> {
        (**self).delete_public_key(key_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyDirectoryError {
    #[error("lookup error: {0}")]
    Lookup(String),
}

/// Errors that can occur in the Share application service.
#[derive(Debug, thiserror::Error)]
pub enum ShareApplicationError {
    #[error("content not found")]
    ContentNotFound,

    #[error("content is deleted")]
    ContentDeleted,

    #[error("missing encrypted content for content")]
    MissingEncryptedContent,

    #[error("missing CEK for content")]
    MissingContentEncryptionKey,

    #[error("share domain error: {0:?}")]
    Share(ShareError),

    #[error("content repository error: {0}")]
    ContentRepository(ContentRepositoryError),

    #[error("CEK store error: {0}")]
    ContentEncryptionKeyStore(ContentEncryptionKeyStoreError),

    #[error("share repository error: {0}")]
    ShareRepository(ShareRepositoryError),

    #[error("public key directory error: {0}")]
    PublicKeyDirectory(PublicKeyDirectoryError),

    #[error("missing public key for key_id")]
    MissingPublicKey,

    #[error("key wrapping error: {0}")]
    KeyWrapping(String),
}
