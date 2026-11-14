use crate::domain::{
    content::encryption::ContentEncryptionKey, content::Content, content_id::ContentId,
};

/// Port for persisting content.
pub trait ContentRepository {
    fn save(&self, content_id: &ContentId, content: &Content)
        -> Result<(), ContentRepositoryError>;
    fn find_by_id(&self, content_id: &ContentId)
        -> Result<Option<Content>, ContentRepositoryError>;
}

/// Extension trait of ContentRepository that can handle multiple storage providers.
///
/// Repositories implementing this trait can save and fetch content with a specified
/// provider.
pub trait MultiStorageContentRepository: ContentRepository {
    /// Saves content to the specified provider.
    fn save_to(
        &self,
        provider: &str,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError>;

    /// Fetches content from the specified provider.
    fn find_from(
        &self,
        provider: &str,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError>;

    /// Gets the list of connected providers.
    fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError>;

    /// Gets the current default provider.
    fn default_provider(&self) -> Result<String, ContentRepositoryError>;

    /// Connects a storage provider (registers an auth session).
    ///
    /// This method may be unavailable depending on the implementation.
    /// Returns `Ok(())` if available, and an error otherwise.
    fn connect_provider(
        &self,
        provider: &str,
        access_token: String,
    ) -> Result<(), ContentRepositoryError>;

    /// Disconnects a storage provider (deletes the auth session).
    ///
    /// This method may be unavailable depending on the implementation.
    /// Returns `Ok(())` if available, and an error otherwise.
    fn disconnect_provider(&self, provider: &str) -> Result<(), ContentRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ContentRepositoryError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// Port for saving, loading, and deleting CEKs (content encryption keys).
///
/// - Implementations live in the infra layer (in-memory / sled / other KVS, etc.).
/// - The application layer accesses CEKs only through this port.
pub trait ContentEncryptionKeyStore {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError>;

    fn load(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError>;

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError>;
}

/// Blanket impl so that `Arc<dyn ContentEncryptionKeyStore + Send + Sync>` can be passed
/// directly as a type parameter of `ContentService`.
///
/// Needed so the SDK can switch the persistence backend at runtime (in-memory / sled / others).
impl<T: ContentEncryptionKeyStore + ?Sized> ContentEncryptionKeyStore for std::sync::Arc<T> {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError> {
        (**self).save(content_id, key)
    }

    fn load(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError> {
        (**self).load(content_id)
    }

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError> {
        (**self).delete(content_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContentEncryptionKeyStoreError {
    #[error("storage error: {0}")]
    Storage(String),
}
