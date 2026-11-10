use crate::domain::content::provider::StorageProvider;
use crate::domain::{content::metadata::Metadata, content_id::ContentId};

/// Input for the create-content use case.
#[derive(Debug)]
pub struct CreateContentCommand {
    /// Content name
    pub name: String,
    /// Logical path
    pub path: String,
    /// Raw content data
    pub raw_content: Vec<u8>,
    /// Storage provider to save to.
    /// If `None`, the content is saved to the default provider.
    pub provider: Option<StorageProvider>,
}

/// Output of the create-content use case.
#[derive(Debug)]
pub struct CreateContentResult {
    /// plainCid of the created version.
    pub content_id: ContentId,
    /// The file's key. Subsequent operations identify the target with this.
    pub series_id: ContentId,
    pub metadata: Metadata,
    /// Public information derived from the key used for content encryption, etc.
    /// The concrete meaning is to be decided in later design.
    pub public_key: String,
    pub encrypted_content: Vec<u8>,
}

/// Input for the update-content use case.
#[derive(Debug)]
pub struct UpdateContentCommand {
    /// Key of the target file (`series_id`).
    pub content_id: ContentId,
    pub new_name: Option<String>,
    pub new_raw_content: Option<Vec<u8>>,
    pub provider: Option<StorageProvider>,
}

/// Output of the update-content use case.
#[derive(Debug)]
pub struct UpdateContentResult {
    pub content_id: ContentId,
    pub series_id: ContentId,
    pub metadata: Metadata,
    pub encrypted_content: Vec<u8>,
}

/// Input for the delete-content use case.
#[derive(Debug)]
pub struct DeleteContentCommand {
    /// Key of the target file (`series_id`).
    pub content_id: ContentId,
    pub provider: Option<StorageProvider>,
}

/// Output of the delete-content use case.
#[derive(Debug)]
pub struct DeleteContentResult {
    pub content_id: ContentId,
}

/// Output of the fetch-content use case.
///
/// - `content_id` is the ID (plainCid) identifying the body of the current version.
/// - `series_id` is the file's key (fixed at creation and never changed afterwards).
/// - `raw_content` is the decrypted content bytes.
#[derive(Debug)]
pub struct FetchContentResult {
    pub content_id: ContentId,
    pub series_id: ContentId,
    pub metadata: Metadata,
    pub raw_content: Vec<u8>,
}

/// Input for the re-encrypt-content use case.
#[derive(Debug)]
pub struct ReencryptContentCommand {
    /// Key of the target file (`series_id`).
    pub content_id: ContentId,
}

/// Output of the re-encrypt-content use case.
#[derive(Debug)]
pub struct ReencryptContentResult {
    pub encrypted_id: ContentId,
    pub raw_id: ContentId,
    pub metadata: Metadata,
    pub encrypted_content: Vec<u8>,
}
