use crate::domain::content::encryption::{ContentEncryption, ContentEncryptionKey};
use crate::domain::content::provider::StorageProvider;
use crate::domain::content::Metadata;
use crate::domain::content_id::{ContentId, ContentIdGenerator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentStatus {
    Active,
    Deleting,
    Deleted,
}

#[derive(Debug, PartialEq)]
pub enum ContentError {
    EncryptionError(String),
    DecryptionError(String),
    AlreadyDeleted,
    StorageError(String),
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentEvent {
    Created,
    Updated,
    Deleted,
}

/// File creation time (nanoseconds since the Unix epoch). Monotonically increasing within the
/// process.
///
/// When consecutive reads return the same time, the previous value + 1 is returned, so creating
/// files with the same body in succession does not produce overlapping `series_id`s (same idea
/// as the state node's `next_monotonic_timestamp`).
fn next_creation_timestamp() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(last.saturating_add(1));
        match LAST.compare_exchange_weak(last, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    /// plainCid of the current version (SHA-256 of the body). Used for the AAD and tamper
    /// detection; not used as the key for device-side storage.
    raw_id: ContentId,
    /// The file's key. Decided only once at creation via `ContentIdGenerator::generate_series`
    /// and never changed afterwards. Records, CEKs, and share settings are kept under this key.
    series_id: ContentId,
    encrypted_id: ContentId,
    metadata: Metadata,
    /// Not included when persisted (only encrypted data is stored)
    #[serde(skip)]
    raw_content: Option<Vec<u8>>,
    encrypted_content: Option<Vec<u8>>,
    is_deleted: bool,
    content_status: ContentStatus,
    // TODO: added because it may turn out to be needed
    // last_updated_by: Option<StateNodeId>, // ID of the StateNode that last updated it
}

impl Content {
    #[cfg(test)]
    pub(crate) fn new(
        id: ContentId,
        metadata: Metadata,
        raw_content: Option<Vec<u8>>,
        encrypted_content: Option<Vec<u8>>,
        is_deleted: bool,
    ) -> Self {
        Self {
            raw_id: id.clone(),
            series_id: id.clone(),
            encrypted_id: id,
            metadata,
            raw_content,
            encrypted_content,
            is_deleted,
            content_status: ContentStatus::Active,
        }
    }

    pub fn create<G, E>(
        name: String,
        raw_content: Vec<u8>,
        path: String,
        provider: Option<StorageProvider>,
        id_generator: &G,
        key: &ContentEncryptionKey,
        encryption: &E,
    ) -> Result<(Self, ContentEvent), ContentError>
    where
        G: ContentIdGenerator,
        E: ContentEncryption,
    {
        let cid = id_generator.generate(&raw_content);
        let series_id = id_generator.generate_series(&cid, next_creation_timestamp());
        let metadata = Metadata::new(name, path, cid.clone(), provider);

        if key.0.is_empty() {
            return Err(ContentError::EncryptionError(
                "Missing content encryption key".to_string(),
            ));
        }

        let encrypted_content = encryption.encrypt(key, &raw_content)?;
        // encCid is generated from plainCid and the ciphertext (so that the state node etc. can
        // verify ciphertext integrity).
        let enc_cid = id_generator.generate_encrypted(&cid, &encrypted_content);

        let content = Self {
            raw_id: cid,
            series_id,
            encrypted_id: enc_cid,
            metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            is_deleted: false,
            content_status: ContentStatus::Active,
        };

        Ok((content, ContentEvent::Created))
    }

    /// Updates only the content body (binary).
    ///
    /// - Does not change name / path / series_id
    /// - `raw_id` (plainCid) is recomputed from the new binary (content addressing)
    /// - `metadata.updated_at` is updated to the current time
    pub fn update_content<G, E>(
        &self,
        raw_content: Vec<u8>,
        id_generator: &G,
        key: &ContentEncryptionKey,
        encryption: &E,
    ) -> Result<(Self, ContentEvent), ContentError>
    where
        G: ContentIdGenerator,
        E: ContentEncryption,
    {
        self.ensure_not_deleted()?;

        if key.0.is_empty() {
            return Err(ContentError::EncryptionError(
                "Missing content encryption key".to_string(),
            ));
        }

        let encrypted_content = encryption.encrypt(key, &raw_content)?;

        let new_id = id_generator.generate(&raw_content);
        // encCid is generated from plainCid and the ciphertext.
        let new_enc_id = id_generator.generate_encrypted(&new_id, &encrypted_content);

        let new_metadata = self.metadata.with_new_id(new_id.clone());

        let content = Self {
            raw_id: new_id,
            series_id: self.series_id.clone(),
            encrypted_id: new_enc_id,
            metadata: new_metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            is_deleted: false,
            content_status: ContentStatus::Active,
        };

        Ok((content, ContentEvent::Updated))
    }

    /// Imports a version created elsewhere as a new version of this series.
    ///
    /// Creates a new `Content` of the same shape as [`update_content`](Self::update_content),
    /// but keeps the given ciphertext as-is without re-encrypting. This is the entry point for
    /// the owner to import into their own record a version that already exists on the State
    /// Node (a version written by a recipient delegated write permission); it assumes the caller
    /// (application service) has verified the plaintext/ciphertext correspondence by decrypting
    /// with the same CEK.
    /// The ciphertext is kept as-is to preserve the match between the local ciphertext and the
    /// State Node's ciphertext (integrity verification).
    ///
    /// - Does not change name / path / series_id
    /// - `raw_id` (plainCid) is recomputed from the plaintext
    pub fn adopt_version<G>(
        &self,
        raw_content: Vec<u8>,
        encrypted_content: Vec<u8>,
        id_generator: &G,
    ) -> Result<(Self, ContentEvent), ContentError>
    where
        G: ContentIdGenerator,
    {
        self.ensure_not_deleted()?;

        let new_id = id_generator.generate(&raw_content);
        let new_enc_id = id_generator.generate_encrypted(&new_id, &encrypted_content);
        let new_metadata = self.metadata.with_new_id(new_id.clone());

        let content = Self {
            raw_id: new_id,
            series_id: self.series_id.clone(),
            encrypted_id: new_enc_id,
            metadata: new_metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            is_deleted: false,
            content_status: ContentStatus::Active,
        };

        Ok((content, ContentEvent::Updated))
    }

    /// Changes only the content name.
    ///
    /// - Does not change the binary or encrypted data
    /// - `metadata.updated_at` is updated to the current time
    pub fn rename(&self, new_name: String) -> Result<(Self, ContentEvent), ContentError> {
        self.ensure_not_deleted()?;

        let new_metadata = self.metadata.rename(new_name);

        let content = Self {
            raw_id: self.raw_id.clone(),
            series_id: self.series_id.clone(),
            encrypted_id: self.encrypted_id.clone(),
            metadata: new_metadata,
            raw_content: self.raw_content.clone(),
            encrypted_content: self.encrypted_content.clone(),
            is_deleted: self.is_deleted,
            content_status: self.content_status.clone(),
        };

        Ok((content, ContentEvent::Updated))
    }

    // A staged deletion process is needed if consensus across multiple nodes or cancellability
    // is required
    pub fn delete(&self) -> Result<(Self, ContentEvent), ContentError> {
        self.ensure_not_deleted()?;

        // Deletion is also a kind of update, so advance updated_at
        let new_metadata = self.metadata.touch();

        let content = Self {
            raw_id: self.raw_id.clone(),
            series_id: self.series_id.clone(),
            encrypted_id: self.encrypted_id.clone(),
            metadata: new_metadata,
            raw_content: None,
            encrypted_content: None,
            is_deleted: true,
            content_status: ContentStatus::Deleted,
        };

        Ok((content, ContentEvent::Deleted))
    }

    pub fn decrypt<E>(
        &self,
        key: &ContentEncryptionKey,
        encryption: &E,
    ) -> Result<Vec<u8>, ContentError>
    where
        E: ContentEncryption,
    {
        self.ensure_not_deleted()?;

        let Some(encrypted) = self.encrypted_content.as_ref() else {
            return Err(ContentError::DecryptionError(
                "Missing encrypted content".to_string(),
            ));
        };

        if key.0.is_empty() {
            return Err(ContentError::DecryptionError(
                "Missing content encryption key".to_string(),
            ));
        }

        encryption.decrypt(key, encrypted)
    }

    /// - Returns `ContentError::AlreadyDeleted` if `is_deleted == true`.
    fn ensure_not_deleted(&self) -> Result<(), ContentError> {
        if self.is_deleted {
            Err(ContentError::AlreadyDeleted)
        } else {
            Ok(())
        }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn raw_id(&self) -> &ContentId {
        &self.raw_id
    }

    pub fn series_id(&self) -> &ContentId {
        &self.series_id
    }

    pub fn encrypted_id(&self) -> &ContentId {
        &self.encrypted_id
    }

    pub fn raw_content(&self) -> Option<&Vec<u8>> {
        self.raw_content.as_ref()
    }

    pub fn encrypted_content(&self) -> Option<&Vec<u8>> {
        self.encrypted_content.as_ref()
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }

    pub fn content_status(&self) -> &ContentStatus {
        &self.content_status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content::encryption::{ContentEncryption, ContentEncryptionKey};
    use crate::domain::content_id::{ContentId, ContentIdGenerator};

    /// Simple encryption implementation for tests.
    /// encrypt: +1 to each byte, decrypt: -1 from each byte.
    #[derive(Debug, Clone)]
    struct MockEncryption;

    impl ContentEncryption for MockEncryption {
        fn encrypt(
            &self,
            _key: &ContentEncryptionKey,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            Ok(plaintext.iter().map(|b| b.wrapping_add(1)).collect())
        }

        fn decrypt(
            &self,
            _key: &ContentEncryptionKey,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            Ok(ciphertext.iter().map(|b| b.wrapping_sub(1)).collect())
        }
    }

    fn create_test_metadata() -> Metadata {
        Metadata::new(
            "test_content".to_string(),
            "test/path".to_string(),
            ContentId::new("test-content-id".into()),
            None,
        )
    }

    fn test_key_and_cipher() -> (ContentEncryptionKey, MockEncryption) {
        (ContentEncryptionKey(vec![1, 2, 3]), MockEncryption)
    }

    #[derive(Debug, Clone)]
    struct MockIdGenerator;

    impl ContentIdGenerator for MockIdGenerator {
        fn generate(&self, raw_content: &[u8]) -> ContentId {
            // Simple ID generation for tests: returns different IDs depending on the length.
            ContentId::new(format!("test-content-id-{}", raw_content.len()))
        }

        fn generate_encrypted(&self, plain_cid: &ContentId, ciphertext: &[u8]) -> ContentId {
            ContentId::new(format!(
                "test-enc-id-{}-{}",
                plain_cid.as_str(),
                ciphertext.len()
            ))
        }

        fn generate_series(&self, initial_plain_cid: &ContentId, created_at: u64) -> ContentId {
            ContentId::new(format!(
                "test-series-{}-{created_at}",
                initial_plain_cid.as_str()
            ))
        }
    }

    #[test]
    fn create_sets_initial_state() {
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let name = "test document".to_string();
        let raw_data = b"This is test content".to_vec();
        let path = "documents/test.txt".to_string();

        let (content, event) = Content::create(
            name.clone(),
            raw_data.clone(),
            path.clone(),
            None,
            &id_gen,
            &key,
            &encryption,
        )
        .unwrap();

        assert_eq!(content.metadata().name(), &name);
        assert_eq!(content.metadata().path(), &path);
        assert_eq!(content.raw_content().unwrap(), &raw_data);
        assert!(!content.is_deleted());
        assert_eq!(content.content_status(), &ContentStatus::Active);
        assert_eq!(event, ContentEvent::Created);
        assert!(content.encrypted_content().is_some());
        assert!(content.raw_id().as_str().starts_with("test-content-id-"));
        assert_ne!(content.raw_id(), content.series_id());
    }

    /// Two files created with the same body have different file keys.
    #[test]
    fn two_files_created_from_the_same_body_get_different_series_ids() {
        let (key, encryption) = test_key_and_cipher();
        let make = || {
            Content::create(
                "same".into(),
                b"same body".to_vec(),
                "/same".into(),
                None,
                &MockIdGenerator,
                &key,
                &encryption,
            )
            .unwrap()
            .0
        };
        let (a, b) = (make(), make());
        assert_eq!(a.raw_id(), b.raw_id());
        assert_ne!(a.series_id(), b.series_id());
    }

    #[test]
    fn update_changes_raw_content_and_keeps_path() {
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let (content, _) = Content::create(
            "test".to_string(),
            b"old".to_vec(),
            "path.txt".to_string(),
            None,
            &id_gen,
            &key,
            &encryption,
        )
        .unwrap();

        let updated_data = b"Updated content".to_vec();
        let (updated_content, event) = content
            .update_content(updated_data.clone(), &id_gen, &key, &encryption)
            .unwrap();

        assert_eq!(updated_content.raw_content().unwrap(), &updated_data);
        assert_eq!(event, ContentEvent::Updated);
        assert_eq!(updated_content.metadata().path(), content.metadata().path());
        assert_ne!(updated_content.raw_id(), content.raw_id());
        assert_eq!(updated_content.series_id(), content.series_id());
    }

    #[test]
    fn rename_updates_name_and_metadata_timestamp() {
        let metadata = create_test_metadata();
        let content = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            None,
            None,
            false,
        );

        let before_updated_at = content.metadata().updated_at();
        let (renamed, event) = content.rename("new_name".to_string()).unwrap();

        assert_eq!(event, ContentEvent::Updated);
        assert_eq!(renamed.metadata().name(), "new_name");
        assert_eq!(renamed.metadata().path(), content.metadata().path());
        assert!(renamed.metadata().updated_at() >= before_updated_at);
    }

    #[test]
    fn delete_marks_content_deleted_and_clears_buffers() {
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let (content, _) = Content::create(
            "test".to_string(),
            b"data".to_vec(),
            "path.txt".to_string(),
            None,
            &id_gen,
            &key,
            &encryption,
        )
        .unwrap();

        let before_updated_at = content.metadata().updated_at();
        let (deleted_content, event) = content.delete().unwrap();

        assert!(deleted_content.is_deleted());
        assert!(deleted_content.raw_content().is_none());
        assert!(deleted_content.encrypted_content().is_none());
        assert_eq!(event, ContentEvent::Deleted);
        assert!(deleted_content.metadata().updated_at() >= before_updated_at);
    }

    #[test]
    fn delete_on_already_deleted_returns_error() {
        let metadata = create_test_metadata();
        let deleted_content = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            None,
            None,
            true,
        );

        let result = deleted_content.delete();
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));
    }

    #[test]
    fn update_on_deleted_content_returns_error() {
        let metadata = create_test_metadata();
        let deleted_content = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            None,
            None,
            true,
        );
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let result =
            deleted_content.update_content(b"New data".to_vec(), &id_gen, &key, &encryption);
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));
    }

    #[test]
    fn decrypt_on_deleted_content_returns_error() {
        let metadata = create_test_metadata();
        let deleted_content = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            None,
            None,
            true,
        );
        let (key, encryption) = test_key_and_cipher();

        let result = deleted_content.decrypt(&key, &encryption);
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));
    }

    #[test]
    fn decrypt_success_with_valid_key_and_encrypted_content() {
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let name = "test file".to_string();
        let raw_data = b"Sensitive information".to_vec();
        let path = "documents/secrets.txt".to_string();

        let (content, _) = Content::create(
            name,
            raw_data.clone(),
            path,
            None,
            &id_gen,
            &key,
            &encryption,
        )
        .unwrap();

        assert!(content.encrypted_content().is_some());

        let decrypted_data = content.decrypt(&key, &encryption).unwrap();
        assert_eq!(decrypted_data, raw_data);
    }

    #[test]
    fn decrypt_error_when_missing_encrypted_content() {
        let (key, encryption) = test_key_and_cipher();

        let metadata = create_test_metadata();
        let content_missing_encrypted = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            Some(b"Raw data".to_vec()),
            None,
            false,
        );

        let result = content_missing_encrypted.decrypt(&key, &encryption);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn decrypt_error_when_missing_key() {
        let metadata = create_test_metadata();
        let content_with_encrypted = Content::new(
            ContentId::new("test-content-id".into()),
            metadata,
            Some(b"Raw data".to_vec()),
            Some(b"Encrypted data".to_vec()),
            false,
        );

        let empty_key = ContentEncryptionKey(vec![]);
        let encryption = MockEncryption;

        let result = content_with_encrypted.decrypt(&empty_key, &encryption);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }
}
