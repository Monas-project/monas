use crate::domain::content::encryption::{ContentEncryption, ContentEncryptionKey};
use crate::domain::content::Metadata;
use crate::domain::content_id::{ContentId, ContentIdGenerator};

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct Content {
    id: ContentId,
    series_id: ContentId,
    metadata: Metadata,
    raw_content: Option<Vec<u8>>,
    encrypted_content: Option<Vec<u8>>,
    is_deleted: bool,
    content_status: ContentStatus,
    // TODO: 必要性があるかもしれないので追加した
    // last_updated_by: Option<StateNodeId>, // 最後に更新を行ったStateNodeのID
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
            id: id.clone(),
            series_id: id,
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
        id_generator: &G,
        key: &ContentEncryptionKey,
        encryption: &E,
    ) -> Result<(Self, ContentEvent), ContentError>
    where
        G: ContentIdGenerator,
        E: ContentEncryption,
    {
        let cid = id_generator.generate(&raw_content);
        let metadata = Metadata::new(name, path, cid.clone());

        if key.0.is_empty() {
            return Err(ContentError::EncryptionError(
                "Missing content encryption key".to_string(),
            ));
        }

        let encrypted_content = encryption.encrypt(key, &raw_content)?;

        let content = Self {
            id: cid.clone(),
            series_id: cid,
            metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            is_deleted: false,
            content_status: ContentStatus::Active,
        };

        Ok((content, ContentEvent::Created))
    }

    /// コンテンツ本体（バイナリ）のみを更新する。
    ///
    /// - name / path / series_id は変更しない
    /// - `id` は新しいバイナリから再計算される（コンテンツアドレス化）
    /// - `metadata.updated_at` は現在時刻に更新される
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

        let new_metadata = self.metadata.with_new_id(new_id.clone());

        let content = Self {
            id: new_id,
            series_id: self.series_id.clone(),
            metadata: new_metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            is_deleted: false,
            content_status: ContentStatus::Active,
        };

        Ok((content, ContentEvent::Updated))
    }

    /// コンテンツ名のみを変更する。
    ///
    /// - バイナリや暗号化データは変更しない
    /// - `metadata.updated_at` は現在時刻に更新される
    pub fn rename(&self, new_name: String) -> Result<(Self, ContentEvent), ContentError> {
        self.ensure_not_deleted()?;

        let new_metadata = self.metadata.rename(new_name);

        let content = Self {
            id: self.id.clone(),
            series_id: self.series_id.clone(),
            metadata: new_metadata,
            raw_content: self.raw_content.clone(),
            encrypted_content: self.encrypted_content.clone(),
            is_deleted: self.is_deleted,
            content_status: self.content_status.clone(),
        };

        Ok((content, ContentEvent::Updated))
    }

    // 複数のノードでのコンセンサスやキャンセル可能性が必要な場合は段階的な削除処理が必要
    pub fn delete(&self) -> Result<(Self, ContentEvent), ContentError> {
        self.ensure_not_deleted()?;

        // 削除操作も更新の一種なので updated_at を進める
        let new_metadata = self.metadata.touch();

        let content = Self {
            id: self.id.clone(),
            series_id: self.series_id.clone(),
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

        if self.encrypted_content.is_none() {
            Err(ContentError::DecryptionError(
                "Missing encrypted content".to_string(),
            ))
        } else if key.0.is_empty() {
            Err(ContentError::DecryptionError(
                "Missing content encryption key".to_string(),
            ))
        } else {
            let encrypted = self.encrypted_content.as_ref().unwrap();
            encryption.decrypt(key, encrypted)
        }
    }

    /// - `is_deleted == true` の場合は `ContentError::AlreadyDeleted` を返す。
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

    pub fn id(&self) -> &ContentId {
        &self.id
    }

    pub fn series_id(&self) -> &ContentId {
        &self.series_id
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

    /// テスト用の単純な暗号化実装。
    /// encrypt: 各バイトに +1, decrypt: 各バイトに -1。
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
        )
    }

    fn test_key_and_cipher() -> (ContentEncryptionKey, MockEncryption) {
        (ContentEncryptionKey(vec![1, 2, 3]), MockEncryption)
    }

    #[derive(Debug, Clone)]
    struct MockIdGenerator;

    impl ContentIdGenerator for MockIdGenerator {
        fn generate(&self, raw_content: &[u8]) -> ContentId {
            // テスト用の単純な ID 生成: 長さに応じて異なる ID を返す。
            ContentId::new(format!("test-content-id-{}", raw_content.len()))
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
        assert!(content.id().as_str().starts_with("test-content-id-"));
        assert_eq!(content.id(), content.series_id());
    }

    #[test]
    fn update_changes_raw_content_and_keeps_path() {
        let (key, encryption) = test_key_and_cipher();
        let id_gen = MockIdGenerator;

        let (content, _) = Content::create(
            "test".to_string(),
            b"old".to_vec(),
            "path.txt".to_string(),
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
        assert_ne!(updated_content.id(), content.id());
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

        let (content, _) =
            Content::create(name, raw_data.clone(), path, &id_gen, &key, &encryption).unwrap();

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
