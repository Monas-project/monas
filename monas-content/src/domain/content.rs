use crate::domain::metadata::Metadata;
use chrono::{DateTime, Utc};
use std::fmt::Debug;


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteStatus {
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

pub trait ContentKeyPair: Debug + Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> String;
    fn clone_box(&self) -> Box<dyn ContentKeyPair>;
}

impl Clone for Box<dyn ContentKeyPair> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Debug)]
pub struct Content {
    metadata: Metadata,
    raw_content: Option<Vec<u8>>,
    encrypted_content: Option<Vec<u8>>,
    key_pair: Option<Box<dyn ContentKeyPair>>,
    is_deleted: bool,
    delete_status: DeleteStatus,
    // TODO: 必要性があるかもしれないので追加した
    // last_updated_by: Option<StateNodeId>, // 最後に更新を行ったStateNodeのID
}

impl Content {
    pub fn new(
        metadata: Metadata,
        raw_content: Option<Vec<u8>>,
        encrypted_content: Option<Vec<u8>>,
        key_pair: Option<Box<dyn ContentKeyPair>>,
        is_deleted: bool,
    ) -> Self {

        // TODO: 事前条件を追加する

        Self {
            metadata,
            raw_content,
            encrypted_content,
            key_pair,
            is_deleted,
            delete_status: DeleteStatus::Active,
        }
    }

    pub fn create(
        name: String,
        raw_content: Vec<u8>,
        path: String,
        key_pair: Box<dyn ContentKeyPair>,
    ) -> Result<(Self, ContentEvent), ContentError> {
        let metadata = Metadata::new(name, &raw_content, path);

        let encrypted_content = key_pair.encrypt(&raw_content);

        let content = Self {
            metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            key_pair: Some(key_pair),
            is_deleted: false,
            delete_status: DeleteStatus::Active,
        };

        Ok((content, ContentEvent::Created))
    }

    pub fn update(
        &self,
        raw_content: Vec<u8>,
        key_pair: Option<Box<dyn ContentKeyPair>>,
    ) -> Result<(Self, ContentEvent), ContentError> {
        if self.is_deleted {
            return Err(ContentError::AlreadyDeleted);
        }

        let key_pair = key_pair.unwrap_or_else(|| self.key_pair.clone().unwrap());
        let encrypted_content = key_pair.encrypt(&raw_content);

        let new_metadata = self.metadata.clone();

        let content = Self {
            metadata: new_metadata,
            raw_content: Some(raw_content),
            encrypted_content: Some(encrypted_content),
            key_pair: Some(key_pair),
            is_deleted: false,
            delete_status: DeleteStatus::Active,
        };

        Ok((content, ContentEvent::Updated))
    }

    // 複数のノードでのコンセンサスやキャンセル可能性が必要な場合は段階的な削除処理が必要
    pub fn delete(&self) -> Result<(Self, ContentEvent), ContentError> {
        if self.is_deleted {
            return Err(ContentError::AlreadyDeleted);
        }

        let content = Self {
            metadata: self.metadata.clone(),
            raw_content: None,
            encrypted_content: None,
            key_pair: self.key_pair.clone(),
            is_deleted: true,
            delete_status: DeleteStatus::Deleted,
        };

        Ok((content, ContentEvent::Deleted))
    }

    pub fn decrypt(&self) -> Result<Vec<u8>, ContentError> {
        if self.is_deleted {
            return Err(ContentError::AlreadyDeleted);
        }

        if let (Some(encrypted), Some(key)) = (&self.encrypted_content, &self.key_pair) {
            Ok(key.decrypt(encrypted))
        } else {
            Err(ContentError::DecryptionError(
                "Missing encrypted content or key pair".to_string(),
            ))
        }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn raw_content(&self) -> Option<&Vec<u8>> {
        self.raw_content.as_ref()
    }

    pub fn encrypted_content(&self) -> Option<&Vec<u8>> {
        self.encrypted_content.as_ref()
    }

    pub fn key_pair(&self) -> Option<&Box<dyn ContentKeyPair>> {
        self.key_pair.as_ref()
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }

    pub fn delete_status(&self) -> &DeleteStatus {
        &self.delete_status
    }
}

impl Clone for Content {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            raw_content: self.raw_content.clone(),
            encrypted_content: self.encrypted_content.clone(),
            key_pair: self.key_pair.clone(),
            is_deleted: self.is_deleted,
            delete_status: self.delete_status.clone(),
        }
    }
}

#[cfg(test)]
mod mock {
    use super::*;

    pub struct MockContentKeyPairFactory;

    impl MockContentKeyPairFactory {
        pub fn create_key_pair(id: &str) -> Box<dyn ContentKeyPair> {
            Box::new(MockKeyPair {
                id: id.to_string(),
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockKeyPair {
        pub id: String,
    }

    impl ContentKeyPair for MockKeyPair {
        fn encrypt(&self, data: &[u8]) -> Vec<u8> {
            // 簡易的な暗号化: データの各バイトに1を加算
            data.iter().map(|b| b.wrapping_add(1)).collect()
        }

        fn decrypt(&self, data: &[u8]) -> Vec<u8> {
            // 簡易的な復号化: データの各バイトから1を減算
            data.iter().map(|b| b.wrapping_sub(1)).collect()
        }

        fn public_key(&self) -> String {
            format!("mock_public_key_{}", self.id)
        }

        fn clone_box(&self) -> Box<dyn ContentKeyPair> {
            Box::new(self.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn create_test_metadata() -> Metadata {
        Metadata::new(
            "test_content".to_string(),
            b"test content data",
            "test/path".to_string(),
        )
    }

    #[test]
    fn test_content_lifecycle() {
        // Test: Content::create()
        let name = "test document".to_string();
        let raw_data = b"This is test content".to_vec();
        let path = "documents/test.txt".to_string();
        let key_pair = mock::MockContentKeyPairFactory::create_key_pair("test");

        let (content, event) = Content::create(name.clone(), raw_data.clone(), path.clone(), key_pair).unwrap();

        assert_eq!(content.metadata().name(), &name);
        assert_eq!(content.metadata().path(), &path);
        assert_eq!(content.raw_content().unwrap(), &raw_data);
        assert_eq!(content.is_deleted(), false);
        assert_eq!(content.delete_status(), &DeleteStatus::Active);
        assert_eq!(event, ContentEvent::Created);
        assert!(content.encrypted_content().is_some());

        // Test: Content::update()
        let updated_data = b"Updated content".to_vec();
        let (updated_content, event) = content.update(updated_data.clone(), None).unwrap();

        assert_eq!(updated_content.raw_content().unwrap(), &updated_data);
        assert_eq!(event, ContentEvent::Updated);
        assert_eq!(updated_content.metadata().path(), content.metadata().path());

        // Test: Content::delete()
        let (deleted_content, event) = updated_content.delete().unwrap();

        assert_eq!(deleted_content.is_deleted(), true);
        assert!(deleted_content.raw_content().is_none());
        assert!(deleted_content.encrypted_content().is_none());
        assert_eq!(event, ContentEvent::Deleted);

        // Test: try to delete deleted content
        let result = deleted_content.delete();
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));

        // Test: try to update deleted content
        let result = deleted_content.update(b"New data".to_vec(), None);
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));
    }

    #[test]
    fn test_decrypt_error_handling_for_missing_components() {
        let name = "test file".to_string();
        let raw_data = b"Sensitive information".to_vec();
        let path = "documents/secrets.txt".to_string();
        let key_pair = mock::MockContentKeyPairFactory::create_key_pair("test");
        let (content, _) = Content::create(name, raw_data.clone(), path, key_pair).unwrap();

        assert!(content.encrypted_content().is_some());

        let decrypted_data = content.decrypt().unwrap();
        assert_eq!(decrypted_data, raw_data);

        let metadata = create_test_metadata();
        let content_missing_encrypted = Content::new(
            metadata.clone(),
            Some(b"Raw data".to_vec()),
            None,
            Some(mock::MockContentKeyPairFactory::create_key_pair("test")),
            false,
        );
        // Test: try to decrypt content with missing encrypted data
        let result = content_missing_encrypted.decrypt();
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));

        let content_missing_key = Content::new(
            metadata,
            Some(b"Raw data".to_vec()),
            Some(b"Encrypted data".to_vec()),
            None,
            false,
        );
        // Test: try to decrypt content with missing key pair
        let result = content_missing_key.decrypt();
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn test_operations_on_deleted_content_return_already_deleted_error() {
        let metadata = create_test_metadata();

        let deleted_content = Content::new(
            metadata,
            None,
            None,
            Some(mock::MockContentKeyPairFactory::create_key_pair("test")),
            true,
        );
        // Test: try to delete deleted content
        let result = deleted_content.delete();
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));

        // Test: try to update deleted content
        let result = deleted_content.update(b"New data".to_vec(), None);
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));

        // Test: try to decrypt deleted content
        let result = deleted_content.decrypt();
        assert!(matches!(result, Err(ContentError::AlreadyDeleted)));
    }
}