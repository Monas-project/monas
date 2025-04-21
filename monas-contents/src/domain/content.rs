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
