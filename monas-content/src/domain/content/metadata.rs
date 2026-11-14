use crate::domain::content::provider::StorageProvider;
use crate::domain::content_id::ContentId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    name: String,
    path: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    id: ContentId,
    provider: Option<StorageProvider>,
}

impl Metadata {
    /// Creates metadata with a ContentId.
    pub fn new(
        name: String,
        path: String,
        id: ContentId,
        provider: Option<StorageProvider>,
    ) -> Self {
        let now = Utc::now();
        Self {
            name,
            path,
            created_at: now,
            updated_at: now,
            id,
            provider,
        }
    }

    /// Returns a new Metadata with only `updated_at` updated, following an update of the content body
    /// or metadata.
    pub fn touch(&self) -> Self {
        let now = Utc::now();
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            created_at: self.created_at,
            updated_at: now,
            id: self.id.clone(),
            provider: self.provider.clone(),
        }
    }

    /// Returns a Metadata with the ContentId replaced by a new one and `updated_at` set to now.
    ///
    /// - name / path / created_at / provider are kept.
    /// - Only id is updated to the new value.
    pub fn with_new_id(&self, new_id: ContentId) -> Self {
        let now = Utc::now();
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            created_at: self.created_at,
            updated_at: now,
            id: new_id,
            provider: self.provider.clone(),
        }
    }

    /// Returns a new Metadata with the name changed and `updated_at` updated.
    pub fn rename(&self, new_name: String) -> Self {
        let now = Utc::now();
        Self {
            name: new_name,
            path: self.path.clone(),
            created_at: self.created_at,
            updated_at: now,
            id: self.id.clone(),
            provider: self.provider.clone(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn id(&self) -> &ContentId {
        &self.id
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn provider(&self) -> Option<&StorageProvider> {
        self.provider.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content_id::ContentId;

    #[test]
    fn test_metadata_holds_content_id() {
        let cid = ContentId::new("cid-1234".to_string());
        let metadata = Metadata::new("name".to_string(), "/path".to_string(), cid.clone(), None);

        assert_eq!(metadata.id(), &cid);
    }

    #[test]
    fn test_metadata_creation_and_hash_validation() {
        let name = "テストファイル".to_string();
        let path = "/test/path".to_string();
        let cid = ContentId::new("cid-5678".to_string());
        let metadata = Metadata::new(name.clone(), path.clone(), cid.clone(), None);

        assert_eq!(metadata.name(), name);
        assert_eq!(metadata.path(), path);
        assert_eq!(metadata.created_at(), metadata.updated_at());
        assert_eq!(metadata.id(), &cid);
    }

    #[test]
    fn test_metadata_with_provider() {
        use crate::domain::content::provider::StorageProvider;
        let cid = ContentId::new("cid-provider".to_string());
        let metadata = Metadata::new(
            "name".to_string(),
            "/path".to_string(),
            cid.clone(),
            Some(StorageProvider::GoogleDrive),
        );

        assert_eq!(metadata.provider(), Some(&StorageProvider::GoogleDrive));
    }

    #[test]
    fn test_metadata_provider_preserved_on_touch() {
        use crate::domain::content::provider::StorageProvider;
        let cid = ContentId::new("cid-touch".to_string());
        let metadata = Metadata::new(
            "name".to_string(),
            "/path".to_string(),
            cid,
            Some(StorageProvider::Local),
        );

        let touched = metadata.touch();
        assert_eq!(touched.provider(), Some(&StorageProvider::Local));
    }
}
