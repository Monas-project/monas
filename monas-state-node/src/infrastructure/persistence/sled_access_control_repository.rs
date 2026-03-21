//! Sled-based persistent access control repository implementation.

use crate::domain::access_control::ContentAccessControl;
use crate::port::persistence::PersistentAccessControlRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;
use sled::Db;
use std::path::Path;

const ACCESS_CONTROL_TREE_NAME: &str = "access_control";

/// Sled-based implementation of PersistentAccessControlRepository.
///
/// Stores ContentAccessControl state in a sled database for persistent storage.
pub struct SledAccessControlRepository {
    db: Db,
}

impl SledAccessControlRepository {
    /// Open or create a sled database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path.as_ref()).context("Failed to open sled database")?;
        Ok(Self { db })
    }

    /// Open with an existing sled database instance.
    pub fn with_db(db: Db) -> Self {
        Self { db }
    }

    /// Get the access control tree.
    fn access_control_tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(ACCESS_CONTROL_TREE_NAME)
            .context("Failed to open access_control tree")
    }
}

#[async_trait]
impl PersistentAccessControlRepository for SledAccessControlRepository {
    async fn get_access_control(&self, content_id: &str) -> Result<Option<ContentAccessControl>> {
        let tree = self.access_control_tree()?;
        match tree.get(content_id.as_bytes())? {
            Some(bytes) => {
                let ac: ContentAccessControl = serde_json::from_slice(&bytes)
                    .context("Failed to deserialize access control")?;
                Ok(Some(ac))
            }
            None => Ok(None),
        }
    }

    async fn save_access_control(&self, access_control: &ContentAccessControl) -> Result<()> {
        let tree = self.access_control_tree()?;
        let value =
            serde_json::to_vec(access_control).context("Failed to serialize access control")?;
        tree.insert(access_control.content_id().as_bytes(), value)
            .context("Failed to insert access control")?;
        Ok(())
    }

    async fn delete_access_control(&self, content_id: &str) -> Result<()> {
        let tree = self.access_control_tree()?;
        tree.remove(content_id.as_bytes())
            .context("Failed to delete access control")?;
        Ok(())
    }

    async fn list_access_controls(&self) -> Result<Vec<String>> {
        let tree = self.access_control_tree()?;
        let mut content_ids = Vec::new();
        for result in tree.iter() {
            let (key, _) = result.context("Failed to iterate access controls")?;
            let content_id =
                String::from_utf8(key.to_vec()).context("Failed to decode content ID as UTF-8")?;
            content_ids.push(content_id);
        }
        Ok(content_ids)
    }

    async fn flush(&self) -> Result<()> {
        self.db
            .flush_async()
            .await
            .context("Failed to flush database")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_save_and_get_access_control() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledAccessControlRepository::open(temp_dir.path()).unwrap();

        let ac = ContentAccessControl::new("content-1".to_string());

        repo.save_access_control(&ac).await.unwrap();

        let retrieved = repo.get_access_control("content-1").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.content_id(), "content-1");
        assert_eq!(retrieved.min_valid_issued_at(), 0);
        assert_eq!(retrieved.version(), 1);
    }

    #[tokio::test]
    async fn test_update_access_control() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledAccessControlRepository::open(temp_dir.path()).unwrap();

        let mut ac = ContentAccessControl::new("content-1".to_string());
        repo.save_access_control(&ac).await.unwrap();

        // Update the access control
        ac.invalidate_before(1000).unwrap();
        repo.save_access_control(&ac).await.unwrap();

        let retrieved = repo.get_access_control("content-1").await.unwrap().unwrap();
        assert_eq!(retrieved.min_valid_issued_at(), 1000);
        assert_eq!(retrieved.version(), 2);
    }

    #[tokio::test]
    async fn test_list_access_controls() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledAccessControlRepository::open(temp_dir.path()).unwrap();

        let ac1 = ContentAccessControl::new("content-1".to_string());
        let ac2 = ContentAccessControl::new("content-2".to_string());

        repo.save_access_control(&ac1).await.unwrap();
        repo.save_access_control(&ac2).await.unwrap();

        let content_ids = repo.list_access_controls().await.unwrap();
        assert_eq!(content_ids.len(), 2);
        assert!(content_ids.contains(&"content-1".to_string()));
        assert!(content_ids.contains(&"content-2".to_string()));
    }

    #[tokio::test]
    async fn test_delete_access_control() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledAccessControlRepository::open(temp_dir.path()).unwrap();

        let ac = ContentAccessControl::new("content-1".to_string());
        repo.save_access_control(&ac).await.unwrap();
        assert!(repo
            .get_access_control("content-1")
            .await
            .unwrap()
            .is_some());

        repo.delete_access_control("content-1").await.unwrap();
        assert!(repo
            .get_access_control("content-1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_none() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledAccessControlRepository::open(temp_dir.path()).unwrap();

        let result = repo.get_access_control("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
