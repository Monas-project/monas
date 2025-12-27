//! Sled-based persistent content network repository implementation.

use crate::domain::content_network::ContentNetwork;
use crate::port::persistence::PersistentContentRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;
use sled::Db;
use std::path::Path;

const CONTENT_NETWORK_TREE_NAME: &str = "content_networks";
const CAPACITY_INDEX_TREE_NAME: &str = "capacity_index";

/// Sled-based implementation of PersistentContentRepository.
///
/// Stores content networks in a sled database with an index for capacity-based queries.
pub struct SledContentNetworkRepository {
    db: Db,
}

impl SledContentNetworkRepository {
    /// Open or create a sled database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path.as_ref()).context("Failed to open sled database")?;
        Ok(Self { db })
    }

    /// Open with an existing sled database instance.
    pub fn with_db(db: Db) -> Self {
        Self { db }
    }

    /// Get the content networks tree.
    fn content_tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(CONTENT_NETWORK_TREE_NAME)
            .context("Failed to open content networks tree")
    }

    /// Get the capacity index tree.
    fn capacity_tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(CAPACITY_INDEX_TREE_NAME)
            .context("Failed to open capacity index tree")
    }

    /// Add a content to the capacity index.
    pub fn index_by_capacity(&self, content_id: &str, required_capacity: u64) -> Result<()> {
        let tree = self.capacity_tree()?;
        // Use capacity as prefix for range queries (big-endian for correct ordering)
        let key = format!("{:016x}:{}", required_capacity, content_id);
        tree.insert(key.as_bytes(), content_id.as_bytes())
            .context("Failed to index capacity")?;
        Ok(())
    }

    /// Remove a content from the capacity index.
    pub fn remove_from_capacity_index(
        &self,
        content_id: &str,
        required_capacity: u64,
    ) -> Result<()> {
        let tree = self.capacity_tree()?;
        let key = format!("{:016x}:{}", required_capacity, content_id);
        tree.remove(key.as_bytes())
            .context("Failed to remove from capacity index")?;
        Ok(())
    }
}

#[async_trait]
impl PersistentContentRepository for SledContentNetworkRepository {
    async fn find_assignable_cids(&self, capacity: u64) -> Result<Vec<String>> {
        let tree = self.capacity_tree()?;
        let mut cids = Vec::new();

        // Find all content with required_capacity <= capacity
        // Since keys are hex-encoded capacity:content_id, we can iterate
        // from the beginning up to the given capacity
        let max_key = format!("{:016x}:", capacity + 1);

        for result in tree.range(..max_key.as_bytes()) {
            let (_, value) = result.context("Failed to iterate capacity index")?;
            let content_id = String::from_utf8(value.to_vec())
                .context("Failed to decode content ID as UTF-8")?;
            cids.push(content_id);
        }

        Ok(cids)
    }

    async fn get_content_network(&self, content_id: &str) -> Result<Option<ContentNetwork>> {
        let tree = self.content_tree()?;
        match tree.get(content_id.as_bytes())? {
            Some(bytes) => {
                let network: ContentNetwork = serde_json::from_slice(&bytes)
                    .context("Failed to deserialize content network")?;
                Ok(Some(network))
            }
            None => Ok(None),
        }
    }

    async fn save_content_network(&self, net: ContentNetwork) -> Result<()> {
        let tree = self.content_tree()?;
        let value = serde_json::to_vec(&net).context("Failed to serialize content network")?;
        tree.insert(net.content_id.as_bytes(), value)
            .context("Failed to insert content network")?;
        Ok(())
    }

    async fn delete_content_network(&self, content_id: &str) -> Result<()> {
        let tree = self.content_tree()?;
        tree.remove(content_id.as_bytes())
            .context("Failed to delete content network")?;
        Ok(())
    }

    async fn list_content_networks(&self) -> Result<Vec<String>> {
        let tree = self.content_tree()?;
        let mut networks = Vec::new();
        for result in tree.iter() {
            let (key, _) = result.context("Failed to iterate content networks")?;
            let content_id =
                String::from_utf8(key.to_vec()).context("Failed to decode content ID as UTF-8")?;
            networks.push(content_id);
        }
        Ok(networks)
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
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_save_and_get_content_network() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledContentNetworkRepository::open(temp_dir.path()).unwrap();

        let mut members = BTreeSet::new();
        members.insert("node-1".to_string());
        members.insert("node-2".to_string());

        let network = ContentNetwork {
            content_id: "cid-1".to_string(),
            member_nodes: members,
        };

        repo.save_content_network(network.clone()).await.unwrap();

        let retrieved = repo.get_content_network("cid-1").await.unwrap();
        assert_eq!(retrieved, Some(network));
    }

    #[tokio::test]
    async fn test_list_content_networks() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledContentNetworkRepository::open(temp_dir.path()).unwrap();

        let network1 = ContentNetwork {
            content_id: "cid-1".to_string(),
            member_nodes: BTreeSet::new(),
        };
        let network2 = ContentNetwork {
            content_id: "cid-2".to_string(),
            member_nodes: BTreeSet::new(),
        };

        repo.save_content_network(network1).await.unwrap();
        repo.save_content_network(network2).await.unwrap();

        let networks = repo.list_content_networks().await.unwrap();
        assert_eq!(networks.len(), 2);
        assert!(networks.contains(&"cid-1".to_string()));
        assert!(networks.contains(&"cid-2".to_string()));
    }

    #[tokio::test]
    async fn test_find_assignable_cids() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledContentNetworkRepository::open(temp_dir.path()).unwrap();

        // Index some content with different capacities
        repo.index_by_capacity("cid-small", 100).unwrap();
        repo.index_by_capacity("cid-medium", 500).unwrap();
        repo.index_by_capacity("cid-large", 1000).unwrap();

        // Find content that fits in 600 capacity
        let cids = repo.find_assignable_cids(600).await.unwrap();
        assert!(cids.contains(&"cid-small".to_string()));
        assert!(cids.contains(&"cid-medium".to_string()));
        assert!(!cids.contains(&"cid-large".to_string()));
    }

    #[tokio::test]
    async fn test_delete_content_network() {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledContentNetworkRepository::open(temp_dir.path()).unwrap();

        let network = ContentNetwork {
            content_id: "cid-1".to_string(),
            member_nodes: BTreeSet::new(),
        };

        repo.save_content_network(network).await.unwrap();
        assert!(repo.get_content_network("cid-1").await.unwrap().is_some());

        repo.delete_content_network("cid-1").await.unwrap();
        assert!(repo.get_content_network("cid-1").await.unwrap().is_none());
    }
}

