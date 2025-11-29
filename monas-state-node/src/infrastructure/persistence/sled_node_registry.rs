//! Sled-based persistent node registry implementation.

use crate::domain::state_node::NodeSnapshot;
use crate::port::persistence::PersistentNodeRegistry;
use anyhow::{Context, Result};
use async_trait::async_trait;
use sled::Db;
use std::path::Path;

const NODE_TREE_NAME: &str = "nodes";

/// Sled-based implementation of PersistentNodeRegistry.
///
/// Stores node snapshots in a sled database for persistent storage.
pub struct SledNodeRegistry {
    db: Db,
}

impl SledNodeRegistry {
    /// Open or create a sled database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path.as_ref()).context("Failed to open sled database")?;
        Ok(Self { db })
    }

    /// Open with an existing sled database instance.
    pub fn with_db(db: Db) -> Self {
        Self { db }
    }

    /// Get the nodes tree.
    fn nodes_tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(NODE_TREE_NAME)
            .context("Failed to open nodes tree")
    }
}

#[async_trait]
impl PersistentNodeRegistry for SledNodeRegistry {
    async fn upsert_node(&self, node: &NodeSnapshot) -> Result<()> {
        let tree = self.nodes_tree()?;
        let value = serde_json::to_vec(node).context("Failed to serialize node snapshot")?;
        tree.insert(node.node_id.as_bytes(), value)
            .context("Failed to insert node")?;
        Ok(())
    }

    async fn get_available_capacity(&self, node_id: &str) -> Result<Option<u64>> {
        let tree = self.nodes_tree()?;
        match tree.get(node_id.as_bytes())? {
            Some(bytes) => {
                let node: NodeSnapshot =
                    serde_json::from_slice(&bytes).context("Failed to deserialize node")?;
                Ok(Some(node.available_capacity))
            }
            None => Ok(None),
        }
    }

    async fn list_nodes(&self) -> Result<Vec<String>> {
        let tree = self.nodes_tree()?;
        let mut nodes = Vec::new();
        for result in tree.iter() {
            let (key, _) = result.context("Failed to iterate nodes")?;
            let node_id =
                String::from_utf8(key.to_vec()).context("Failed to decode node ID as UTF-8")?;
            nodes.push(node_id);
        }
        Ok(nodes)
    }

    async fn get_node(&self, node_id: &str) -> Result<Option<NodeSnapshot>> {
        let tree = self.nodes_tree()?;
        match tree.get(node_id.as_bytes())? {
            Some(bytes) => {
                let node: NodeSnapshot =
                    serde_json::from_slice(&bytes).context("Failed to deserialize node")?;
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    async fn delete_node(&self, node_id: &str) -> Result<()> {
        let tree = self.nodes_tree()?;
        tree.remove(node_id.as_bytes())
            .context("Failed to delete node")?;
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.db.flush_async().await.context("Failed to flush database")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_upsert_and_get_node() {
        let temp_dir = TempDir::new().unwrap();
        let registry = SledNodeRegistry::open(temp_dir.path()).unwrap();

        let node = NodeSnapshot {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 800,
        };

        registry.upsert_node(&node).await.unwrap();

        let retrieved = registry.get_node("node-1").await.unwrap();
        assert_eq!(retrieved, Some(node.clone()));

        let capacity = registry.get_available_capacity("node-1").await.unwrap();
        assert_eq!(capacity, Some(800));
    }

    #[tokio::test]
    async fn test_list_nodes() {
        let temp_dir = TempDir::new().unwrap();
        let registry = SledNodeRegistry::open(temp_dir.path()).unwrap();

        let node1 = NodeSnapshot {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 800,
        };
        let node2 = NodeSnapshot {
            node_id: "node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 1500,
        };

        registry.upsert_node(&node1).await.unwrap();
        registry.upsert_node(&node2).await.unwrap();

        let nodes = registry.list_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&"node-1".to_string()));
        assert!(nodes.contains(&"node-2".to_string()));
    }

    #[tokio::test]
    async fn test_delete_node() {
        let temp_dir = TempDir::new().unwrap();
        let registry = SledNodeRegistry::open(temp_dir.path()).unwrap();

        let node = NodeSnapshot {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 800,
        };

        registry.upsert_node(&node).await.unwrap();
        assert!(registry.get_node("node-1").await.unwrap().is_some());

        registry.delete_node("node-1").await.unwrap();
        assert!(registry.get_node("node-1").await.unwrap().is_none());
    }
}

