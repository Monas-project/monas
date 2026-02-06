//! Sled-based public key repository for persistent storage.

use crate::domain::value_objects::NodeId;
use crate::port::extended_public_key_registry::ExtendedPublicKeyRegistry;
use crate::port::public_key_registry::PublicKeyRegistry;
use anyhow::{Context, Result};
use async_trait::async_trait;
use sled::Db;
use std::sync::Arc;

/// Sled-based public key repository
///
/// This repository provides persistent storage for public keys using Sled.
/// It stores mappings from both NodeId and KeyId to public keys.
pub struct SledPublicKeyRepository {
    /// Database handle
    db: Arc<Db>,
    /// Tree for NodeId -> PublicKey mapping
    node_key_tree: sled::Tree,
    /// Tree for KeyId -> PublicKey mapping
    key_id_tree: sled::Tree,
    /// Tree for NodeId -> KeyId mapping
    node_to_key_tree: sled::Tree,
    /// Tree for nonce tracking (replay attack prevention)
    nonce_tree: sled::Tree,
}

impl SledPublicKeyRepository {
    /// Create a new repository with the given database
    pub fn new(db: Arc<Db>) -> Result<Self> {
        let node_key_tree = db
            .open_tree("public_keys_by_node")
            .context("Failed to open node_key_tree")?;
        let key_id_tree = db
            .open_tree("public_keys_by_key_id")
            .context("Failed to open key_id_tree")?;
        let node_to_key_tree = db
            .open_tree("node_to_key_mapping")
            .context("Failed to open node_to_key_tree")?;
        let nonce_tree = db
            .open_tree("used_nonces")
            .context("Failed to open nonce_tree")?;

        Ok(Self {
            db,
            node_key_tree,
            key_id_tree,
            node_to_key_tree,
            nonce_tree,
        })
    }

    /// Open a repository at the specified path
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        Self::new(Arc::new(db))
    }

    /// Check and record a nonce to prevent replay attacks
    ///
    /// # Returns
    /// Ok(true) if the nonce is new and was recorded
    /// Ok(false) if the nonce was already used
    pub async fn check_and_record_nonce(&self, nonce: &str) -> Result<bool> {
        let nonce_bytes = nonce.as_bytes();

        // Check if nonce already exists
        if self.nonce_tree.contains_key(nonce_bytes)? {
            return Ok(false);
        }

        // Record the nonce with current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        self.nonce_tree
            .insert(nonce_bytes, &timestamp.to_le_bytes())?;

        // Clean up old nonces (older than 1 hour)
        self.cleanup_old_nonces(timestamp - 3600)?;

        Ok(true)
    }

    /// Clean up nonces older than the given timestamp
    fn cleanup_old_nonces(&self, cutoff_timestamp: u64) -> Result<()> {
        let mut keys_to_remove = Vec::new();

        for result in self.nonce_tree.iter() {
            let (key, value) = result?;
            if value.len() == 8 {
                let timestamp = u64::from_le_bytes(value.as_ref().try_into()?);
                if timestamp < cutoff_timestamp {
                    keys_to_remove.push(key.to_vec());
                }
            }
        }

        for key in keys_to_remove {
            self.nonce_tree.remove(key)?;
        }

        Ok(())
    }

    /// Flush all pending writes to disk
    pub async fn flush(&self) -> Result<()> {
        self.db.flush_async().await?;
        Ok(())
    }
}

#[async_trait]
impl PublicKeyRegistry for SledPublicKeyRepository {
    async fn register_public_key(&self, public_key: Vec<u8>) -> Result<NodeId> {
        // Generate NodeId from public key
        let node_id = NodeId::from_public_key(&public_key)?;

        // Store in node_key_tree
        self.node_key_tree
            .insert(node_id.as_str().as_bytes(), public_key.clone())?;

        // Generate default key_id (monas:node:<node_id>)
        let key_id = format!("monas:node:{}", node_id.as_str());

        // Store in key_id_tree
        self.key_id_tree.insert(key_id.as_bytes(), public_key)?;

        // Store mapping
        self.node_to_key_tree
            .insert(node_id.as_str().as_bytes(), key_id.as_bytes())?;

        Ok(node_id)
    }

    async fn get_public_key(&self, node_id: &NodeId) -> Result<Option<Vec<u8>>> {
        Ok(self
            .node_key_tree
            .get(node_id.as_str().as_bytes())?
            .map(|ivec| ivec.to_vec()))
    }

    async fn unregister(&self, node_id: &NodeId) -> Result<bool> {
        // Remove from node_key_tree
        let removed = self
            .node_key_tree
            .remove(node_id.as_str().as_bytes())?
            .is_some();

        // Remove associated key_id if exists
        if let Some(key_id_bytes) = self.node_to_key_tree.remove(node_id.as_str().as_bytes())? {
            self.key_id_tree.remove(key_id_bytes)?;
        }

        Ok(removed)
    }

    async fn is_registered(&self, node_id: &NodeId) -> Result<bool> {
        Ok(self
            .node_key_tree
            .contains_key(node_id.as_str().as_bytes())?)
    }

    async fn list_node_ids(&self) -> Result<Vec<NodeId>> {
        let mut node_ids = Vec::new();

        for result in self.node_key_tree.iter() {
            let (key, _) = result?;
            let node_id_str = std::str::from_utf8(&key)?;
            let node_id = NodeId::from_string(node_id_str.to_string())?;
            node_ids.push(node_id);
        }

        Ok(node_ids)
    }
}

#[async_trait]
impl ExtendedPublicKeyRegistry for SledPublicKeyRepository {
    async fn register_public_key_for_key_id(
        &self,
        key_id: String,
        public_key: Vec<u8>,
    ) -> Result<()> {
        // Store in key_id_tree
        self.key_id_tree
            .insert(key_id.as_bytes(), public_key.clone())?;

        // Also generate and store NodeId if it's a node key
        if key_id.starts_with("monas:node:") || key_id.starts_with("node:") {
            let node_id = NodeId::from_public_key(&public_key)?;
            self.node_key_tree
                .insert(node_id.as_str().as_bytes(), public_key)?;
            self.node_to_key_tree
                .insert(node_id.as_str().as_bytes(), key_id.as_bytes())?;
        }

        Ok(())
    }

    async fn get_public_key_by_key_id(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        // First try direct lookup
        if let Some(key) = self.key_id_tree.get(key_id.as_bytes())? {
            return Ok(Some(key.to_vec()));
        }

        // If not found and it's a simple format (e.g., "user:alice"),
        // try with "monas:" prefix
        if !key_id.starts_with("monas:") && key_id.contains(':') {
            let monas_key_id = format!("monas:{}", key_id);
            if let Some(key) = self.key_id_tree.get(monas_key_id.as_bytes())? {
                return Ok(Some(key.to_vec()));
            }
        }

        Ok(None)
    }

    async fn remove_public_key_by_key_id(&self, key_id: &str) -> Result<bool> {
        // Remove from key_id_tree
        let removed = self.key_id_tree.remove(key_id.as_bytes())?.is_some();

        // If it's a node key, also remove from node trees
        if let Some(public_key_ivec) = self.key_id_tree.get(key_id.as_bytes())? {
            let public_key = public_key_ivec.to_vec();
            if let Ok(node_id) = NodeId::from_public_key(&public_key) {
                self.node_key_tree.remove(node_id.as_str().as_bytes())?;
                self.node_to_key_tree.remove(node_id.as_str().as_bytes())?;
            }
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    async fn create_test_repository() -> (SledPublicKeyRepository, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let repo = SledPublicKeyRepository::open(temp_dir.path()).unwrap();
        (repo, temp_dir)
    }

    fn generate_test_public_key() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut OsRng);
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn test_register_and_get_public_key() {
        let (repo, _temp_dir) = create_test_repository().await;
        let public_key = generate_test_public_key();

        // Register public key
        let node_id = repo.register_public_key(public_key.clone()).await.unwrap();

        // Retrieve by NodeId
        let retrieved = repo.get_public_key(&node_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), public_key);
    }

    #[tokio::test]
    async fn test_register_and_get_by_key_id() {
        let (repo, _temp_dir) = create_test_repository().await;
        let public_key = generate_test_public_key();
        let key_id = "monas:user:alice".to_string();

        // Register with key_id
        repo.register_public_key_for_key_id(key_id.clone(), public_key.clone())
            .await
            .unwrap();

        // Retrieve by key_id
        let retrieved = repo.get_public_key_by_key_id(&key_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), public_key);

        // Should also work without "monas:" prefix
        let retrieved = repo.get_public_key_by_key_id("user:alice").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), public_key);
    }

    #[tokio::test]
    async fn test_list_node_ids() {
        let (repo, _temp_dir) = create_test_repository().await;

        // Register multiple keys
        let key1 = generate_test_public_key();
        let key2 = generate_test_public_key();

        let node_id1 = repo.register_public_key(key1).await.unwrap();
        let node_id2 = repo.register_public_key(key2).await.unwrap();

        // List all node IDs
        let node_ids = repo.list_node_ids().await.unwrap();
        assert_eq!(node_ids.len(), 2);
        assert!(node_ids.contains(&node_id1));
        assert!(node_ids.contains(&node_id2));
    }

    #[tokio::test]
    async fn test_remove_public_key() {
        let (repo, _temp_dir) = create_test_repository().await;
        let public_key = generate_test_public_key();

        // Register and then remove
        let node_id = repo.register_public_key(public_key.clone()).await.unwrap();
        assert!(repo.unregister(&node_id).await.unwrap());

        // Should no longer exist
        let retrieved = repo.get_public_key(&node_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_nonce_tracking() {
        let (repo, _temp_dir) = create_test_repository().await;

        let nonce = "test-nonce-123";

        // First use should succeed
        assert!(repo.check_and_record_nonce(nonce).await.unwrap());

        // Second use should fail (replay attack prevention)
        assert!(!repo.check_and_record_nonce(nonce).await.unwrap());

        // Different nonce should succeed
        assert!(repo
            .check_and_record_nonce("different-nonce")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let public_key = generate_test_public_key();
        let node_id;

        // Create repository and register key
        {
            let repo = SledPublicKeyRepository::open(temp_dir.path()).unwrap();
            node_id = repo.register_public_key(public_key.clone()).await.unwrap();
            repo.flush().await.unwrap();
        }

        // Open new repository instance and verify key persists
        {
            let repo = SledPublicKeyRepository::open(temp_dir.path()).unwrap();
            let retrieved = repo.get_public_key(&node_id).await.unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap(), public_key);
        }
    }

    #[tokio::test]
    async fn test_key_id_with_node_prefix() {
        let (repo, _temp_dir) = create_test_repository().await;
        let public_key = generate_test_public_key();
        let key_id = "node:test-node-123".to_string();

        // Register with node: prefix
        repo.register_public_key_for_key_id(key_id.clone(), public_key.clone())
            .await
            .unwrap();

        // Should be retrievable by key_id
        let retrieved = repo.get_public_key_by_key_id(&key_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), public_key);

        // Should also create NodeId entry
        let node_id = NodeId::from_public_key(&public_key).unwrap();
        let retrieved = repo.get_public_key(&node_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), public_key);
    }
}
