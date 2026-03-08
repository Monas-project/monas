//! Sled-based public key repository for persistent storage.

use crate::domain::value_objects::NodeId;
use crate::port::public_key_registry::PublicKeyRegistry;
use anyhow::{Context, Result};
use async_trait::async_trait;
use sled::{Db, Transactional};
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

    /// Maximum number of nonce entries before forced cleanup.
    const MAX_NONCE_ENTRIES: usize = 1_000_000;

    /// Check and record a nonce to prevent replay attacks.
    ///
    /// Uses sled's compare-and-swap to atomically check and insert,
    /// preventing TOCTOU race conditions between concurrent requests.
    ///
    /// # Returns
    /// Ok(true) if the nonce is new and was recorded
    /// Ok(false) if the nonce was already used
    pub async fn check_and_record_nonce(&self, nonce: &str) -> Result<bool> {
        let nonce_bytes = nonce.as_bytes();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let timestamp_bytes = timestamp.to_le_bytes();

        // Size limit: clean up aggressively if approaching capacity
        if self.nonce_tree.len() >= Self::MAX_NONCE_ENTRIES {
            tracing::warn!(
                "Nonce store at capacity ({} entries), running cleanup",
                self.nonce_tree.len()
            );
            self.cleanup_old_nonces(timestamp.saturating_sub(3600))?;
            // If still over capacity after 1-hour cleanup, be more aggressive
            if self.nonce_tree.len() >= Self::MAX_NONCE_ENTRIES {
                self.cleanup_old_nonces(timestamp.saturating_sub(300))?;
            }
        }

        // Atomic compare-and-swap: only insert if key does not exist (None -> Some)
        match self.nonce_tree.compare_and_swap(
            nonce_bytes,
            None::<&[u8]>,
            Some(&timestamp_bytes),
        )? {
            Ok(()) => {
                // Successfully recorded — nonce was new
                // Periodically clean up old nonces (older than 1 hour)
                if timestamp % 60 == 0 {
                    self.cleanup_old_nonces(timestamp.saturating_sub(3600))?;
                }
                Ok(true)
            }
            Err(_) => {
                // Nonce already existed
                Ok(false)
            }
        }
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

        let key_id = format!("monas:node:{}", node_id.as_str());
        let node_id_bytes = node_id.as_str().as_bytes().to_vec();
        let key_id_bytes = key_id.as_bytes().to_vec();

        (&self.node_key_tree, &self.key_id_tree, &self.node_to_key_tree)
            .transaction(|(node_key_tx, key_id_tx, node_to_key_tx)|
                -> sled::transaction::ConflictableTransactionResult<(), ()> {
                node_key_tx.insert(node_id_bytes.as_slice(), public_key.as_slice())?;
                key_id_tx.insert(key_id_bytes.as_slice(), public_key.as_slice())?;
                node_to_key_tx.insert(node_id_bytes.as_slice(), key_id_bytes.as_slice())?;
                Ok(())
            })
            .map_err(|e| anyhow::anyhow!("Failed to register public key: {:?}", e))?;

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
}
