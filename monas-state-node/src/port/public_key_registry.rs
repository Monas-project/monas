//! Public key registry for managing node public keys.

use crate::domain::value_objects::NodeId;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Registry for managing the association between NodeIds and their public keys.
///
/// Since NodeId is now derived from the public key hash, this registry
/// provides a way to retrieve the original public key from the NodeId.
#[async_trait]
pub trait PublicKeyRegistry: Send + Sync {
    /// Get the public key for a given NodeId.
    async fn get_public_key(&self, node_id: &NodeId) -> Result<Option<Vec<u8>>>;

    /// Register a public key and return its NodeId.
    async fn register_public_key(&self, public_key: Vec<u8>) -> Result<NodeId>;

    /// Remove a public key registration.
    async fn unregister(&self, node_id: &NodeId) -> Result<bool>;

    /// Check if a NodeId is registered.
    async fn is_registered(&self, node_id: &NodeId) -> Result<bool>;

    /// Get all registered NodeIds.
    async fn list_node_ids(&self) -> Result<Vec<NodeId>>;
}

/// In-memory implementation of PublicKeyRegistry for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPublicKeyRegistry {
    registry: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryPublicKeyRegistry {
    /// Create a new in-memory registry.
    pub fn new() -> Self {
        Self {
            registry: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PublicKeyRegistry for InMemoryPublicKeyRegistry {
    async fn get_public_key(&self, node_id: &NodeId) -> Result<Option<Vec<u8>>> {
        let registry = self.registry.read().await;
        Ok(registry.get(node_id.as_str()).cloned())
    }

    async fn register_public_key(&self, public_key: Vec<u8>) -> Result<NodeId> {
        let node_id = NodeId::from_public_key(&public_key)?;
        let mut registry = self.registry.write().await;
        registry.insert(node_id.as_str().to_string(), public_key);
        Ok(node_id)
    }

    async fn unregister(&self, node_id: &NodeId) -> Result<bool> {
        let mut registry = self.registry.write().await;
        Ok(registry.remove(node_id.as_str()).is_some())
    }

    async fn is_registered(&self, node_id: &NodeId) -> Result<bool> {
        let registry = self.registry.read().await;
        Ok(registry.contains_key(node_id.as_str()))
    }

    async fn list_node_ids(&self) -> Result<Vec<NodeId>> {
        let registry = self.registry.read().await;
        let mut node_ids = Vec::new();
        for key in registry.keys() {
            node_ids.push(NodeId::from_string(key.clone())?);
        }
        Ok(node_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    fn generate_test_public_key() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    #[tokio::test]
    async fn test_register_and_retrieve_public_key() {
        let registry = InMemoryPublicKeyRegistry::new();
        let public_key = generate_test_public_key();

        // Register
        let node_id = registry
            .register_public_key(public_key.clone())
            .await
            .unwrap();

        // Retrieve
        let retrieved = registry.get_public_key(&node_id).await.unwrap();
        assert_eq!(retrieved, Some(public_key));
    }

    #[tokio::test]
    async fn test_unregister() {
        let registry = InMemoryPublicKeyRegistry::new();
        let public_key = generate_test_public_key();

        let node_id = registry.register_public_key(public_key).await.unwrap();
        assert!(registry.is_registered(&node_id).await.unwrap());

        let removed = registry.unregister(&node_id).await.unwrap();
        assert!(removed);
        assert!(!registry.is_registered(&node_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_node_ids() {
        let registry = InMemoryPublicKeyRegistry::new();
        let key1 = generate_test_public_key();
        let key2 = generate_test_public_key();

        let id1 = registry.register_public_key(key1).await.unwrap();
        let id2 = registry.register_public_key(key2).await.unwrap();

        let ids = registry.list_node_ids().await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }
}