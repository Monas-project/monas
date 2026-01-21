//! Sled-based access policy repository implementation.

use crate::domain::access_policy::AccessPolicy;
use crate::port::persistence::PersistentAccessPolicyRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;

/// Sled-based repository for access policies
pub struct SledAccessPolicyRepository {
    db: sled::Db,
    tree_name: String,
}

impl SledAccessPolicyRepository {
    /// Create a new repository with the given database
    pub fn new(db: sled::Db) -> Self {
        Self {
            db,
            tree_name: "access_policies".to_string(),
        }
    }

    /// Create a new repository with custom tree name
    pub fn with_tree_name(db: sled::Db, tree_name: String) -> Self {
        Self { db, tree_name }
    }

    /// Get the tree for access policies
    fn tree(&self) -> Result<sled::Tree> {
        self.db
            .open_tree(&self.tree_name)
            .context("Failed to open access policies tree")
    }

    /// Serialize an access policy to bytes
    fn serialize_policy(policy: &AccessPolicy) -> Result<Vec<u8>> {
        serde_json::to_vec(policy).context("Failed to serialize access policy")
    }

    /// Deserialize an access policy from bytes
    fn deserialize_policy(bytes: &[u8]) -> Result<AccessPolicy> {
        serde_json::from_slice(bytes).context("Failed to deserialize access policy")
    }
}

#[async_trait]
impl PersistentAccessPolicyRepository for SledAccessPolicyRepository {
    async fn get_policy(&self, content_id: &str) -> Result<Option<AccessPolicy>> {
        let tree = self.tree()?;
        let key = content_id.as_bytes();

        match tree.get(key).context("Failed to get policy from tree")? {
            Some(bytes) => {
                let policy = Self::deserialize_policy(&bytes)?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    async fn save_policy(&self, policy: &AccessPolicy) -> Result<()> {
        let tree = self.tree()?;
        let key = policy.content_id().as_str().as_bytes();
        let value = Self::serialize_policy(policy)?;

        tree.insert(key, value)
            .context("Failed to insert policy into tree")?;

        Ok(())
    }

    async fn delete_policy(&self, content_id: &str) -> Result<()> {
        let tree = self.tree()?;
        let key = content_id.as_bytes();

        tree.remove(key)
            .context("Failed to remove policy from tree")?;

        Ok(())
    }

    async fn list_policies(&self) -> Result<Vec<String>> {
        let tree = self.tree()?;
        let mut policies = Vec::new();

        for result in tree.iter() {
            let (key, _) = result.context("Failed to iterate over policies")?;
            let content_id =
                String::from_utf8(key.to_vec()).context("Failed to convert key to string")?;
            policies.push(content_id);
        }

        Ok(policies)
    }

    async fn flush(&self) -> Result<()> {
        self.db.flush().context("Failed to flush database")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::access_policy::AccessPolicy;
    use crate::domain::auth_capability::AuthCapability;
    use crate::domain::identity::Identity;
    use crate::domain::value_objects::ContentId;

    fn create_test_db() -> sled::Db {
        sled::Config::new().temporary(true).open().unwrap()
    }

    fn create_test_policy() -> AccessPolicy {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let owner = Identity::user("alice".to_string()).unwrap();
        AccessPolicy::new(content_id, owner)
    }

    #[tokio::test]
    async fn test_save_and_get_policy() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        let policy = create_test_policy();
        let content_id = policy.content_id().as_str();

        // Save policy
        repo.save_policy(&policy).await.unwrap();

        // Get policy
        let retrieved = repo.get_policy(content_id).await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.content_id(), policy.content_id());
        assert_eq!(retrieved.owner(), policy.owner());
    }

    #[tokio::test]
    async fn test_get_nonexistent_policy() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        let result = repo.get_policy("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_policy() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        let policy = create_test_policy();
        let content_id = policy.content_id().as_str();

        // Save policy
        repo.save_policy(&policy).await.unwrap();
        assert!(repo.get_policy(content_id).await.unwrap().is_some());

        // Delete policy
        repo.delete_policy(content_id).await.unwrap();
        assert!(repo.get_policy(content_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_policies() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        // Save multiple policies
        for i in 0..3 {
            let content_id = ContentId::new(format!("content-{}", i)).unwrap();
            let owner = Identity::user(format!("user-{}", i)).unwrap();
            let policy = AccessPolicy::new(content_id, owner);
            repo.save_policy(&policy).await.unwrap();
        }

        // List policies
        let policies = repo.list_policies().await.unwrap();
        assert_eq!(policies.len(), 3);
        assert!(policies.contains(&"content-0".to_string()));
        assert!(policies.contains(&"content-1".to_string()));
        assert!(policies.contains(&"content-2".to_string()));
    }

    #[tokio::test]
    async fn test_update_policy() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        let mut policy = create_test_policy();
        let content_id = policy.content_id().as_str().to_string(); // Clone to own the string

        // Save initial policy
        repo.save_policy(&policy).await.unwrap();

        // Update policy (grant access to bob)
        let bob = Identity::user("bob".to_string()).unwrap();
        policy
            .grant(bob.clone(), vec![AuthCapability::ReadContent])
            .unwrap();
        repo.save_policy(&policy).await.unwrap();

        // Verify update
        let retrieved = repo.get_policy(&content_id).await.unwrap().unwrap();
        assert!(retrieved.has_capability(&bob, &AuthCapability::ReadContent));
    }

    #[tokio::test]
    async fn test_flush() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::new(db);

        let policy = create_test_policy();
        repo.save_policy(&policy).await.unwrap();

        // Flush should not error
        repo.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_custom_tree_name() {
        let db = create_test_db();
        let repo = SledAccessPolicyRepository::with_tree_name(db, "custom_tree".to_string());

        let policy = create_test_policy();
        repo.save_policy(&policy).await.unwrap();

        let retrieved = repo.get_policy(policy.content_id().as_str()).await.unwrap();
        assert!(retrieved.is_some());
    }
}
