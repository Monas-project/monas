//! Key management for node P-256 keys.

use anyhow::{Context, Result};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

/// Node key pair for P-256 cryptography.
#[derive(Debug, Clone)]
pub struct NodeKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl NodeKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load key pair from file, or generate new if file doesn't exist.
    pub fn load_or_generate(key_path: &Path) -> Result<Self> {
        if key_path.exists() {
            Self::load_from_file(key_path)
        } else {
            let key_pair = Self::generate();
            key_pair.save_to_file(key_path)?;
            Ok(key_pair)
        }
    }

    /// Load key pair from a file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let key_bytes = std::fs::read(path).context("Failed to read key file")?;

        // The file contains the private key bytes (32 bytes)
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "Invalid key file: expected 32 bytes, got {}",
                key_bytes.len()
            );
        }

        let signing_key = SigningKey::from_bytes((&key_bytes[..]).into())
            .context("Failed to parse signing key")?;
        let verifying_key = *signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Save key pair to a file (saves only the private key).
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create key directory")?;
        }

        // Save the private key bytes
        let key_bytes = self.signing_key.to_bytes();
        std::fs::write(path, key_bytes).context("Failed to write key file")?;

        // Set file permissions to 0600 (read/write for owner only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Get the public key in uncompressed SEC1 format (65 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Get the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Generate NodeId from this key pair.
    pub fn node_id(&self) -> Result<crate::domain::value_objects::NodeId> {
        crate::domain::value_objects::NodeId::from_public_key(&self.public_key_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to generate NodeId: {}", e))
    }
}

/// Key store for managing multiple node keys.
pub struct KeyStore {
    base_path: PathBuf,
}

impl KeyStore {
    /// Create a new key store with the given base path.
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Get or generate key pair for a node.
    pub fn get_or_generate_node_key(&self, node_name: &str) -> Result<NodeKeyPair> {
        let key_path = self.base_path.join(format!("{}.p256", node_name));
        NodeKeyPair::load_or_generate(&key_path)
    }

    /// Get the default node key (for the local node).
    pub fn get_default_node_key(&self) -> Result<NodeKeyPair> {
        self.get_or_generate_node_key("node")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = NodeKeyPair::generate();
        let public_key = key_pair.public_key_bytes();

        // P-256 uncompressed public key should be 65 bytes
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04); // Uncompressed point indicator
    }

    #[test]
    fn test_save_and_load_key_pair() {
        let tmp_dir = tempdir().unwrap();
        let key_path = tmp_dir.path().join("test.p256");

        let original = NodeKeyPair::generate();
        original.save_to_file(&key_path).unwrap();

        let loaded = NodeKeyPair::load_from_file(&key_path).unwrap();

        // Public keys should match
        assert_eq!(original.public_key_bytes(), loaded.public_key_bytes());
    }

    #[test]
    fn test_load_or_generate() {
        let tmp_dir = tempdir().unwrap();
        let key_path = tmp_dir.path().join("test.p256");

        // First call should generate
        let key1 = NodeKeyPair::load_or_generate(&key_path).unwrap();
        assert!(key_path.exists());

        // Second call should load the same key
        let key2 = NodeKeyPair::load_or_generate(&key_path).unwrap();
        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

    #[test]
    fn test_node_id_generation() {
        let key_pair = NodeKeyPair::generate();
        let node_id = key_pair.node_id().unwrap();

        // NodeId should be a non-empty string
        assert!(!node_id.as_str().is_empty());

        // Should be deterministic
        let node_id2 = key_pair.node_id().unwrap();
        assert_eq!(node_id.as_str(), node_id2.as_str());
    }

    #[test]
    fn test_key_store() {
        let tmp_dir = tempdir().unwrap();
        let store = KeyStore::new(tmp_dir.path().to_path_buf());

        let key1 = store.get_or_generate_node_key("node1").unwrap();
        let key2 = store.get_or_generate_node_key("node2").unwrap();

        // Different nodes should have different keys
        assert_ne!(key1.public_key_bytes(), key2.public_key_bytes());

        // Same node should have same key when loaded again
        let key1_again = store.get_or_generate_node_key("node1").unwrap();
        assert_eq!(key1.public_key_bytes(), key1_again.public_key_bytes());
    }

    #[test]
    fn test_default_node_key() {
        let tmp_dir = tempdir().unwrap();
        let store = KeyStore::new(tmp_dir.path().to_path_buf());

        let key = store.get_default_node_key().unwrap();
        let key_again = store.get_default_node_key().unwrap();

        // Should be the same key
        assert_eq!(key.public_key_bytes(), key_again.public_key_bytes());
    }
}
