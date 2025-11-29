//! Content storage repository for raw content data.
//!
//! TODO: Integrate with crsl-lib once API is stabilized.
//! For now, this provides a stub implementation.

use anyhow::Result;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::collections::HashMap;
use std::sync::RwLock;

/// Result of saving content.
pub struct SaveResult {
    pub genesis_cid: String,
    pub version_cid: Option<String>,
    pub created: bool,
}

/// Trait for content storage operations.
pub trait ContentStorageRepository: Send + Sync {
    /// Save content and return the result with CIDs.
    fn save_content(
        &self,
        maybe_genesis_cid: Option<&str>,
        data: &[u8],
        author_id: &str,
    ) -> Result<SaveResult>;

    /// Fetch content payload by CID.
    fn fetch_payload_by_cid(&self, payload_cid: &str) -> Result<Vec<u8>>;

    /// Fetch the latest version of content by genesis CID.
    fn fetch_latest_by_genesis(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>>;
}

/// In-memory content storage for development and testing.
///
/// TODO: Replace with crsl-lib based implementation once API is stable.
#[derive(Default)]
pub struct InMemoryContentStorageRepository {
    /// Maps CID to content data.
    content: RwLock<HashMap<String, Vec<u8>>>,
    /// Maps genesis CID to latest version CID.
    latest_versions: RwLock<HashMap<String, String>>,
}

impl InMemoryContentStorageRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ContentStorageRepository for InMemoryContentStorageRepository {
    fn save_content(
        &self,
        maybe_genesis_cid: Option<&str>,
        data: &[u8],
        _author_id: &str,
    ) -> Result<SaveResult> {
        // Generate CID from content
        let mh = Code::Sha2_256.digest(data);
        let content_cid = Cid::new_v1(0x55, mh);
        let cid_str = content_cid.to_string();

        let mut content = self.content.write().unwrap();
        let mut latest = self.latest_versions.write().unwrap();

        if let Some(genesis) = maybe_genesis_cid {
            // Update existing content
            content.insert(cid_str.clone(), data.to_vec());
            latest.insert(genesis.to_string(), cid_str.clone());
            Ok(SaveResult {
                genesis_cid: genesis.to_string(),
                version_cid: Some(cid_str),
                created: false,
            })
        } else {
            // Create new content
            content.insert(cid_str.clone(), data.to_vec());
            latest.insert(cid_str.clone(), cid_str.clone());
            Ok(SaveResult {
                genesis_cid: cid_str.clone(),
                version_cid: None,
                created: true,
            })
        }
    }

    fn fetch_payload_by_cid(&self, payload_cid: &str) -> Result<Vec<u8>> {
        let content = self.content.read().unwrap();
        content
            .get(payload_cid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Content not found: {}", payload_cid))
    }

    fn fetch_latest_by_genesis(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>> {
        let latest = self.latest_versions.read().unwrap();
        let content = self.content.read().unwrap();

        if let Some(latest_cid) = latest.get(genesis_cid) {
            Ok(content.get(latest_cid).cloned())
        } else {
            Ok(None)
        }
    }
}

/// Stub implementation that does nothing (for backward compatibility).
#[derive(Default)]
pub struct CrslContentStorageRepository;

impl ContentStorageRepository for CrslContentStorageRepository {
    fn save_content(
        &self,
        maybe_genesis_cid: Option<&str>,
        data: &[u8],
        _author_id: &str,
    ) -> Result<SaveResult> {
        // Generate CID from content
        let mh = Code::Sha2_256.digest(data);
        let content_cid = Cid::new_v1(0x55, mh);
        let cid_str = content_cid.to_string();

        if let Some(genesis) = maybe_genesis_cid {
            Ok(SaveResult {
                genesis_cid: genesis.to_string(),
                version_cid: Some(cid_str),
                created: false,
            })
        } else {
            Ok(SaveResult {
                genesis_cid: cid_str,
                version_cid: None,
                created: true,
            })
        }
    }

    fn fetch_payload_by_cid(&self, _payload_cid: &str) -> Result<Vec<u8>> {
        // TODO: Implement with crsl-lib
        Ok(Vec::new())
    }

    fn fetch_latest_by_genesis(&self, _genesis_cid: &str) -> Result<Option<Vec<u8>>> {
        // TODO: Implement with crsl-lib
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_save_and_fetch() {
        let repo = InMemoryContentStorageRepository::new();

        // Create new content
        let data = b"hello world";
        let result = repo.save_content(None, data, "author-1").unwrap();
        assert!(result.created);
        assert!(result.version_cid.is_none());

        // Fetch by genesis CID
        let fetched = repo.fetch_latest_by_genesis(&result.genesis_cid).unwrap();
        assert_eq!(fetched, Some(data.to_vec()));

        // Update content
        let new_data = b"hello world updated";
        let update_result = repo
            .save_content(Some(&result.genesis_cid), new_data, "author-1")
            .unwrap();
        assert!(!update_result.created);
        assert!(update_result.version_cid.is_some());

        // Fetch latest should return updated content
        let fetched = repo.fetch_latest_by_genesis(&result.genesis_cid).unwrap();
        assert_eq!(fetched, Some(new_data.to_vec()));
    }
}


