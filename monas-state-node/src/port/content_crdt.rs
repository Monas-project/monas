//! ContentCrdtRepository trait - Abstract interface for CRDT-based content storage.
//!
//! This module defines the interface for storing and synchronizing content
//! using CRDT (Conflict-free Replicated Data Types) via crsl-lib.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Represents a CRDT operation that can be serialized and sent over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedOperation {
    /// The serialized operation bytes (CBOR encoded).
    pub data: Vec<u8>,
    /// The genesis CID this operation belongs to.
    pub genesis_cid: String,
    /// The author of this operation.
    pub author: String,
    /// Timestamp of this operation.
    pub timestamp: u64,
}

/// Result of committing content to the CRDT store.
#[derive(Debug, Clone)]
pub struct CommitResult {
    /// The genesis CID (content identifier).
    pub genesis_cid: String,
    /// The version CID of this specific commit.
    pub version_cid: String,
    /// Whether this was a new content creation.
    pub is_new: bool,
}

/// Abstract interface for CRDT-based content storage.
///
/// This trait provides methods for:
/// - Creating and updating content with CRDT operations
/// - Fetching content and its history
/// - Synchronizing operations between nodes
#[async_trait]
pub trait ContentCrdtRepository: Send + Sync {
    /// Create new content and return the genesis CID.
    ///
    /// # Arguments
    /// * `data` - The content data to store
    /// * `author` - The author/node ID creating this content
    ///
    /// # Returns
    /// The commit result containing genesis and version CIDs.
    async fn create_content(&self, data: &[u8], author: &str) -> Result<CommitResult>;

    /// Update existing content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content to update
    /// * `data` - The new content data
    /// * `author` - The author/node ID making this update
    ///
    /// # Returns
    /// The commit result containing the new version CID.
    async fn update_content(
        &self,
        genesis_cid: &str,
        data: &[u8],
        author: &str,
    ) -> Result<CommitResult>;

    /// Get the latest version of content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    ///
    /// # Returns
    /// The latest content data, or None if not found.
    async fn get_latest(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>>;

    /// Get content at a specific version.
    ///
    /// # Arguments
    /// * `version_cid` - The specific version CID
    ///
    /// # Returns
    /// The content data at that version, or None if not found.
    async fn get_version(&self, version_cid: &str) -> Result<Option<Vec<u8>>>;

    /// Get the version history of content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    ///
    /// # Returns
    /// List of version CIDs in chronological order.
    async fn get_history(&self, genesis_cid: &str) -> Result<Vec<String>>;

    /// Get operations for synchronization.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    /// * `since_version` - Optional version to get operations after
    ///
    /// # Returns
    /// List of serialized operations for sync.
    async fn get_operations(
        &self,
        genesis_cid: &str,
        since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>>;

    /// Apply operations received from another node.
    ///
    /// # Arguments
    /// * `operations` - The serialized operations to apply
    ///
    /// # Returns
    /// Number of operations successfully applied.
    async fn apply_operations(&self, operations: &[SerializedOperation]) -> Result<usize>;

    /// Check if content exists.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID to check
    ///
    /// # Returns
    /// True if the content exists.
    async fn exists(&self, genesis_cid: &str) -> Result<bool>;

    /// List all content genesis CIDs.
    ///
    /// # Returns
    /// List of all genesis CIDs in the repository.
    async fn list_contents(&self) -> Result<Vec<String>>;
}

