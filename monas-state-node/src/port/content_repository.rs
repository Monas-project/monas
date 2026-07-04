//! ContentRepository trait - Abstract interface for versioned content storage.
//!
//! This module defines the interface for storing and synchronizing content
//! with version history and multi-node synchronization support.

use crate::domain::access_policy::AccessPolicy;
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
    /// DAG node timestamp for CID-consistent replication.
    /// This timestamp is used to generate the same CID across replicas.
    pub node_timestamp: u64,
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

/// Result of preparing a set of operations for a new content network
/// without persisting them locally.
///
/// The creator uses this to derive a deterministic `genesis_cid` and a
/// vector of `SerializedOperation` values it can ship to member nodes via
/// `push_operations`. The operations carry explicit `node_timestamp`s, so
/// when members call `apply_operations` they reproduce the exact same CIDs.
#[derive(Debug, Clone)]
pub struct PreparedCreate {
    pub genesis_cid: String,
    pub operations: Vec<SerializedOperation>,
}

/// Abstract interface for versioned content storage.
///
/// This trait provides methods for:
/// - Creating and updating content with version tracking
/// - Fetching content and its history
/// - Synchronizing operations between nodes
#[async_trait]
pub trait ContentRepository: Send + Sync {
    /// Create new content and return the genesis CID.
    ///
    /// # Arguments
    /// * `data` - The content data to store
    /// * `author` - The author/node ID creating this content
    /// * `access_policy` - Optional access policy to embed in the content
    ///
    /// # Returns
    /// The commit result containing genesis and version CIDs.
    async fn create_content(
        &self,
        data: &[u8],
        author: &str,
        access_policy: Option<AccessPolicy>,
    ) -> Result<CommitResult>;

    /// Update existing content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content to update
    /// * `data` - The new content data
    /// * `author` - The author/node ID making this update
    /// * `access_policy` - Optional access policy. If None, preserves the existing policy.
    ///
    /// # Returns
    /// The commit result containing the new version CID.
    async fn update_content(
        &self,
        genesis_cid: &str,
        data: &[u8],
        author: &str,
        access_policy: Option<AccessPolicy>,
    ) -> Result<CommitResult>;

    /// Get the latest version of content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    ///
    /// # Returns
    /// The latest content data, or None if not found.
    async fn get_latest(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>>;

    /// Get the latest version of content with its version CID.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    ///
    /// # Returns
    /// A tuple of (content data, version CID), or None if not found.
    async fn get_latest_with_version(&self, genesis_cid: &str)
        -> Result<Option<(Vec<u8>, String)>>;

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

    /// Check whether this node actually holds the **genesis node** for the
    /// content (not merely some version of it).
    ///
    /// This differs from [`exists`](Self::exists): `exists` is satisfied by any
    /// node in the genesis series (it uses `latest`), so a node that synced
    /// only later operations — without the genesis itself — still reports
    /// `true`. A local write, however, must traverse the genesis node and fails
    /// with "Genesis not found" if it is absent. Routing local-vs-relay
    /// decisions on `has_genesis` therefore matches what a local commit can
    /// actually do, whereas `exists` can be "true" yet still fail to commit.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID to check
    ///
    /// # Returns
    /// True if the genesis node is present in the local DAG.
    async fn has_genesis(&self, genesis_cid: &str) -> Result<bool>;

    /// List all content genesis CIDs.
    ///
    /// # Returns
    /// List of all genesis CIDs in the repository.
    async fn list_contents(&self) -> Result<Vec<String>>;

    /// Get the access policy for content.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    ///
    /// # Returns
    /// The access policy if one exists.
    async fn get_access_policy(&self, genesis_cid: &str) -> Result<Option<AccessPolicy>>;

    /// Update only the access policy for content, preserving data.
    ///
    /// # Arguments
    /// * `genesis_cid` - The genesis CID of the content
    /// * `access_policy` - The new access policy
    /// * `author` - The author/node ID making this update
    ///
    /// # Returns
    /// The commit result containing the new version CID.
    async fn update_access_policy(
        &self,
        genesis_cid: &str,
        access_policy: AccessPolicy,
        author: &str,
    ) -> Result<CommitResult>;

    /// Build the operations needed to create new content (Create + an
    /// optional AccessPolicy Update) **without** persisting anything in
    /// `self`.
    ///
    /// This exists so the creator node can ship a brand-new content network
    /// to members via `push_operations` without retaining a local copy
    /// (the creator is intentionally excluded from the member set). The
    /// returned `genesis_cid` and `SerializedOperation` values are
    /// deterministic — applying them via `apply_operations` on a member
    /// produces the same CIDs.
    ///
    /// If `owner_identity` is `Some`, the helper also generates an
    /// `AccessPolicy` bound to the genesis_cid with that owner and appends
    /// a policy-update operation to the returned list.
    async fn prepare_create_operations(
        &self,
        data: &[u8],
        author: &str,
        owner_identity: Option<crate::domain::identity::Identity>,
    ) -> Result<PreparedCreate>;
}
