//! Persistence traits - Abstract interfaces for data persistence

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::content_network::ContentNetwork;
use crate::domain::state_node::NodeSnapshot;

/// Abstract interface for node registry persistence.
///
/// Extends the basic NodeRegistry with persistence capabilities.
/// Implementations may use sled (native) or IndexedDB (WASM).
#[async_trait]
pub trait PersistentNodeRegistry: Send + Sync {
    /// Insert or update a node snapshot.
    async fn upsert_node(&self, node: &NodeSnapshot) -> Result<()>;

    /// Get the available capacity for a node.
    async fn get_available_capacity(&self, node_id: &str) -> Result<Option<u64>>;

    /// List all known node IDs.
    async fn list_nodes(&self) -> Result<Vec<String>>;

    /// Get a node snapshot by ID.
    async fn get_node(&self, node_id: &str) -> Result<Option<NodeSnapshot>>;

    /// Delete a node from the registry.
    async fn delete_node(&self, node_id: &str) -> Result<()>;

    /// Flush pending writes to disk.
    async fn flush(&self) -> Result<()>;
}

/// Abstract interface for content network persistence.
///
/// Extends the basic ContentNetworkRepository with persistence capabilities.
#[async_trait]
pub trait PersistentContentRepository: Send + Sync {
    /// Find content IDs that can be assigned to a node with given capacity.
    async fn find_assignable_cids(&self, capacity: u64) -> Result<Vec<String>>;

    /// Get a content network by content ID.
    async fn get_content_network(&self, content_id: &str) -> Result<Option<ContentNetwork>>;

    /// Save a content network.
    async fn save_content_network(&self, net: ContentNetwork) -> Result<()>;

    /// Delete a content network.
    async fn delete_content_network(&self, content_id: &str) -> Result<()>;

    /// List all content network IDs.
    async fn list_content_networks(&self) -> Result<Vec<String>>;

    /// Flush pending writes to disk.
    async fn flush(&self) -> Result<()>;
}

/// Content storage operations for raw content data.
#[async_trait]
pub trait PersistentContentStorage: Send + Sync {
    /// Save raw content data.
    async fn save_content(
        &self,
        genesis_cid: Option<&str>,
        data: &[u8],
        updated_node_id: &str,
    ) -> Result<String>;

    /// Get raw content data by CID.
    async fn get_content(&self, cid: &str) -> Result<Option<Vec<u8>>>;

    /// Fetch the latest version of content by genesis CID.
    async fn fetch_latest_by_genesis(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>>;

    /// Delete content by CID.
    async fn delete_content(&self, cid: &str) -> Result<()>;

    /// Flush pending writes to disk.
    async fn flush(&self) -> Result<()>;
}
