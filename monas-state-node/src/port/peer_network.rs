//! PeerNetwork trait - Abstract interface for P2P network operations

use crate::port::content_crdt::SerializedOperation;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Abstract interface for peer-to-peer network operations.
///
/// This trait provides methods for:
/// - DHT-based peer discovery (Kademlia)
/// - Capacity queries via RequestResponse protocol
/// - Event publishing via Gossipsub
/// - Content fetching from peers
/// - CRDT operation synchronization
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    /// Find the k closest peers to a given DHT key.
    ///
    /// Uses Kademlia's GetClosestPeers query.
    async fn find_closest_peers(&self, key: Vec<u8>, k: usize) -> Result<Vec<String>>;

    /// Query node capacities in batch.
    ///
    /// Uses RequestResponse protocol to query multiple peers in parallel.
    async fn query_node_capacity_batch(
        &self,
        peer_ids: &[String],
    ) -> Result<HashMap<String, u64>>;

    /// Publish an event to the network via Gossipsub.
    async fn publish_event(&self, topic: &str, event_data: &[u8]) -> Result<()>;

    /// Fetch content from a specific peer.
    ///
    /// Uses RequestResponse protocol.
    async fn fetch_content(&self, peer_id: &str, content_id: &str) -> Result<Vec<u8>>;

    /// Announce this node as a provider for a content key.
    ///
    /// Uses Kademlia's start_providing.
    async fn publish_provider(&self, key: Vec<u8>) -> Result<()>;

    /// Get the local peer ID as a string.
    fn local_peer_id(&self) -> String;

    // ========== CRDT Synchronization Methods ==========

    /// Fetch CRDT operations from a peer for a specific content.
    ///
    /// Uses RequestResponse protocol to fetch operations since a given version.
    /// If `since_version` is None, fetches all operations.
    async fn fetch_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>>;

    /// Push CRDT operations to a peer.
    ///
    /// Uses RequestResponse protocol to send operations to a peer.
    /// Returns the number of operations accepted by the peer.
    async fn push_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
    ) -> Result<usize>;

    /// Broadcast a new operation to interested peers via Gossipsub.
    ///
    /// This is used for real-time sync of new operations.
    async fn broadcast_operation(
        &self,
        genesis_cid: &str,
        operation: &SerializedOperation,
    ) -> Result<()>;

    /// Find peers that have a specific content.
    ///
    /// Uses Kademlia's get_providers to find content providers.
    async fn find_content_providers(&self, genesis_cid: &str) -> Result<Vec<String>>;
}

/// Synchronous network operations for backward compatibility.
///
/// These methods are kept for compatibility with existing code
/// and will be deprecated in favor of async methods.
pub trait SyncPeerNetwork {
    /// Query node capacity synchronously (deprecated, use async version).
    fn query_node_capacity(&self, node_id: &str) -> Option<u64>;

    /// Query assignable CIDs synchronously (deprecated, use async version).
    fn query_assignable_cids(&self, capacity: u64) -> Vec<String>;
}

