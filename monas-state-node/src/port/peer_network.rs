//! PeerNetwork trait - Abstract interface for P2P network operations

use crate::port::content_repository::SerializedOperation;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Payload that bootstraps a brand-new content network on the receiver of
/// a `PushOperations` request.
///
/// The first push for a newly-created content network races the gossipsub
/// `Event::ContentCreated` broadcast. The member receiving the push may not
/// yet have a `ContentNetwork` record for this genesis, so the push itself
/// must carry enough membership metadata for the receiver to decide whether
/// to accept the push and persist the network record inline.
///
/// Subsequent (update/delete) pushes leave this as `None`; the receiver then
/// enforces strict membership against its existing record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBootstrap {
    /// The peer_id of the creator sending this push.
    pub creator_node_id: String,
    /// The member set (peer_ids) for the new network. The receiver rejects
    /// the push unless its own peer_id is present in this list.
    pub member_nodes: Vec<String>,
    /// Wall-clock timestamp at creation, for auditability.
    pub created_at: u64,
}

/// Abstract interface for peer-to-peer network operations.
///
/// This trait provides methods for:
/// - DHT-based peer discovery (Kademlia)
/// - Capacity queries via RequestResponse protocol
/// - Event publishing via Gossipsub
/// - Content fetching from peers
/// - CRDT operation synchronization
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    /// Find the k closest peers to a given DHT key.
    ///
    /// Uses Kademlia's GetClosestPeers query.
    async fn find_closest_peers(&self, key: Vec<u8>, k: usize) -> Result<Vec<String>>;

    /// Query node capacities in batch.
    ///
    /// Uses RequestResponse protocol to query multiple peers in parallel.
    async fn query_node_capacity_batch(&self, peer_ids: &[String]) -> Result<HashMap<String, u64>>;

    /// Query node public keys (P-256, SEC1 uncompressed format) in batch.
    ///
    /// Uses RequestResponse protocol to query multiple peers in parallel.
    /// Returns a map of peer_id -> public key (65 bytes).
    async fn query_node_public_keys_batch(
        &self,
        peer_ids: &[String],
    ) -> Result<HashMap<String, Vec<u8>>>;

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

    /// Get the addresses this node is listening on.
    async fn listen_addrs(&self) -> Vec<String>;

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

    /// Push CRDT operations to a peer that already knows this content network.
    ///
    /// The receiver verifies the sender is a known member. For the very first
    /// push to a brand-new network use [`push_operations_with_bootstrap`]
    /// instead.
    async fn push_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
    ) -> Result<usize>;

    /// Push CRDT operations together with a bootstrap payload that lets the
    /// receiver persist its `ContentNetwork` record inline.
    ///
    /// Only used by `create_content` for the first push to member nodes that
    /// haven't received the `Event::ContentCreated` gossipsub message yet.
    async fn push_operations_with_bootstrap(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
        bootstrap: PushBootstrap,
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

    // ========== Relay Methods ==========

    /// Relay an update request to a member node.
    ///
    /// Used when the creator node (non-member) receives an update request
    /// and needs to forward it to a member node for processing.
    async fn relay_update_content(
        &self,
        peer_id: &str,
        content_id: &str,
        data: &[u8],
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool>;

    /// Relay a delete request to a member node.
    ///
    /// Used when the creator node (non-member) receives a delete request
    /// and needs to forward it to a member node for processing.
    async fn relay_delete_content(
        &self,
        peer_id: &str,
        content_id: &str,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool>;

    /// Relay an invalidate_tokens request to a member node.
    ///
    /// Used when the creator node (non-member) receives an invalidate_tokens request
    /// and needs to forward it to a member node for processing.
    async fn relay_invalidate_tokens(
        &self,
        peer_id: &str,
        content_id: &str,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool>;

    // ========== Monitoring Methods ==========

    /// Get the number of currently connected peers.
    async fn connected_peer_count(&self) -> usize;
}
