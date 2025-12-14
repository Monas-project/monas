//! Test utilities and mock implementations for unit testing.
//!
//! This module provides mock implementations of the main traits
//! to enable unit testing without real infrastructure dependencies.

use crate::domain::content_network::ContentNetwork;
use crate::domain::events::Event;
use crate::domain::state_node::NodeSnapshot;
use crate::port::content_repository::{CommitResult, ContentRepository, SerializedOperation};
use crate::port::event_publisher::EventPublisher;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::{PersistentContentRepository, PersistentNodeRegistry};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// MockPeerNetwork
// ============================================================================

/// Type alias for published events storage.
pub type PublishedEvents = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Mock implementation of PeerNetwork for testing.
#[derive(Default)]
pub struct MockPeerNetwork {
    pub published_events: PublishedEvents,
    pub closest_peers: Arc<Mutex<Vec<String>>>,
    pub capacities: Arc<Mutex<HashMap<String, u64>>>,
    pub providers: Arc<Mutex<Vec<String>>>,
    pub fetched_operations: Arc<Mutex<Vec<SerializedOperation>>>,
    pub local_peer_id: String,
}

impl MockPeerNetwork {
    pub fn new() -> Self {
        Self {
            published_events: Arc::new(Mutex::new(Vec::new())),
            closest_peers: Arc::new(Mutex::new(Vec::new())),
            capacities: Arc::new(Mutex::new(HashMap::new())),
            providers: Arc::new(Mutex::new(Vec::new())),
            fetched_operations: Arc::new(Mutex::new(Vec::new())),
            local_peer_id: "mock-peer-id".to_string(),
        }
    }

    pub fn with_local_peer_id(mut self, id: &str) -> Self {
        self.local_peer_id = id.to_string();
        self
    }

    pub fn with_closest_peers(self, peers: Vec<String>) -> Self {
        Self {
            closest_peers: Arc::new(Mutex::new(peers)),
            ..self
        }
    }

    pub fn with_capacities(self, caps: HashMap<String, u64>) -> Self {
        Self {
            capacities: Arc::new(Mutex::new(caps)),
            ..self
        }
    }

    pub fn with_providers(self, providers: Vec<String>) -> Self {
        Self {
            providers: Arc::new(Mutex::new(providers)),
            ..self
        }
    }

    pub fn with_fetched_operations(self, ops: Vec<SerializedOperation>) -> Self {
        Self {
            fetched_operations: Arc::new(Mutex::new(ops)),
            ..self
        }
    }
}

#[async_trait]
impl PeerNetwork for MockPeerNetwork {
    async fn find_closest_peers(&self, _key: Vec<u8>, _k: usize) -> Result<Vec<String>> {
        Ok(self.closest_peers.lock().await.clone())
    }

    async fn query_node_capacity_batch(
        &self,
        _peer_ids: &[String],
    ) -> Result<HashMap<String, u64>> {
        Ok(self.capacities.lock().await.clone())
    }

    async fn publish_event(&self, topic: &str, event_data: &[u8]) -> Result<()> {
        self.published_events
            .lock()
            .await
            .push((topic.to_string(), event_data.to_vec()));
        Ok(())
    }

    async fn fetch_content(&self, _peer_id: &str, _content_id: &str) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    async fn publish_provider(&self, _key: Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn local_peer_id(&self) -> String {
        self.local_peer_id.clone()
    }

    async fn fetch_operations(
        &self,
        _peer_id: &str,
        _genesis_cid: &str,
        _since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>> {
        Ok(self.fetched_operations.lock().await.clone())
    }

    async fn push_operations(
        &self,
        _peer_id: &str,
        _genesis_cid: &str,
        operations: &[SerializedOperation],
    ) -> Result<usize> {
        Ok(operations.len())
    }

    async fn broadcast_operation(
        &self,
        _genesis_cid: &str,
        _operation: &SerializedOperation,
    ) -> Result<()> {
        Ok(())
    }

    async fn find_content_providers(&self, _genesis_cid: &str) -> Result<Vec<String>> {
        Ok(self.providers.lock().await.clone())
    }
}

// ============================================================================
// MockEventPublisher
// ============================================================================

/// Mock implementation of EventPublisher for testing.
#[derive(Default)]
pub struct MockEventPublisher {
    pub published_events: Arc<Mutex<Vec<Event>>>,
    pub network_events: Arc<Mutex<Vec<Event>>>,
}

impl MockEventPublisher {
    pub fn new() -> Self {
        Self {
            published_events: Arc::new(Mutex::new(Vec::new())),
            network_events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl EventPublisher for MockEventPublisher {
    async fn publish(&self, event: &Event) -> Result<()> {
        self.published_events.lock().await.push(event.clone());
        Ok(())
    }

    async fn publish_to_network(&self, event: &Event) -> Result<()> {
        self.network_events.lock().await.push(event.clone());
        Ok(())
    }

    async fn subscribe<F>(&self, _event_type: &str, _handler: F) -> Result<()>
    where
        F: Fn(Event) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync + 'static,
    {
        Ok(())
    }
}

// ============================================================================
// MockContentRepository
// ============================================================================

/// Mock implementation of ContentRepository for testing.
#[derive(Default)]
pub struct MockContentRepository {
    pub contents: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub history: Arc<Mutex<HashMap<String, Vec<String>>>>,
    pub operations: Arc<Mutex<Vec<SerializedOperation>>>,
    pub next_cid: Arc<Mutex<u64>>,
}

impl MockContentRepository {
    pub fn new() -> Self {
        Self {
            contents: Arc::new(Mutex::new(HashMap::new())),
            history: Arc::new(Mutex::new(HashMap::new())),
            operations: Arc::new(Mutex::new(Vec::new())),
            next_cid: Arc::new(Mutex::new(1)),
        }
    }
}

#[async_trait]
impl ContentRepository for MockContentRepository {
    async fn create_content(&self, data: &[u8], _author: &str) -> Result<CommitResult> {
        let mut next = self.next_cid.lock().await;
        let genesis_cid = format!("genesis-cid-{}", *next);
        let version_cid = format!("version-cid-{}", *next);
        *next += 1;

        self.contents
            .lock()
            .await
            .insert(genesis_cid.clone(), data.to_vec());
        self.history
            .lock()
            .await
            .insert(genesis_cid.clone(), vec![version_cid.clone()]);

        Ok(CommitResult {
            genesis_cid,
            version_cid,
            is_new: true,
        })
    }

    async fn update_content(
        &self,
        genesis_cid: &str,
        data: &[u8],
        _author: &str,
    ) -> Result<CommitResult> {
        let mut next = self.next_cid.lock().await;
        let version_cid = format!("version-cid-{}", *next);
        *next += 1;

        self.contents
            .lock()
            .await
            .insert(genesis_cid.to_string(), data.to_vec());

        if let Some(history) = self.history.lock().await.get_mut(genesis_cid) {
            history.push(version_cid.clone());
        }

        Ok(CommitResult {
            genesis_cid: genesis_cid.to_string(),
            version_cid,
            is_new: false,
        })
    }

    async fn get_latest(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.contents.lock().await.get(genesis_cid).cloned())
    }

    async fn get_latest_with_version(
        &self,
        genesis_cid: &str,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let contents = self.contents.lock().await;
        let history = self.history.lock().await;

        if let Some(data) = contents.get(genesis_cid) {
            // Get the latest version CID from history
            let version_cid = history
                .get(genesis_cid)
                .and_then(|h| h.last().cloned())
                .unwrap_or_else(|| genesis_cid.to_string());
            Ok(Some((data.clone(), version_cid)))
        } else {
            Ok(None)
        }
    }

    async fn get_version(&self, version_cid: &str) -> Result<Option<Vec<u8>>> {
        // For simplicity, return the first content that matches
        let contents = self.contents.lock().await;
        for (genesis_cid, _) in contents.iter() {
            if let Some(history) = self.history.lock().await.get(genesis_cid) {
                if history.contains(&version_cid.to_string()) {
                    return Ok(contents.get(genesis_cid).cloned());
                }
            }
        }
        Ok(None)
    }

    async fn get_history(&self, genesis_cid: &str) -> Result<Vec<String>> {
        Ok(self
            .history
            .lock()
            .await
            .get(genesis_cid)
            .cloned()
            .unwrap_or_default())
    }

    async fn get_operations(
        &self,
        _genesis_cid: &str,
        _since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>> {
        Ok(self.operations.lock().await.clone())
    }

    async fn apply_operations(&self, operations: &[SerializedOperation]) -> Result<usize> {
        let mut ops = self.operations.lock().await;
        ops.extend(operations.iter().cloned());
        Ok(operations.len())
    }

    async fn exists(&self, genesis_cid: &str) -> Result<bool> {
        Ok(self.contents.lock().await.contains_key(genesis_cid))
    }

    async fn list_contents(&self) -> Result<Vec<String>> {
        Ok(self.contents.lock().await.keys().cloned().collect())
    }
}

// ============================================================================
// MockNodeRegistry
// ============================================================================

/// Mock implementation of PersistentNodeRegistry for testing.
#[derive(Default)]
pub struct MockNodeRegistry {
    pub nodes: Arc<Mutex<HashMap<String, NodeSnapshot>>>,
}

impl MockNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PersistentNodeRegistry for MockNodeRegistry {
    async fn upsert_node(&self, node: &NodeSnapshot) -> Result<()> {
        self.nodes
            .lock()
            .await
            .insert(node.node_id.clone(), node.clone());
        Ok(())
    }

    async fn get_available_capacity(&self, node_id: &str) -> Result<Option<u64>> {
        Ok(self
            .nodes
            .lock()
            .await
            .get(node_id)
            .map(|n| n.available_capacity))
    }

    async fn list_nodes(&self) -> Result<Vec<String>> {
        Ok(self.nodes.lock().await.keys().cloned().collect())
    }

    async fn get_node(&self, node_id: &str) -> Result<Option<NodeSnapshot>> {
        Ok(self.nodes.lock().await.get(node_id).cloned())
    }

    async fn delete_node(&self, node_id: &str) -> Result<()> {
        self.nodes.lock().await.remove(node_id);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// MockContentNetworkRepository
// ============================================================================

/// Mock implementation of PersistentContentRepository for testing.
#[derive(Default)]
pub struct MockContentNetworkRepository {
    pub networks: Arc<Mutex<HashMap<String, ContentNetwork>>>,
}

impl MockContentNetworkRepository {
    pub fn new() -> Self {
        Self {
            networks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_network(self, network: ContentNetwork) -> Self {
        let mut networks = HashMap::new();
        networks.insert(network.content_id.clone(), network);
        Self {
            networks: Arc::new(Mutex::new(networks)),
        }
    }
}

#[async_trait]
impl PersistentContentRepository for MockContentNetworkRepository {
    async fn find_assignable_cids(&self, _capacity: u64) -> Result<Vec<String>> {
        Ok(self.networks.lock().await.keys().cloned().collect())
    }

    async fn get_content_network(&self, content_id: &str) -> Result<Option<ContentNetwork>> {
        Ok(self.networks.lock().await.get(content_id).cloned())
    }

    async fn save_content_network(&self, net: ContentNetwork) -> Result<()> {
        self.networks
            .lock()
            .await
            .insert(net.content_id.clone(), net);
        Ok(())
    }

    async fn delete_content_network(&self, content_id: &str) -> Result<()> {
        self.networks.lock().await.remove(content_id);
        Ok(())
    }

    async fn list_content_networks(&self) -> Result<Vec<String>> {
        Ok(self.networks.lock().await.keys().cloned().collect())
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create a test ContentNetwork with the given members.
pub fn create_test_network(content_id: &str, members: Vec<&str>) -> ContentNetwork {
    ContentNetwork {
        content_id: content_id.to_string(),
        member_nodes: members.into_iter().map(|s| s.to_string()).collect(),
    }
}

/// Create a test NodeSnapshot.
pub fn create_test_node(
    node_id: &str,
    total_capacity: u64,
    available_capacity: u64,
) -> NodeSnapshot {
    NodeSnapshot {
        node_id: node_id.to_string(),
        total_capacity,
        available_capacity,
    }
}

/// Create a test SerializedOperation.
pub fn create_test_operation(genesis_cid: &str, author: &str) -> SerializedOperation {
    SerializedOperation {
        data: vec![1, 2, 3, 4],
        genesis_cid: genesis_cid.to_string(),
        author: author.to_string(),
        timestamp: 12345,
        node_timestamp: 12345,
    }
}
