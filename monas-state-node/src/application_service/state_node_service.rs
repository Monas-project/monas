//! State Node Service - Application layer for managing state nodes.

use crate::domain::content_network::ContentNetwork;
use crate::domain::events::{current_timestamp, Event};
use crate::domain::state_node::{self, NodeSnapshot};
use crate::infrastructure::placement::compute_dht_key;
use crate::port::content_repository::ContentRepository;
use crate::port::event_publisher::EventPublisher;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::{PersistentContentRepository, PersistentNodeRegistry};
use anyhow::Result;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Result of applying an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Event was applied, no further action needed.
    Applied,
    /// Event was ignored (not relevant to this node).
    Ignored,
    /// Event was applied and content sync is needed for the given content_id.
    /// The node should call sync_from_peers for this content.
    NeedsSync { content_id: String },
}

// ============================================================================
// StateNodeService - Structured service with dependency injection
// ============================================================================

/// State Node Service with injected dependencies.
///
/// This service provides high-level operations for managing state nodes,
/// content networks, and event publishing.
pub struct StateNodeService<N, C, P, E, R>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
    R: ContentRepository,
{
    node_registry: Arc<tokio::sync::RwLock<N>>,
    content_repo: Arc<tokio::sync::RwLock<C>>,
    peer_network: Arc<P>,
    event_publisher: Arc<E>,
    crdt_repo: Arc<R>,
    local_node_id: String,
}

impl<N, C, P, E, R> StateNodeService<N, C, P, E, R>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
    R: ContentRepository,
{
    /// Create a new StateNodeService.
    ///
    /// The `peer_network` is passed as an `Arc` to allow sharing with other components
    /// (e.g., GossipsubEventPublisher).
    /// The `content_repo` is passed as `Arc<RwLock<C>>` to allow sharing with ContentSyncService.
    pub fn new(
        node_registry: N,
        content_repo: Arc<tokio::sync::RwLock<C>>,
        peer_network: Arc<P>,
        event_publisher: E,
        crdt_repo: Arc<R>,
        local_node_id: String,
    ) -> Self {
        Self {
            node_registry: Arc::new(tokio::sync::RwLock::new(node_registry)),
            content_repo,
            peer_network,
            event_publisher: Arc::new(event_publisher),
            crdt_repo,
            local_node_id,
        }
    }

    /// Get the CRDT repository.
    pub fn crdt_repo(&self) -> &Arc<R> {
        &self.crdt_repo
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// Register a new node.
    ///
    /// This publishes the NodeCreated event both locally and to the network.
    pub async fn register_node(&self, total_capacity: u64) -> Result<(NodeSnapshot, Vec<Event>)> {
        let (snapshot, events) =
            state_node::create_node(self.local_node_id.clone(), total_capacity);

        self.node_registry
            .write()
            .await
            .upsert_node(&snapshot)
            .await?;

        // Publish events both locally and to the network
        for event in &events {
            self.event_publisher.publish_all(event).await?;
        }

        Ok((snapshot, events))
    }

    /// Create new content and assign it to nodes.
    ///
    /// The content will be assigned to other nodes in the network (not the creator).
    /// At least one member node must be available for the content to be created.
    pub async fn create_content(&self, data: &[u8]) -> Result<Event> {
        // 1. Save content to CRDT repository first
        let commit_result = self
            .crdt_repo
            .create_content(data, &self.local_node_id)
            .await?;
        let content_id = commit_result.genesis_cid;

        // 2. Find closest peers for content placement
        let key = compute_dht_key(&content_id);
        let k = 3usize;
        let closest = self.peer_network.find_closest_peers(key, k).await?;
        let caps = self
            .peer_network
            .query_node_capacity_batch(&closest)
            .await?;

        // Select nodes with highest capacity, excluding the creator
        let mut scored: Vec<(u64, String)> = closest
            .into_iter()
            .filter(|peer| peer != &self.local_node_id) // Exclude creator
            .map(|peer| (caps.get(&peer).cloned().unwrap_or(0), peer))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        let selected: Vec<String> = scored.into_iter().take(k).map(|(_, pid)| pid).collect();

        // Validate that we have at least one member node
        if selected.is_empty() {
            return Err(anyhow::anyhow!(
                "Cannot create content: no available member nodes found. \
                 At least one other registered node is required to store the content."
            ));
        }

        // 3. Create content network
        let network = ContentNetwork {
            content_id: content_id.clone(),
            member_nodes: selected.iter().cloned().collect(),
        };
        self.content_repo
            .write()
            .await
            .save_content_network(network)
            .await?;

        // 4. Create and publish event both locally and to the network
        let event = Event::ContentCreated {
            content_id,
            creator_node_id: self.local_node_id.clone(),
            content_size: data.len() as u64,
            member_nodes: selected,
            timestamp: current_timestamp(),
        };

        self.event_publisher.publish_all(&event).await?;

        Ok(event)
    }

    /// Update existing content.
    pub async fn update_content(&self, content_id: &str, data: &[u8]) -> Result<Event> {
        // 1. Verify content network exists
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Content network not found: {}", content_id))?;

        // 2. Verify local node is a member
        if !network.member_nodes.contains(&self.local_node_id) {
            return Err(anyhow::anyhow!(
                "Local node {} is not a member of content network {}",
                self.local_node_id,
                content_id
            ));
        }

        // 3. Update content in CRDT repository
        self.crdt_repo
            .update_content(content_id, data, &self.local_node_id)
            .await?;

        // 4. Create and publish update event both locally and to the network
        let event = Event::ContentUpdated {
            content_id: content_id.to_string(),
            updated_node_id: self.local_node_id.clone(),
            timestamp: current_timestamp(),
        };

        self.event_publisher.publish_all(&event).await?;

        Ok(event)
    }

    /// Handle a sync event from another node.
    ///
    /// Returns `ApplyOutcome::NeedsSync` when the caller should perform content
    /// synchronization (e.g., call `ContentSyncService::sync_from_peers`).
    pub async fn handle_sync_event(&self, event: &Event) -> Result<ApplyOutcome> {
        match event {
            Event::ContentUpdated {
                content_id,
                updated_node_id,
                ..
            } => {
                // Skip if we sent this update ourselves
                if updated_node_id == &self.local_node_id {
                    return Ok(ApplyOutcome::Ignored);
                }

                // Ensure content network exists
                let network = self
                    .content_repo
                    .read()
                    .await
                    .get_content_network(content_id)
                    .await?;

                match network {
                    Some(net) => {
                        // If we're a member of this content network, we need to sync
                        if net.member_nodes.contains(&self.local_node_id) {
                            Ok(ApplyOutcome::NeedsSync {
                                content_id: content_id.clone(),
                            })
                        } else {
                            // We're not a member, just acknowledge
                            Ok(ApplyOutcome::Applied)
                        }
                    }
                    None => {
                        // Network doesn't exist locally, create it (empty members)
                        let network = ContentNetwork {
                            content_id: content_id.clone(),
                            member_nodes: BTreeSet::new(),
                        };
                        self.content_repo
                            .write()
                            .await
                            .save_content_network(network)
                            .await?;
                        Ok(ApplyOutcome::Applied)
                    }
                }
            }

            Event::ContentNetworkManagerAdded {
                content_id,
                member_nodes,
                ..
            } => {
                let network = ContentNetwork {
                    content_id: content_id.clone(),
                    member_nodes: member_nodes.iter().cloned().collect(),
                };
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await?;

                // If we're now a member, we need to sync the content
                if member_nodes.contains(&self.local_node_id) {
                    Ok(ApplyOutcome::NeedsSync {
                        content_id: content_id.clone(),
                    })
                } else {
                    Ok(ApplyOutcome::Applied)
                }
            }

            Event::ContentCreated {
                content_id,
                member_nodes,
                ..
            } => {
                let network = ContentNetwork {
                    content_id: content_id.clone(),
                    member_nodes: member_nodes.iter().cloned().collect(),
                };
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await?;

                // If we're a member of this new content, we need to sync it
                if member_nodes.contains(&self.local_node_id) {
                    Ok(ApplyOutcome::NeedsSync {
                        content_id: content_id.clone(),
                    })
                } else {
                    Ok(ApplyOutcome::Applied)
                }
            }

            Event::NodeCreated {
                node_id,
                total_capacity,
                available_capacity,
                ..
            } => {
                let snapshot = NodeSnapshot {
                    node_id: node_id.clone(),
                    total_capacity: *total_capacity,
                    available_capacity: *available_capacity,
                };
                self.node_registry
                    .write()
                    .await
                    .upsert_node(&snapshot)
                    .await?;
                Ok(ApplyOutcome::Applied)
            }

            _ => Ok(ApplyOutcome::Ignored),
        }
    }

    /// Get node info.
    pub async fn get_node(&self, node_id: &str) -> Result<Option<NodeSnapshot>> {
        self.node_registry.read().await.get_node(node_id).await
    }

    /// List all nodes.
    pub async fn list_nodes(&self) -> Result<Vec<String>> {
        self.node_registry.read().await.list_nodes().await
    }

    /// List all content networks.
    pub async fn list_content_networks(&self) -> Result<Vec<String>> {
        self.content_repo.read().await.list_content_networks().await
    }

    /// Get content network info (test-only).
    ///
    /// This method is only available in tests to verify internal state.
    /// It is not exposed via HTTP API to prevent information leakage.
    #[cfg(test)]
    pub(crate) async fn get_content_network_for_test(
        &self,
        content_id: &str,
    ) -> Result<Option<ContentNetwork>> {
        self.content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        create_test_network, MockContentNetworkRepository, MockContentRepository,
        MockEventPublisher, MockNodeRegistry, MockPeerNetwork,
    };
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    type TestService = StateNodeService<
        MockNodeRegistry,
        MockContentNetworkRepository,
        MockPeerNetwork,
        MockEventPublisher,
        MockContentRepository,
    >;

    fn create_test_service(local_node_id: &str) -> TestService {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(MockContentNetworkRepository::new()));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id(local_node_id));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            local_node_id.to_string(),
        )
    }

    fn create_service_with_peers(
        local_node_id: &str,
        peers: Vec<String>,
        capacities: HashMap<String, u64>,
    ) -> TestService {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(MockContentNetworkRepository::new()));
        let peer_network = Arc::new(
            MockPeerNetwork::new()
                .with_local_peer_id(local_node_id)
                .with_closest_peers(peers)
                .with_capacities(capacities),
        );
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            local_node_id.to_string(),
        )
    }

    #[tokio::test]
    async fn test_local_node_id() {
        let service = create_test_service("node-1");
        assert_eq!(service.local_node_id(), "node-1");
    }

    #[tokio::test]
    async fn test_register_node() {
        let service = create_test_service("node-1");

        let (snapshot, events) = service.register_node(1000).await.unwrap();

        assert_eq!(snapshot.node_id, "node-1");
        assert_eq!(snapshot.total_capacity, 1000);
        assert_eq!(snapshot.available_capacity, 1000);
        assert_eq!(events.len(), 1);

        // Verify node was stored
        let stored_node = service.get_node("node-1").await.unwrap();
        assert!(stored_node.is_some());
        assert_eq!(stored_node.unwrap().total_capacity, 1000);
    }

    #[tokio::test]
    async fn test_register_node_publishes_event() {
        let service = create_test_service("node-1");

        let (_, events) = service.register_node(1000).await.unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::NodeCreated {
                node_id,
                total_capacity,
                available_capacity,
                ..
            } => {
                assert_eq!(node_id, "node-1");
                assert_eq!(*total_capacity, 1000);
                assert_eq!(*available_capacity, 1000);
            }
            _ => panic!("Expected NodeCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_with_peers() {
        let mut capacities = HashMap::new();
        capacities.insert("peer-1".to_string(), 500);
        capacities.insert("peer-2".to_string(), 1000);

        let service = create_service_with_peers(
            "node-1",
            vec!["peer-1".to_string(), "peer-2".to_string()],
            capacities,
        );

        let event = service.create_content(b"test data").await.unwrap();

        match event {
            Event::ContentCreated {
                creator_node_id,
                member_nodes,
                content_size,
                ..
            } => {
                assert_eq!(creator_node_id, "node-1");
                assert!(!member_nodes.is_empty());
                assert_eq!(content_size, 9); // "test data" length
            }
            _ => panic!("Expected ContentCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_excludes_creator() {
        let mut capacities = HashMap::new();
        capacities.insert("node-1".to_string(), 1000); // Creator
        capacities.insert("peer-1".to_string(), 500);

        let service = create_service_with_peers(
            "node-1",
            vec!["node-1".to_string(), "peer-1".to_string()],
            capacities,
        );

        let event = service.create_content(b"test data").await.unwrap();

        match event {
            Event::ContentCreated { member_nodes, .. } => {
                // Creator should be excluded from members
                assert!(!member_nodes.contains(&"node-1".to_string()));
                assert!(member_nodes.contains(&"peer-1".to_string()));
            }
            _ => panic!("Expected ContentCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_fails_without_peers() {
        let service = create_test_service("node-1");

        let result = service.create_content(b"test data").await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no available member nodes"));
    }

    #[tokio::test]
    async fn test_update_content_success() {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        // Pre-populate CRDT repo
        crdt_repo
            .contents
            .lock()
            .await
            .insert("content-1".to_string(), b"old data".to_vec());

        let service = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        let event = service
            .update_content("content-1", b"new data")
            .await
            .unwrap();

        match event {
            Event::ContentUpdated {
                content_id,
                updated_node_id,
                ..
            } => {
                assert_eq!(content_id, "content-1");
                assert_eq!(updated_node_id, "node-1");
            }
            _ => panic!("Expected ContentUpdated event"),
        }
    }

    #[tokio::test]
    async fn test_update_content_fails_if_not_member() {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-2", "node-3"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        let result = service.update_content("content-1", b"new data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a member"));
    }

    #[tokio::test]
    async fn test_update_content_fails_if_network_not_found() {
        let service = create_test_service("node-1");

        let result = service.update_content("nonexistent", b"data").await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Content network not found"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_node_created() {
        let service = create_test_service("node-1");

        let event = Event::NodeCreated {
            node_id: "node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 1500,
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);

        // Verify node was stored
        let stored = service.get_node("node-2").await.unwrap().unwrap();
        assert_eq!(stored.total_capacity, 2000);
        assert_eq!(stored.available_capacity, 1500);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_created_as_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-2".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );

        // Verify content network was stored
        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert!(network.member_nodes.contains("node-1"));
        assert!(network.member_nodes.contains("node-2"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_created_not_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-2".to_string(),
            content_size: 100,
            member_nodes: vec!["node-2".to_string(), "node-3".to_string()], // node-1 not included
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is NOT a member, so just Applied
        assert_eq!(outcome, ApplyOutcome::Applied);

        // Verify content network was stored
        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert!(!network.member_nodes.contains("node-1"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_creates_network_if_missing() {
        let service = create_test_service("node-1");

        // ContentUpdated for a content we don't know about
        let event = Event::ContentUpdated {
            content_id: "new-content".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // Network didn't exist, so it's created with empty members, no sync needed
        assert_eq!(outcome, ApplyOutcome::Applied);

        // Verify network was created (empty members)
        let network = service
            .get_content_network_for_test("new-content")
            .await
            .unwrap()
            .unwrap();
        assert!(network.member_nodes.is_empty());
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_as_member_needs_sync() {
        // Create service with pre-existing content network where node-1 is a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        // ContentUpdated from another node
        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_ignores_self() {
        // Create service with pre-existing content network where node-1 is a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        // ContentUpdated from ourselves - should be ignored
        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-1".to_string(), // Same as local node
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // Should be ignored since we sent it
        assert_eq!(outcome, ApplyOutcome::Ignored);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_not_member() {
        // Create service with pre-existing content network where node-1 is NOT a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-2", "node-3"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is NOT a member, so just Applied (no sync needed)
        assert_eq!(outcome, ApplyOutcome::Applied);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_network_manager_added_as_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentNetworkManagerAdded {
            content_id: "content-1".to_string(),
            added_node_id: "node-3".to_string(),
            member_nodes: vec![
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string(),
            ],
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );

        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(network.member_nodes.len(), 3);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_network_manager_added_not_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentNetworkManagerAdded {
            content_id: "content-1".to_string(),
            added_node_id: "node-3".to_string(),
            member_nodes: vec!["node-2".to_string(), "node-3".to_string()], // node-1 not included
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        // node-1 is NOT a member
        assert_eq!(outcome, ApplyOutcome::Applied);

        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(network.member_nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_handle_sync_event_unknown_event_ignored() {
        let service = create_test_service("node-1");

        let event = Event::AssignmentDecided {
            assigning_node_id: "node-1".to_string(),
            assigned_node_id: "node-2".to_string(),
            content_id: "content-1".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Ignored);
    }

    #[tokio::test]
    async fn test_list_nodes() {
        let service = create_test_service("node-1");

        // Register some nodes
        service.register_node(1000).await.unwrap();

        // Handle sync event to add another node
        let event = Event::NodeCreated {
            node_id: "node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 2000,
            timestamp: 12345,
        };
        service.handle_sync_event(&event).await.unwrap();

        let nodes = service.list_nodes().await.unwrap();
        assert!(nodes.contains(&"node-1".to_string()));
        assert!(nodes.contains(&"node-2".to_string()));
    }

    #[tokio::test]
    async fn test_list_content_networks() {
        let service = create_test_service("node-1");

        // Add content networks via sync events
        let event1 = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12345,
        };
        let event2 = Event::ContentCreated {
            content_id: "content-2".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 200,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12346,
        };

        service.handle_sync_event(&event1).await.unwrap();
        service.handle_sync_event(&event2).await.unwrap();

        let networks = service.list_content_networks().await.unwrap();
        assert!(networks.contains(&"content-1".to_string()));
        assert!(networks.contains(&"content-2".to_string()));
    }

    #[tokio::test]
    async fn test_get_content_network_not_found() {
        let service = create_test_service("node-1");

        let result = service
            .get_content_network_for_test("nonexistent")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_not_found() {
        let service = create_test_service("node-1");

        let result = service.get_node("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
