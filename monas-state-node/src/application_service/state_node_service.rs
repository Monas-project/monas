//! State Node Service - Application layer for managing state nodes.

use crate::domain::content_network::{self, ContentNetwork};
use crate::domain::events::{current_timestamp, Event};
use crate::domain::placement::{compute_dht_key, DhtPlacementProof};
use crate::domain::state_node::{self, AssignmentRequest, AssignmentResponse, NodeSnapshot};
use crate::infrastructure::content_storage_repository::ContentStorageRepository;
use crate::port::event_publisher::EventPublisher;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::{PersistentContentRepository, PersistentNodeRegistry};
use anyhow::Result;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Result of applying an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Ignored,
}

/// Node registry for managing node snapshots (synchronous interface).
pub trait NodeRegistry {
    fn upsert_node(&mut self, node: &NodeSnapshot);
    fn get_available_capacity(&self, node_id: &str) -> Option<u64>;
    fn list_nodes(&self) -> Vec<String>;
}

/// Content network repository for managing content networks (synchronous interface).
pub trait ContentNetworkRepository {
    fn find_assignable_cids(&self, capacity: u64) -> Vec<String>;
    fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork>;
    fn save_content_network(&mut self, net: ContentNetwork);
}

/// Legacy peer network trait for backward compatibility.
#[async_trait::async_trait]
pub trait LegacyPeerNetwork: Send + Sync {
    fn query_node_capacity(&self, node_id: &str) -> Option<u64>;
    fn query_assignable_cids(&self, capacity: u64) -> Vec<String>;

    async fn find_closest_peers(&self, _key: Vec<u8>, _k: usize) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn query_node_capacity_batch(
        &self,
        _peer_ids: &[String],
    ) -> anyhow::Result<HashMap<String, u64>> {
        Ok(HashMap::new())
    }

    async fn publish_provider(&self, _key: Vec<u8>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Content Sync network abstraction.
pub trait ContentSyncNetwork {
    fn fetch_encoded_ops(&self, content_id: &str, from_node_id: &str) -> Vec<u8>;
}

/// In-memory content directory implementation.
#[derive(Default)]
pub struct InMemoryContentDirectory {
    pub cids_by_required_capacity: Vec<(u64, String)>,
    pub networks: HashMap<String, ContentNetwork>,
}

impl ContentNetworkRepository for InMemoryContentDirectory {
    fn find_assignable_cids(&self, capacity: u64) -> Vec<String> {
        self.cids_by_required_capacity
            .iter()
            .filter(|(need, _)| *need <= capacity)
            .map(|(_, cid)| cid.clone())
            .collect()
    }
    fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork> {
        self.networks.get(content_id).cloned()
    }
    fn save_content_network(&mut self, net: ContentNetwork) {
        self.networks.insert(net.content_id.clone(), net);
    }
}

// ============================================================================
// StateNodeService - Structured service with dependency injection
// ============================================================================

/// State Node Service with injected dependencies.
///
/// This service provides high-level operations for managing state nodes,
/// content networks, and event publishing.
pub struct StateNodeService<N, C, P, E>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
{
    node_registry: Arc<tokio::sync::RwLock<N>>,
    content_repo: Arc<tokio::sync::RwLock<C>>,
    peer_network: Arc<P>,
    event_publisher: Arc<E>,
    local_node_id: String,
}

impl<N, C, P, E> StateNodeService<N, C, P, E>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
{
    /// Create a new StateNodeService.
    pub fn new(
        node_registry: N,
        content_repo: C,
        peer_network: P,
        event_publisher: E,
        local_node_id: String,
    ) -> Self {
        Self {
            node_registry: Arc::new(tokio::sync::RwLock::new(node_registry)),
            content_repo: Arc::new(tokio::sync::RwLock::new(content_repo)),
            peer_network: Arc::new(peer_network),
            event_publisher: Arc::new(event_publisher),
            local_node_id,
        }
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// Register a new node.
    pub async fn register_node(&self, total_capacity: u64) -> Result<(NodeSnapshot, Vec<Event>)> {
        let (snapshot, events) = state_node::create_node(self.local_node_id.clone(), total_capacity);
        
        self.node_registry.write().await.upsert_node(&snapshot).await?;
        
        for event in &events {
            self.event_publisher.publish(event).await?;
        }
        
        Ok((snapshot, events))
    }

    /// Create new content and assign it to nodes.
    pub async fn create_content(&self, data: &[u8]) -> Result<Event> {
        // Generate CID from content
        let mh = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, mh);
        let content_id = cid.to_string();

        // Find closest peers for content placement
        let key = compute_dht_key(&content_id);
        let k = 3usize;
        let closest = self.peer_network.find_closest_peers(key, k).await?;
        let caps = self.peer_network.query_node_capacity_batch(&closest).await?;

        // Select nodes with highest capacity
        let mut scored: Vec<(u64, String)> = closest
            .into_iter()
            .map(|peer| (caps.get(&peer).cloned().unwrap_or(0), peer))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        let selected: Vec<String> = scored.into_iter().take(k).map(|(_, pid)| pid).collect();

        // Create content network
        let network = ContentNetwork {
            content_id: content_id.clone(),
            member_nodes: selected.iter().cloned().collect(),
        };
        self.content_repo.write().await.save_content_network(network).await?;

        // Create and publish event
        let event = Event::ContentCreated {
            content_id,
            creator_node_id: self.local_node_id.clone(),
            content_size: data.len() as u64,
            member_nodes: selected,
            timestamp: current_timestamp(),
        };

        self.event_publisher.publish(&event).await?;

        Ok(event)
    }

    /// Update existing content.
    pub async fn update_content(&self, content_id: &str, _data: &[u8]) -> Result<Event> {
        // Verify content network exists
        let network = self.content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Content network not found: {}", content_id))?;

        // Verify local node is a member
        if !network.member_nodes.contains(&self.local_node_id) {
            return Err(anyhow::anyhow!(
                "Local node {} is not a member of content network {}",
                self.local_node_id,
                content_id
            ));
        }

        // Create and publish update event
        let event = Event::ContentUpdated {
            content_id: content_id.to_string(),
            updated_node_id: self.local_node_id.clone(),
            timestamp: current_timestamp(),
        };

        self.event_publisher.publish(&event).await?;

        Ok(event)
    }

    /// Handle a sync event from another node.
    pub async fn handle_sync_event(&self, event: &Event) -> Result<ApplyOutcome> {
        match event {
            Event::ContentUpdated { content_id, .. } => {
                // Ensure content network exists
                let exists = self.content_repo
                    .read()
                    .await
                    .get_content_network(content_id)
                    .await?
                    .is_some();

                if !exists {
                    let network = ContentNetwork {
                        content_id: content_id.clone(),
                        member_nodes: BTreeSet::new(),
                    };
                    self.content_repo.write().await.save_content_network(network).await?;
                }

                Ok(ApplyOutcome::Applied)
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
                self.content_repo.write().await.save_content_network(network).await?;
                Ok(ApplyOutcome::Applied)
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
                self.content_repo.write().await.save_content_network(network).await?;
                Ok(ApplyOutcome::Applied)
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
                self.node_registry.write().await.upsert_node(&snapshot).await?;
                Ok(ApplyOutcome::Applied)
            }

            _ => Ok(ApplyOutcome::Ignored),
        }
    }

    /// Get content network info.
    pub async fn get_content_network(&self, content_id: &str) -> Result<Option<ContentNetwork>> {
        self.content_repo.read().await.get_content_network(content_id).await
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
}

// ============================================================================
// Legacy functions for backward compatibility
// ============================================================================

pub fn register_node(
    directory: &mut dyn NodeRegistry,
    node_id: String,
    total_capacity: u64,
) -> (NodeSnapshot, Vec<Event>) {
    let (snapshot, events) = state_node::create_node(node_id, total_capacity);
    directory.upsert_node(&snapshot);
    (snapshot, events)
}

pub fn handle_assignment_request(
    node_registry: &dyn NodeRegistry,
    content_repo: &dyn ContentNetworkRepository,
    peer_network: Option<&dyn LegacyPeerNetwork>,
    assigning_node_id: &str,
    requesting_node: &NodeSnapshot,
) -> (AssignmentRequest, AssignmentResponse, Vec<Event>) {
    let request: AssignmentRequest = state_node::build_assignment_request(requesting_node);
    let capacity = node_registry
        .get_available_capacity(&request.requesting_node_id)
        .or_else(|| peer_network.and_then(|n| n.query_node_capacity(&request.requesting_node_id)))
        .unwrap_or(request.available_capacity);

    let mut candidate_cids = content_repo.find_assignable_cids(capacity);
    if candidate_cids.is_empty() {
        if let Some(net) = peer_network {
            candidate_cids = net.query_assignable_cids(capacity);
        }
    }
    let (response, events) =
        state_node::decide_assignment(assigning_node_id, &request, &candidate_cids);
    (request, response, events)
}

pub fn add_member_node(
    content_repo: &mut dyn ContentNetworkRepository,
    content_id: &str,
    added_node_id: &str,
) -> Vec<Event> {
    let base = content_repo
        .get_content_network(content_id)
        .unwrap_or_else(|| ContentNetwork {
            content_id: content_id.to_string(),
            member_nodes: BTreeSet::new(),
        });
    let (updated, events) = content_network::add_member_node(base, added_node_id.to_string());
    content_repo.save_content_network(updated);
    events
}

pub async fn upload_content(
    content_repo: &mut dyn ContentNetworkRepository,
    _storage_repo: &dyn ContentStorageRepository,
    _node_registry: &dyn NodeRegistry,
    peer_network: &dyn PeerNetwork,
    content_id: &str,
    data: &[u8],
    _updated_node_id: &str,
) -> Result<Vec<Event>> {
    let trimmed = content_id.trim();
    let genesis_cid = if trimmed.is_empty() {
        let mh = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, mh);
        cid.to_string()
    } else {
        trimmed.to_string()
    };

    let key = compute_dht_key(&genesis_cid);
    let k = 3usize;
    let closest = peer_network.find_closest_peers(key.clone(), k).await?;
    let caps = peer_network.query_node_capacity_batch(&closest).await?;
    
    let mut scored: Vec<(u64, String)> = closest
        .into_iter()
        .map(|peer| (caps.get(&peer).cloned().unwrap_or(0u64), peer))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let selected: Vec<String> = scored.into_iter().take(k).map(|(_, pid)| pid).collect();
    
    let _proof = DhtPlacementProof {
        closest_peers: selected.clone(),
        capacity_evidence: caps.into_iter().collect(),
    };

    let mut net = content_repo
        .get_content_network(&genesis_cid)
        .unwrap_or(ContentNetwork {
            content_id: genesis_cid.clone(),
            member_nodes: BTreeSet::new(),
        });
    let mut events: Vec<Event> = Vec::new();
    for node_id in selected {
        let (updated, mut evts) = content_network::add_member_node(net, node_id);
        net = updated;
        events.append(&mut evts);
    }
    content_repo.save_content_network(net);

    Ok(events)
}

pub fn handle_content_sync(
    content_repo: &mut dyn ContentNetworkRepository,
    storage_repo: &dyn ContentStorageRepository,
    _sync_network: &dyn ContentSyncNetwork,
    event: &Event,
) -> Result<ApplyOutcome> {
    match event {
        Event::ContentUpdated {
            content_id,
            updated_node_id,
            ..
        } => {
            if let Some(latest) = storage_repo.fetch_latest_by_genesis(content_id)? {
                let _ = storage_repo.save_content(Some(content_id.as_str()), &latest, updated_node_id)?;
            }
            if content_repo.get_content_network(content_id).is_none() {
                let net = ContentNetwork {
                    content_id: content_id.clone(),
                    member_nodes: BTreeSet::new(),
                };
                content_repo.save_content_network(net);
            }
            Ok(ApplyOutcome::Applied)
        }
        Event::ContentNetworkManagerAdded {
            content_id,
            member_nodes,
            ..
        } => {
            let mut net = content_repo
                .get_content_network(content_id)
                .unwrap_or_else(|| ContentNetwork {
                    content_id: content_id.clone(),
                    member_nodes: BTreeSet::new(),
                });
            net.member_nodes = member_nodes.iter().cloned().collect();
            content_repo.save_content_network(net);
            Ok(ApplyOutcome::Applied)
        }
        _ => Ok(ApplyOutcome::Ignored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::content_network_repository::ContentNetworkRepositoryImpl;
    use crate::infrastructure::node_repository::NodeRegistryImpl;

    struct StubPeerNetwork {
        capacity: Option<u64>,
        cids: Vec<String>,
    }

    impl LegacyPeerNetwork for StubPeerNetwork {
        fn query_node_capacity(&self, _node_id: &str) -> Option<u64> {
            self.capacity
        }
        fn query_assignable_cids(&self, _capacity: u64) -> Vec<String> {
            self.cids.clone()
        }
    }

    #[test]
    fn register_node_returns_snapshot_and_event() {
        let mut nodes = NodeRegistryImpl::default();
        let (snapshot, events) = register_node(&mut nodes, "node-A".into(), 1_000);

        assert_eq!(snapshot.node_id, "node-A");
        assert_eq!(snapshot.total_capacity, 1_000);
        assert_eq!(snapshot.available_capacity, 1_000);
        assert_eq!(events.len(), 1);
        assert_eq!(nodes.get_available_capacity("node-A"), Some(1_000));
    }

    #[test]
    fn handle_assignment_request_uses_repo_candidates() {
        let mut nodes = NodeRegistryImpl::default();
        let (a, _) = register_node(&mut nodes, "node-A".into(), 800);

        let mut contents = ContentNetworkRepositoryImpl::default();
        contents
            .cids_by_required_capacity
            .push((500, "cid-1".to_string()));

        let (_req, resp, events) = handle_assignment_request(&nodes, &contents, None, "node-B", &a);

        assert!(resp.assigned_content_network.is_some());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn handle_assignment_request_falls_back_to_peer_network() {
        let mut nodes = NodeRegistryImpl::default();
        let (a, _) = register_node(&mut nodes, "node-A".into(), 400);

        let contents = ContentNetworkRepositoryImpl::default();
        let peer = StubPeerNetwork {
            capacity: Some(400),
            cids: vec!["cid-x".into()],
        };

        let (_req, resp, events) =
            handle_assignment_request(&nodes, &contents, Some(&peer), "node-B", &a);

        assert!(resp.assigned_content_network.is_some());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn add_member_node_updates_repo_and_emits_event() {
        let mut contents = ContentNetworkRepositoryImpl::default();
        let events = add_member_node(&mut contents, "cid-2", "node-A");

        assert_eq!(events.len(), 1);
        let net = contents
            .get_content_network("cid-2")
            .expect("network saved");
        assert!(net.member_nodes.contains("node-A"));
    }
}
