//! State Node Service - Application layer for managing state nodes.

use crate::domain::content_network::ContentNetwork;
use crate::domain::events::{current_timestamp, Event};
use crate::domain::state_node::{self, NodeSnapshot};
use crate::infrastructure::placement::compute_dht_key;
use crate::port::event_publisher::EventPublisher;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::{PersistentContentRepository, PersistentNodeRegistry};
use anyhow::Result;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Result of applying an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Ignored,
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
    ///
    /// The `peer_network` is passed as an `Arc` to allow sharing with other components
    /// (e.g., GossipsubEventPublisher).
    pub fn new(
        node_registry: N,
        content_repo: C,
        peer_network: Arc<P>,
        event_publisher: E,
        local_node_id: String,
    ) -> Self {
        Self {
            node_registry: Arc::new(tokio::sync::RwLock::new(node_registry)),
            content_repo: Arc::new(tokio::sync::RwLock::new(content_repo)),
            peer_network,
            event_publisher: Arc::new(event_publisher),
            local_node_id,
        }
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
        // Generate CID from content
        let mh = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(0x55, mh);
        let content_id = cid.to_string();

        // Find closest peers for content placement
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

        // Create content network
        let network = ContentNetwork {
            content_id: content_id.clone(),
            member_nodes: selected.iter().cloned().collect(),
        };
        self.content_repo
            .write()
            .await
            .save_content_network(network)
            .await?;

        // Create and publish event both locally and to the network
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
    pub async fn update_content(&self, content_id: &str, _data: &[u8]) -> Result<Event> {
        // Verify content network exists
        let network = self
            .content_repo
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

        // Create and publish update event both locally and to the network
        let event = Event::ContentUpdated {
            content_id: content_id.to_string(),
            updated_node_id: self.local_node_id.clone(),
            timestamp: current_timestamp(),
        };

        self.event_publisher.publish_all(&event).await?;

        Ok(event)
    }

    /// Handle a sync event from another node.
    pub async fn handle_sync_event(&self, event: &Event) -> Result<ApplyOutcome> {
        match event {
            Event::ContentUpdated { content_id, .. } => {
                // Ensure content network exists
                let exists = self
                    .content_repo
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
                    self.content_repo
                        .write()
                        .await
                        .save_content_network(network)
                        .await?;
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
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await?;
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
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await?;
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

    /// Get content network info.
    pub async fn get_content_network(&self, content_id: &str) -> Result<Option<ContentNetwork>> {
        self.content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
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
