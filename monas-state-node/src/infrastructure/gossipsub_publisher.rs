//! GossipsubEventPublisher - Event publisher with local and network delivery.
//!
//! This module provides an EventPublisher implementation that:
//! - Publishes events locally via monas-event-manager EventBus
//! - Publishes events to the P2P network via libp2p Gossipsub

use crate::domain::events::Event;
use crate::port::event_publisher::EventPublisher;
use crate::port::peer_network::PeerNetwork;
use anyhow::Result;
use async_trait::async_trait;
use futures::FutureExt;
use monas_event_manager::{make_subscriber, EventBus};
use std::sync::Arc;

/// Default Gossipsub topic for state node events.
pub const DEFAULT_EVENT_TOPIC: &str = "monas-events";

/// Event publisher that supports both local and network delivery.
///
/// This implementation:
/// - Uses monas-event-manager EventBus for local (in-process) subscribers
/// - Uses libp2p Gossipsub via PeerNetwork for network delivery to other nodes
pub struct GossipsubEventPublisher<P: PeerNetwork> {
    /// Local event bus for in-process subscribers.
    local_bus: EventBus,
    /// P2P network for Gossipsub publishing.
    peer_network: Arc<P>,
    /// Gossipsub topic name.
    topic: String,
}

impl<P: PeerNetwork> GossipsubEventPublisher<P> {
    /// Create a new GossipsubEventPublisher.
    ///
    /// # Arguments
    /// * `peer_network` - The P2P network implementation for Gossipsub
    /// * `topic` - Optional topic name (defaults to "monas-events")
    pub fn new(peer_network: Arc<P>, topic: Option<String>) -> Self {
        Self {
            local_bus: EventBus::new(),
            peer_network,
            topic: topic.unwrap_or_else(|| DEFAULT_EVENT_TOPIC.to_string()),
        }
    }

    /// Create a new GossipsubEventPublisher with persistence for the local bus.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_persistence(
        peer_network: Arc<P>,
        persistence_manager: monas_event_manager::SledPersistenceManager,
        topic: Option<String>,
    ) -> Self {
        Self {
            local_bus: EventBus::with_persistence(persistence_manager),
            peer_network,
            topic: topic.unwrap_or_else(|| DEFAULT_EVENT_TOPIC.to_string()),
        }
    }

    /// Get a reference to the underlying local EventBus.
    pub fn local_bus(&self) -> &EventBus {
        &self.local_bus
    }

    /// Get the topic name.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Register the Event type for serialization/deserialization on the local bus.
    pub async fn register_event_type(&self) {
        self.local_bus.register_event_type::<Event>().await;
    }
}

#[async_trait]
impl<P: PeerNetwork + 'static> EventPublisher for GossipsubEventPublisher<P> {
    /// Publish an event to the local event bus only.
    async fn publish(&self, event: &Event) -> Result<()> {
        let event_arc = Arc::new(event.clone());
        self.local_bus
            .publish(event_arc)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish event locally: {}", e))
    }

    /// Publish an event to the P2P network via Gossipsub.
    async fn publish_to_network(&self, event: &Event) -> Result<()> {
        // Serialize the event to JSON
        let event_data = serde_json::to_vec(event)
            .map_err(|e| anyhow::anyhow!("Failed to serialize event: {}", e))?;

        // Publish via Gossipsub
        self.peer_network
            .publish_event(&self.topic, &event_data)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish event to network: {}", e))
    }

    async fn subscribe<F>(&self, event_type: &str, handler: F) -> Result<()>
    where
        F: Fn(Event) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync + 'static,
    {
        let event_type_filter = event_type.to_string();
        let handler = Arc::new(handler);

        // Create a subscriber that filters by event_type
        let subscriber = make_subscriber::<Event, _, _>(
            format!("subscriber-{}", event_type_filter),
            move |event: Arc<Event>| {
                let handler = handler.clone();
                let event_type_filter = event_type_filter.clone();
                async move {
                    // Filter events by type
                    if event.event_type() == event_type_filter {
                        handler((*event).clone()).await.map_err(|e| {
                            Box::<dyn std::error::Error + Send + Sync>::from(e.to_string())
                        })
                    } else {
                        Ok(())
                    }
                }
                .boxed()
            },
        );

        self.local_bus
            .subscribe::<Event>(subscriber)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::content_repository::SerializedOperation;
    use std::collections::HashMap;

    /// Mock PeerNetwork for testing.
    struct MockPeerNetwork {
        published_events: Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>,
    }

    impl MockPeerNetwork {
        fn new() -> Self {
            Self {
                published_events: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PeerNetwork for MockPeerNetwork {
        async fn find_closest_peers(&self, _key: Vec<u8>, _k: usize) -> Result<Vec<String>> {
            Ok(vec![])
        }

        async fn query_node_capacity_batch(
            &self,
            _peer_ids: &[String],
        ) -> Result<HashMap<String, u64>> {
            Ok(HashMap::new())
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
            "mock-peer-id".to_string()
        }

        async fn fetch_operations(
            &self,
            _peer_id: &str,
            _genesis_cid: &str,
            _since_version: Option<&str>,
        ) -> Result<Vec<SerializedOperation>> {
            Ok(vec![])
        }

        async fn push_operations(
            &self,
            _peer_id: &str,
            _genesis_cid: &str,
            _operations: &[SerializedOperation],
        ) -> Result<usize> {
            Ok(0)
        }

        async fn broadcast_operation(
            &self,
            _genesis_cid: &str,
            _operation: &SerializedOperation,
        ) -> Result<()> {
            Ok(())
        }

        async fn find_content_providers(&self, _genesis_cid: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_publish_locally() {
        let network = Arc::new(MockPeerNetwork::new());
        let publisher = GossipsubEventPublisher::new(network.clone(), None);
        publisher.register_event_type().await;

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };

        // Local publish should succeed
        let result = publisher.publish(&event).await;
        assert!(result.is_ok());

        // Network should not have received anything
        let published = network.published_events.lock().await;
        assert!(published.is_empty());
    }

    #[tokio::test]
    async fn test_publish_to_network() {
        let network = Arc::new(MockPeerNetwork::new());
        let publisher = GossipsubEventPublisher::new(network.clone(), None);

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };

        // Network publish should succeed
        let result = publisher.publish_to_network(&event).await;
        assert!(result.is_ok());

        // Verify the event was published to the network
        let published = network.published_events.lock().await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, DEFAULT_EVENT_TOPIC);

        // Verify the event data can be deserialized
        let deserialized: Event = serde_json::from_slice(&published[0].1).unwrap();
        assert_eq!(deserialized, event);
    }

    #[tokio::test]
    async fn test_publish_all() {
        let network = Arc::new(MockPeerNetwork::new());
        let publisher = GossipsubEventPublisher::new(network.clone(), None);
        publisher.register_event_type().await;

        let event = Event::ContentCreated {
            content_id: "cid-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12345,
        };

        // publish_all should succeed
        let result = publisher.publish_all(&event).await;
        assert!(result.is_ok());

        // Network should have received the event
        let published = network.published_events.lock().await;
        assert_eq!(published.len(), 1);
    }

    #[tokio::test]
    async fn test_custom_topic() {
        let network = Arc::new(MockPeerNetwork::new());
        let custom_topic = "custom-events".to_string();
        let publisher =
            GossipsubEventPublisher::new(network.clone(), Some(custom_topic.clone()));

        assert_eq!(publisher.topic(), custom_topic);

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };

        publisher.publish_to_network(&event).await.unwrap();

        let published = network.published_events.lock().await;
        assert_eq!(published[0].0, custom_topic);
    }
}

