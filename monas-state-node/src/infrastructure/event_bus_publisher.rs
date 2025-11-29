//! EventBus publisher implementation using monas-event-manager.

use crate::domain::events::Event;
use crate::port::event_publisher::EventPublisher;
use anyhow::Result;
use async_trait::async_trait;
use futures::FutureExt;
use monas_event_manager::{make_subscriber, EventBus};
use std::sync::Arc;

/// EventBus-based implementation of EventPublisher.
///
/// This wraps the monas-event-manager EventBus to provide
/// a clean interface for the application layer.
pub struct EventBusPublisher {
    event_bus: EventBus,
}

impl EventBusPublisher {
    /// Create a new EventBusPublisher with a default EventBus.
    pub fn new() -> Self {
        Self {
            event_bus: EventBus::new(),
        }
    }

    /// Create a new EventBusPublisher with persistence.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_persistence(
        persistence_manager: monas_event_manager::SledPersistenceManager,
    ) -> Self {
        Self {
            event_bus: EventBus::with_persistence(persistence_manager),
        }
    }

    /// Get a reference to the underlying EventBus.
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Register the Event type for serialization/deserialization.
    pub async fn register_event_type(&self) {
        self.event_bus.register_event_type::<Event>().await;
    }
}

impl Default for EventBusPublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventPublisher for EventBusPublisher {
    async fn publish(&self, event: &Event) -> Result<()> {
        let event_arc = Arc::new(event.clone());
        self.event_bus
            .publish(event_arc)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish event: {}", e))
    }

    async fn publish_to_network(&self, _event: &Event) -> Result<()> {
        // EventBusPublisher is local-only, so network publishing is a no-op.
        // Use GossipsubEventPublisher for network publishing.
        Ok(())
    }

    async fn subscribe<F>(&self, event_type: &str, handler: F) -> Result<()>
    where
        F: Fn(Event) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync + 'static,
    {
        let event_type_filter = event_type.to_string();
        let handler = Arc::new(handler);

        let subscriber = make_subscriber::<Event, _, _>(
            format!("subscriber-{}", event_type_filter),
            move |event: Arc<Event>| {
                let handler = handler.clone();
                let event_type_filter = event_type_filter.clone();
                async move {
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

        self.event_bus
            .subscribe::<Event>(subscriber)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_event() {
        let publisher = EventBusPublisher::new();
        publisher.register_event_type().await;

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };

        // Should not error even without subscribers
        let result = publisher.publish(&event).await;
        assert!(result.is_ok());
    }
}

