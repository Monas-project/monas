//! EventPublisher trait - Abstract interface for event publishing

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::events::Event;

/// Abstract interface for publishing and subscribing to domain events.
///
/// This trait provides two publishing mechanisms:
/// - `publish`: Publishes to the local event bus (same process)
/// - `publish_to_network`: Publishes to the P2P network via Gossipsub
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish an event to the local event bus.
    ///
    /// This is for in-process subscribers only.
    async fn publish(&self, event: &Event) -> Result<()>;

    /// Publish an event to the P2P network via Gossipsub.
    ///
    /// This broadcasts the event to other nodes in the network.
    async fn publish_to_network(&self, event: &Event) -> Result<()>;

    /// Publish an event both locally and to the network.
    ///
    /// Convenience method that calls both `publish` and `publish_to_network`.
    async fn publish_all(&self, event: &Event) -> Result<()> {
        self.publish(event).await?;
        self.publish_to_network(event).await
    }

    /// Subscribe to events of a specific type.
    ///
    /// The handler will be called for each matching event.
    async fn subscribe<F>(&self, event_type: &str, handler: F) -> Result<()>
    where
        F: Fn(Event) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync + 'static;
}

/// Event type identifier for subscription routing.
pub trait EventType {
    /// Returns the string identifier for this event type.
    fn event_type() -> &'static str;
}

impl EventType for Event {
    fn event_type() -> &'static str {
        "StateNodeEvent"
    }
}

