//! EventPublisher trait - Abstract interface for event publishing

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::events::Event;

/// Abstract interface for publishing and subscribing to domain events.
///
/// This trait wraps the monas-event-manager EventBus to provide
/// a clean interface for the application layer.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish an event to the event bus.
    async fn publish(&self, event: &Event) -> Result<()>;

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

