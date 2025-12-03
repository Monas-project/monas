//! Reliable Event Publisher - Outbox pattern implementation for reliable event delivery.
//!
//! This module combines Outbox and Inbox patterns to provide:
//! - At-least-once delivery guarantee
//! - Idempotent event processing
//! - Automatic retry with backoff

use crate::domain::events::Event;
use crate::infrastructure::inbox_persistence::SledInboxPersistence;
use crate::infrastructure::outbox_persistence::SledOutboxPersistence;
use crate::port::peer_network::PeerNetwork;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the reliable event publisher.
#[derive(Debug, Clone)]
pub struct ReliablePublisherConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Minimum time between retries (milliseconds).
    pub retry_interval_ms: u64,
    /// Maximum age of events to keep in delivered state (for audit).
    pub delivered_retention: Duration,
    /// Maximum age of processed records to keep in inbox.
    pub inbox_retention: Duration,
}

impl Default for ReliablePublisherConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            retry_interval_ms: 5000, // 5 seconds
            delivered_retention: Duration::from_secs(24 * 60 * 60), // 24 hours
            inbox_retention: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
        }
    }
}

/// Result of processing a received event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// Event was processed successfully.
    Processed,
    /// Event was already processed (duplicate).
    AlreadyProcessed,
}

/// Result of a retry operation.
#[derive(Debug, Clone)]
pub struct RetryResult {
    /// Number of events successfully delivered.
    pub delivered: usize,
    /// Number of events that failed and will be retried.
    pub failed: usize,
    /// Number of events that exceeded max retries and were dropped.
    pub dropped: usize,
}

/// Reliable event publisher using Outbox/Inbox pattern.
///
/// This publisher ensures:
/// - Events are persisted before sending (durability)
/// - Failed deliveries are retried automatically
/// - Received events are deduplicated (idempotency)
pub struct ReliableEventPublisher<P: PeerNetwork> {
    peer_network: Arc<P>,
    outbox: SledOutboxPersistence,
    inbox: SledInboxPersistence,
    config: ReliablePublisherConfig,
    local_node_id: String,
}

impl<P: PeerNetwork> ReliableEventPublisher<P> {
    /// Create a new reliable event publisher.
    pub fn new(
        peer_network: Arc<P>,
        outbox: SledOutboxPersistence,
        inbox: SledInboxPersistence,
        config: ReliablePublisherConfig,
        local_node_id: String,
    ) -> Self {
        Self {
            peer_network,
            outbox,
            inbox,
            config,
            local_node_id,
        }
    }

    /// Publish an event reliably to target nodes.
    ///
    /// The event is first persisted to the outbox, then delivery is attempted.
    /// If delivery fails, it will be retried by the retry task.
    pub async fn publish_reliably(&self, event: &Event, target_nodes: &[String]) -> Result<String> {
        // 1. Save to outbox first (durability)
        let event_id = self.outbox.save_pending_event(event, target_nodes)?;

        // 2. Attempt delivery
        self.try_deliver_event(&event_id, event, target_nodes)
            .await;

        Ok(event_id)
    }

    /// Attempt to deliver an event to target nodes.
    async fn try_deliver_event(&self, event_id: &str, event: &Event, target_nodes: &[String]) {
        // Serialize the event for network transmission
        let event_data = match serde_json::to_vec(event) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to serialize event {}: {}", event_id, e);
                return;
            }
        };

        // Determine the topic based on event type
        let topic = format!("monas/events/{}", event.event_type());

        for node_id in target_nodes {
            if node_id == &self.local_node_id {
                // Local delivery - just mark as delivered
                if let Err(e) = self.outbox.mark_delivered(event_id, node_id) {
                    tracing::warn!("Failed to mark local delivery: {}", e);
                }
                continue;
            }

            // Try to publish via gossipsub (broadcast)
            match self.peer_network.publish_event(&topic, &event_data).await {
                Ok(()) => {
                    // Mark as delivered for this node
                    // Note: In gossipsub, we can't guarantee delivery to specific nodes,
                    // so we mark as delivered optimistically
                    if let Err(e) = self.outbox.mark_delivered(event_id, node_id) {
                        tracing::warn!("Failed to mark delivery for {}: {}", node_id, e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to publish event {} to {}: {}", event_id, node_id, e);
                    // Event remains in outbox for retry
                }
            }
        }

        // Update retry attempt timestamp
        if let Err(e) = self.outbox.mark_retry_attempt(event_id) {
            tracing::warn!("Failed to update retry attempt: {}", e);
        }
    }

    /// Retry pending events that haven't been delivered.
    ///
    /// This should be called periodically by a background task.
    pub async fn retry_pending(&self) -> Result<RetryResult> {
        let mut result = RetryResult {
            delivered: 0,
            failed: 0,
            dropped: 0,
        };

        // Get pending events that are old enough for retry
        let pending = self
            .outbox
            .get_pending_events(Some(self.config.retry_interval_ms))?;

        for event in pending {
            if event.retry_count >= self.config.max_retries {
                // Max retries exceeded - drop the event
                tracing::warn!(
                    "Event {} exceeded max retries ({}), dropping",
                    event.id,
                    event.retry_count
                );
                if let Err(e) = self.outbox.remove_pending_event(&event.id) {
                    tracing::error!("Failed to remove dropped event: {}", e);
                }
                result.dropped += 1;
                continue;
            }

            // Attempt delivery
            self.try_deliver_event(&event.id, &event.event, &event.remaining_targets)
                .await;

            // Check if still pending
            match self.outbox.get_pending_event(&event.id)? {
                Some(_) => result.failed += 1,
                None => result.delivered += 1,
            }
        }

        Ok(result)
    }

    /// Process a received event (inbox side).
    ///
    /// Returns whether the event should be processed or was already processed.
    pub fn process_received(&self, event_id: &str, source_node: Option<&str>) -> Result<ProcessResult> {
        // Check if already processed
        if self.inbox.is_processed(event_id)? {
            return Ok(ProcessResult::AlreadyProcessed);
        }

        // Mark as processed
        self.inbox.mark_processed(event_id, source_node)?;

        Ok(ProcessResult::Processed)
    }

    /// Compute a unique ID for an event.
    ///
    /// This can be used to identify events for deduplication.
    pub fn compute_event_id(event: &Event) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Hash event type
        event.event_type().hash(&mut hasher);

        // Hash event-specific fields
        match event {
            Event::NodeCreated { node_id, timestamp, .. } => {
                node_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
            Event::ContentCreated { content_id, timestamp, .. } => {
                content_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
            Event::ContentUpdated { content_id, timestamp, .. } => {
                content_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
            Event::AssignmentDecided { content_id, timestamp, .. } => {
                content_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
            Event::ContentNetworkManagerAdded { content_id, timestamp, .. } => {
                content_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
            Event::ContentSyncRequested { content_id, timestamp, .. } => {
                content_id.hash(&mut hasher);
                timestamp.hash(&mut hasher);
            }
        }

        format!("{:016x}", hasher.finish())
    }

    /// Cleanup old records from both outbox and inbox.
    pub fn cleanup(&self) -> Result<(usize, usize)> {
        let outbox_cleaned = self.outbox.cleanup_old_events(self.config.delivered_retention)?;
        let inbox_cleaned = self.inbox.cleanup_old_records(self.config.inbox_retention)?;
        Ok((outbox_cleaned, inbox_cleaned))
    }

    /// Get statistics about the publisher.
    pub fn stats(&self) -> Result<PublisherStats> {
        let outbox_stats = self.outbox.stats()?;
        Ok(PublisherStats {
            pending_events: outbox_stats.pending_count,
            delivered_events: outbox_stats.delivered_count,
            processed_events: self.inbox.count(),
        })
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.outbox.flush()?;
        self.inbox.flush()?;
        Ok(())
    }
}

/// Statistics about the reliable publisher.
#[derive(Debug, Clone)]
pub struct PublisherStats {
    /// Number of events pending delivery.
    pub pending_events: usize,
    /// Number of events successfully delivered.
    pub delivered_events: usize,
    /// Number of events processed (received).
    pub processed_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::current_timestamp;

    fn create_test_event() -> Event {
        Event::NodeCreated {
            node_id: "test-node".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: current_timestamp(),
        }
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let event = create_test_event();
        let id1 = ReliableEventPublisher::<crate::infrastructure::network::Libp2pNetwork>::compute_event_id(&event);
        let id2 = ReliableEventPublisher::<crate::infrastructure::network::Libp2pNetwork>::compute_event_id(&event);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_different_events() {
        let event1 = create_test_event();
        let event2 = Event::NodeCreated {
            node_id: "different-node".to_string(),
            total_capacity: 2000,
            available_capacity: 2000,
            timestamp: current_timestamp(),
        };

        let id1 = ReliableEventPublisher::<crate::infrastructure::network::Libp2pNetwork>::compute_event_id(&event1);
        let id2 = ReliableEventPublisher::<crate::infrastructure::network::Libp2pNetwork>::compute_event_id(&event2);
        assert_ne!(id1, id2);
    }
}

