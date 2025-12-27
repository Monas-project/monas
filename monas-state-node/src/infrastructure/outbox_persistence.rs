//! Outbox Persistence - Reliable event delivery with retry support.
//!
//! This module implements the Outbox pattern for reliable event delivery.
//! Events are persisted before being sent, enabling retry on failure.

use crate::domain::events::Event;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A pending event waiting to be delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEvent {
    /// Unique identifier for this pending event.
    pub id: String,
    /// The event to be delivered.
    pub event: Event,
    /// Target nodes that haven't acknowledged delivery yet.
    pub remaining_targets: Vec<String>,
    /// Timestamp when the event was created.
    pub created_at: u64,
    /// Number of delivery attempts.
    pub retry_count: u32,
    /// Last delivery attempt timestamp.
    pub last_attempt_at: Option<u64>,
}

/// Outbox persistence for reliable event delivery.
///
/// Uses Sled for durable storage of pending events.
pub struct SledOutboxPersistence {
    db: Arc<sled::Db>,
    /// Tree for pending events.
    pending_tree: sled::Tree,
    /// Tree for delivered events (for audit/debugging).
    delivered_tree: sled::Tree,
}

impl SledOutboxPersistence {
    /// Open or create an outbox persistence at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Arc::new(sled::open(path.as_ref()).context("Failed to open outbox database")?);
        let pending_tree = db
            .open_tree("pending")
            .context("Failed to open pending tree")?;
        let delivered_tree = db
            .open_tree("delivered")
            .context("Failed to open delivered tree")?;

        Ok(Self {
            db,
            pending_tree,
            delivered_tree,
        })
    }

    /// Generate a unique event ID.
    fn generate_event_id(event: &Event) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Hash event type and timestamp
        event.event_type().hash(&mut hasher);

        // Add current time for uniqueness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        now.hash(&mut hasher);

        format!("{:016x}", hasher.finish())
    }

    /// Get current timestamp in milliseconds.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Save a pending event to the outbox.
    ///
    /// Returns the event ID.
    pub fn save_pending_event(&self, event: &Event, target_nodes: &[String]) -> Result<String> {
        let event_id = Self::generate_event_id(event);

        let pending = PendingEvent {
            id: event_id.clone(),
            event: event.clone(),
            remaining_targets: target_nodes.to_vec(),
            created_at: Self::current_timestamp(),
            retry_count: 0,
            last_attempt_at: None,
        };

        let serialized =
            serde_json::to_vec(&pending).context("Failed to serialize pending event")?;

        self.pending_tree
            .insert(event_id.as_bytes(), serialized)
            .context("Failed to save pending event")?;

        Ok(event_id)
    }

    /// Mark delivery as successful for a specific node.
    ///
    /// If all targets have been delivered, moves the event to the delivered tree.
    pub fn mark_delivered(&self, event_id: &str, node_id: &str) -> Result<()> {
        let key = event_id.as_bytes();

        if let Some(data) = self
            .pending_tree
            .get(key)
            .context("Failed to get pending event")?
        {
            let mut pending: PendingEvent =
                serde_json::from_slice(&data).context("Failed to deserialize pending event")?;

            // Remove the node from remaining targets
            pending.remaining_targets.retain(|n| n != node_id);

            if pending.remaining_targets.is_empty() {
                // All targets delivered, move to delivered tree
                self.pending_tree
                    .remove(key)
                    .context("Failed to remove from pending")?;

                let serialized =
                    serde_json::to_vec(&pending).context("Failed to serialize delivered event")?;
                self.delivered_tree
                    .insert(key, serialized)
                    .context("Failed to save to delivered")?;
            } else {
                // Update remaining targets
                let serialized =
                    serde_json::to_vec(&pending).context("Failed to serialize pending event")?;
                self.pending_tree
                    .insert(key, serialized)
                    .context("Failed to update pending event")?;
            }
        }

        Ok(())
    }

    /// Update retry count and last attempt timestamp.
    pub fn mark_retry_attempt(&self, event_id: &str) -> Result<()> {
        let key = event_id.as_bytes();

        if let Some(data) = self
            .pending_tree
            .get(key)
            .context("Failed to get pending event")?
        {
            let mut pending: PendingEvent =
                serde_json::from_slice(&data).context("Failed to deserialize pending event")?;

            pending.retry_count += 1;
            pending.last_attempt_at = Some(Self::current_timestamp());

            let serialized =
                serde_json::to_vec(&pending).context("Failed to serialize pending event")?;
            self.pending_tree
                .insert(key, serialized)
                .context("Failed to update pending event")?;
        }

        Ok(())
    }

    /// Get all pending events for retry.
    ///
    /// Optionally filters by minimum age (to avoid retrying too quickly).
    pub fn get_pending_events(&self, min_age_ms: Option<u64>) -> Result<Vec<PendingEvent>> {
        let now = Self::current_timestamp();
        let mut events = Vec::new();

        for result in self.pending_tree.iter() {
            let (_, value) = result.context("Failed to iterate pending events")?;
            let pending: PendingEvent =
                serde_json::from_slice(&value).context("Failed to deserialize pending event")?;

            // Filter by age if specified
            if let Some(min_age) = min_age_ms {
                let last_attempt = pending.last_attempt_at.unwrap_or(pending.created_at);
                if now.saturating_sub(last_attempt) < min_age {
                    continue;
                }
            }

            events.push(pending);
        }

        Ok(events)
    }

    /// Get a specific pending event by ID.
    pub fn get_pending_event(&self, event_id: &str) -> Result<Option<PendingEvent>> {
        if let Some(data) = self
            .pending_tree
            .get(event_id.as_bytes())
            .context("Failed to get pending event")?
        {
            let pending: PendingEvent =
                serde_json::from_slice(&data).context("Failed to deserialize pending event")?;
            Ok(Some(pending))
        } else {
            Ok(None)
        }
    }

    /// Remove a pending event (e.g., after max retries).
    pub fn remove_pending_event(&self, event_id: &str) -> Result<()> {
        self.pending_tree
            .remove(event_id.as_bytes())
            .context("Failed to remove pending event")?;
        Ok(())
    }

    /// Cleanup old delivered events.
    ///
    /// Removes events older than the specified duration.
    pub fn cleanup_old_events(&self, max_age: Duration) -> Result<usize> {
        let now = Self::current_timestamp();
        let max_age_ms = max_age.as_millis() as u64;
        let mut removed = 0;

        let mut to_remove = Vec::new();

        for result in self.delivered_tree.iter() {
            let (key, value) = result.context("Failed to iterate delivered events")?;
            let event: PendingEvent =
                serde_json::from_slice(&value).context("Failed to deserialize delivered event")?;

            if now.saturating_sub(event.created_at) > max_age_ms {
                to_remove.push(key.to_vec());
            }
        }

        for key in to_remove {
            self.delivered_tree
                .remove(&key)
                .context("Failed to remove old event")?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Get statistics about the outbox.
    pub fn stats(&self) -> Result<OutboxStats> {
        Ok(OutboxStats {
            pending_count: self.pending_tree.len(),
            delivered_count: self.delivered_tree.len(),
        })
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("Failed to flush outbox")?;
        Ok(())
    }
}

/// Statistics about the outbox.
#[derive(Debug, Clone)]
pub struct OutboxStats {
    /// Number of pending events.
    pub pending_count: usize,
    /// Number of delivered events (kept for audit).
    pub delivered_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::current_timestamp;
    use tempfile::tempdir;

    fn create_test_event() -> Event {
        Event::NodeCreated {
            node_id: "test-node".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: current_timestamp(),
        }
    }

    #[test]
    fn test_save_and_get_pending_event() {
        let tmp = tempdir().unwrap();
        let outbox = SledOutboxPersistence::open(tmp.path()).unwrap();

        let event = create_test_event();
        let targets = vec!["node1".to_string(), "node2".to_string()];

        let event_id = outbox.save_pending_event(&event, &targets).unwrap();
        assert!(!event_id.is_empty());

        let pending = outbox.get_pending_event(&event_id).unwrap().unwrap();
        assert_eq!(pending.remaining_targets.len(), 2);
        assert_eq!(pending.retry_count, 0);
    }

    #[test]
    fn test_mark_delivered() {
        let tmp = tempdir().unwrap();
        let outbox = SledOutboxPersistence::open(tmp.path()).unwrap();

        let event = create_test_event();
        let targets = vec!["node1".to_string(), "node2".to_string()];

        let event_id = outbox.save_pending_event(&event, &targets).unwrap();

        // Mark first delivery
        outbox.mark_delivered(&event_id, "node1").unwrap();
        let pending = outbox.get_pending_event(&event_id).unwrap().unwrap();
        assert_eq!(pending.remaining_targets.len(), 1);

        // Mark second delivery - should move to delivered
        outbox.mark_delivered(&event_id, "node2").unwrap();
        let pending = outbox.get_pending_event(&event_id).unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_get_pending_events() {
        let tmp = tempdir().unwrap();
        let outbox = SledOutboxPersistence::open(tmp.path()).unwrap();

        let event1 = create_test_event();
        let event2 = Event::NodeCreated {
            node_id: "test-node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 2000,
            timestamp: current_timestamp(),
        };

        outbox
            .save_pending_event(&event1, &["node1".to_string()])
            .unwrap();
        outbox
            .save_pending_event(&event2, &["node2".to_string()])
            .unwrap();

        let pending = outbox.get_pending_events(None).unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_retry_attempt() {
        let tmp = tempdir().unwrap();
        let outbox = SledOutboxPersistence::open(tmp.path()).unwrap();

        let event = create_test_event();
        let event_id = outbox
            .save_pending_event(&event, &["node1".to_string()])
            .unwrap();

        outbox.mark_retry_attempt(&event_id).unwrap();
        outbox.mark_retry_attempt(&event_id).unwrap();

        let pending = outbox.get_pending_event(&event_id).unwrap().unwrap();
        assert_eq!(pending.retry_count, 2);
        assert!(pending.last_attempt_at.is_some());
    }
}
