//! Inbox Persistence - Idempotent event processing with deduplication.
//!
//! This module implements the Inbox pattern for idempotent event processing.
//! Processed event IDs are stored to prevent duplicate processing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Record of a processed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedEventRecord {
    /// The event ID that was processed.
    pub event_id: String,
    /// Timestamp when the event was processed.
    pub processed_at: u64,
    /// Source node that sent the event.
    pub source_node: Option<String>,
}

/// Inbox persistence for idempotent event processing.
///
/// Uses Sled for durable storage of processed event IDs.
pub struct SledInboxPersistence {
    db: Arc<sled::Db>,
    /// Tree for processed events.
    processed_tree: sled::Tree,
}

impl SledInboxPersistence {
    /// Open or create an inbox persistence at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Arc::new(sled::open(path.as_ref()).context("Failed to open inbox database")?);
        let processed_tree = db
            .open_tree("processed")
            .context("Failed to open processed tree")?;

        Ok(Self { db, processed_tree })
    }

    /// Get current timestamp in milliseconds.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Check if an event has already been processed.
    pub fn is_processed(&self, event_id: &str) -> Result<bool> {
        self.processed_tree
            .contains_key(event_id.as_bytes())
            .context("Failed to check processed status")
    }

    /// Mark an event as processed.
    ///
    /// If the event was already processed, this is a no-op.
    pub fn mark_processed(&self, event_id: &str, source_node: Option<&str>) -> Result<()> {
        let record = ProcessedEventRecord {
            event_id: event_id.to_string(),
            processed_at: Self::current_timestamp(),
            source_node: source_node.map(|s| s.to_string()),
        };

        let serialized =
            serde_json::to_vec(&record).context("Failed to serialize processed record")?;

        self.processed_tree
            .insert(event_id.as_bytes(), serialized)
            .context("Failed to mark event as processed")?;

        Ok(())
    }

    /// Get the record of a processed event.
    pub fn get_processed_record(&self, event_id: &str) -> Result<Option<ProcessedEventRecord>> {
        if let Some(data) = self
            .processed_tree
            .get(event_id.as_bytes())
            .context("Failed to get processed record")?
        {
            let record: ProcessedEventRecord =
                serde_json::from_slice(&data).context("Failed to deserialize processed record")?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Cleanup old processed records.
    ///
    /// Removes records older than the specified duration.
    /// Returns the number of records removed.
    pub fn cleanup_old_records(&self, max_age: Duration) -> Result<usize> {
        let now = Self::current_timestamp();
        let max_age_ms = max_age.as_millis() as u64;
        let mut removed = 0;

        let mut to_remove = Vec::new();

        for result in self.processed_tree.iter() {
            let (key, value) = result.context("Failed to iterate processed records")?;
            let record: ProcessedEventRecord =
                serde_json::from_slice(&value).context("Failed to deserialize processed record")?;

            if now.saturating_sub(record.processed_at) >= max_age_ms {
                to_remove.push(key.to_vec());
            }
        }

        for key in to_remove {
            self.processed_tree
                .remove(&key)
                .context("Failed to remove old record")?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Get the number of processed events stored.
    pub fn count(&self) -> usize {
        self.processed_tree.len()
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("Failed to flush inbox")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mark_and_check_processed() {
        let tmp = tempdir().unwrap();
        let inbox = SledInboxPersistence::open(tmp.path()).unwrap();

        let event_id = "test-event-123";

        // Should not be processed initially
        assert!(!inbox.is_processed(event_id).unwrap());

        // Mark as processed
        inbox.mark_processed(event_id, Some("node1")).unwrap();

        // Should be processed now
        assert!(inbox.is_processed(event_id).unwrap());

        // Check record
        let record = inbox.get_processed_record(event_id).unwrap().unwrap();
        assert_eq!(record.event_id, event_id);
        assert_eq!(record.source_node, Some("node1".to_string()));
    }

    #[test]
    fn test_idempotent_mark() {
        let tmp = tempdir().unwrap();
        let inbox = SledInboxPersistence::open(tmp.path()).unwrap();

        let event_id = "test-event-456";

        // Mark multiple times - should not fail
        inbox.mark_processed(event_id, None).unwrap();
        inbox.mark_processed(event_id, None).unwrap();
        inbox.mark_processed(event_id, None).unwrap();

        assert!(inbox.is_processed(event_id).unwrap());
        assert_eq!(inbox.count(), 1);
    }

    #[test]
    fn test_cleanup_old_records() {
        let tmp = tempdir().unwrap();
        let inbox = SledInboxPersistence::open(tmp.path()).unwrap();

        // Add some records
        inbox.mark_processed("event1", None).unwrap();
        inbox.mark_processed("event2", None).unwrap();

        // Cleanup with zero duration should remove all
        let removed = inbox.cleanup_old_records(Duration::from_secs(0)).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(inbox.count(), 0);
    }

    #[test]
    fn test_count() {
        let tmp = tempdir().unwrap();
        let inbox = SledInboxPersistence::open(tmp.path()).unwrap();

        assert_eq!(inbox.count(), 0);

        inbox.mark_processed("event1", None).unwrap();
        assert_eq!(inbox.count(), 1);

        inbox.mark_processed("event2", None).unwrap();
        assert_eq!(inbox.count(), 2);
    }
}
