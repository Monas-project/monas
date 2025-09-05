use crate::event_subscription::{DeliveryStatus, EventMessage};
use serde::{Deserialize, Serialize};
use sled;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct PersistentMessage {
    pub id: String,
    pub event_type: String,
    pub event_data: String, // Event payload serialized as JSON
    pub timestamp: u64,
    pub status: DeliveryStatus,
    pub retry_count: u32,
    pub max_retries: u32,
}

#[derive(Clone)]
pub struct SledPersistenceManager {
    db: Arc<sled::Db>,
}

impl SledPersistenceManager {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db = sled::open(path).map_err(|e| format!("Failed to open sled database: {e}"))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Persist a message into the sled database
    pub fn save_message(
        &self,
        message: &EventMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let system_time = SystemTime::now() - message.timestamp.elapsed();
        let timestamp = system_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let persistent_msg = PersistentMessage {
            id: message.id.clone(),
            event_type: message.event_type.clone(),
            event_data: message.event_data.clone(),
            timestamp,
            status: message.status.clone(),
            retry_count: message.retry_count,
            max_retries: message.max_retries,
        };

        let key = format!("event_message_{}", message.id);
        let value = serde_json::to_vec(&persistent_msg)
            .map_err(|e| format!("Failed to serialize message: {e}"))?;
        self.db
            .insert(key, value)
            .map_err(|e| format!("Failed to insert message: {e}"))?;
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;
        Ok(())
    }

    /// Load all persisted messages
    pub fn load_messages(
        &self,
    ) -> Result<Vec<PersistentMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let mut messages = Vec::new();

        for result in self.db.iter() {
            let (key, value) = result.map_err(|e| format!("Failed to iterate database: {e}"))?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| format!("Failed to decode key: {e}"))?;

            if key_str.starts_with("event_message_") {
                if let Ok(message) = serde_json::from_slice::<PersistentMessage>(&value) {
                    messages.push(message);
                }
            }
        }

        Ok(messages)
    }

    /// Delete a message by ID
    pub fn delete_message(
        &self,
        message_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("event_message_{message_id}");
        self.db
            .remove(key)
            .map_err(|e| format!("Failed to delete message: {e}"))?;
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;
        Ok(())
    }

    /// Remove messages older than the given age (seconds)
    pub fn cleanup_old_messages(
        &self,
        max_age_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let messages = self.load_messages()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for message in messages {
            if now - message.timestamp > max_age_secs {
                self.delete_message(&message.id)?;
            }
        }
        Ok(())
    }

    /// Get basic database statistics
    pub fn get_stats(
        &self,
    ) -> Result<HashMap<String, usize>, Box<dyn std::error::Error + Send + Sync>> {
        let mut stats = HashMap::new();
        let mut message_count = 0;
        let mut total_size = 0;

        for result in self.db.iter() {
            let (key, value) = result.map_err(|e| format!("Failed to iterate database: {e}"))?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| format!("Failed to decode key: {e}"))?;

            if key_str.starts_with("event_message_") {
                message_count += 1;
                total_size += value.len();
            }
        }

        stats.insert("message_count".to_string(), message_count);
        stats.insert("total_size_bytes".to_string(), total_size);

        Ok(stats)
    }

    /// Compact the database (sled compacts automatically; this ensures flush)
    pub fn compact(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;
        // sled runs background compaction automatically
        Ok(())
    }
}

impl Drop for SledPersistenceManager {
    fn drop(&mut self) {
        if let Err(e) = self.db.flush() {
            eprintln!("Failed to flush sled database: {e}");
        }
    }
}

#[cfg(test)]
mod sled_persistence_tests {
    use super::*;
    use crate::event_bus::Event;
    use crate::event_subscription::SerializableEvent;
    use std::any::Any;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    // Define test event types inline for testing
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestEvent {
        data: String,
    }

    impl TestEvent {
        fn new(data: &str) -> Self {
            Self {
                data: data.to_string(),
            }
        }
    }

    impl Event for TestEvent {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SerializableEvent for TestEvent {
        fn event_type() -> &'static str {
            "TestEvent"
        }
    }

    fn create_temp_manager() -> (SledPersistenceManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        (manager, temp_dir)
    }

    #[test]
    fn test_persistence_manager_creation() {
        let (_manager, _temp_dir) = create_temp_manager();
    }

    #[test]
    fn test_store_and_retrieve_message() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        let message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save the message
        let store_result = manager.save_message(&message);
        assert!(store_result.is_ok());

        // Retrieve the message
        let retrieve_result = manager.load_messages();
        assert!(retrieve_result.is_ok());

        let retrieved_messages = retrieve_result.unwrap();
        assert_eq!(retrieved_messages.len(), 1);
        assert_eq!(retrieved_messages[0].id, "test_id");
        assert_eq!(retrieved_messages[0].retry_count, 0);
        assert_eq!(retrieved_messages[0].max_retries, 3);
        assert_eq!(retrieved_messages[0].status, DeliveryStatus::Pending);
    }

    #[test]
    fn test_update_message_status() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        let message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save the message
        manager.save_message(&message).unwrap();

        // Update the message
        let updated_message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Delivered,
            retry_count: 1,
            max_retries: 3,
        };

        manager.save_message(&updated_message).unwrap();

        // Get the updated message
        let retrieved_messages = manager.load_messages().unwrap();
        assert_eq!(retrieved_messages.len(), 1);
        assert_eq!(retrieved_messages[0].status, DeliveryStatus::Delivered);
        assert_eq!(retrieved_messages[0].retry_count, 1);
    }

    #[test]
    fn test_increment_retry_count() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        let message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 0,
            max_retries: 3,
        };

        // Save the message
        manager.save_message(&message).unwrap();

        // Increment retry count
        let retry_message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 1,
            max_retries: 3,
        };

        manager.save_message(&retry_message).unwrap();

        // Verify retry count has been incremented
        let retrieved_messages = manager.load_messages().unwrap();
        assert_eq!(retrieved_messages.len(), 1);
        assert_eq!(retrieved_messages[0].retry_count, 1);
    }

    #[test]
    fn test_get_nonexistent_message() {
        let (manager, _temp_dir) = create_temp_manager();
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_get_all_messages() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        // Save multiple messages
        for i in 0..3 {
            let message = EventMessage {
                id: format!("test_id_{i}"),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: DeliveryStatus::Pending,
                retry_count: 0,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Get all messages
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn test_delete_message() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        let message = EventMessage {
            id: "test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save the message
        manager.save_message(&message).unwrap();

        // Verify the message was saved
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 1);

        // Delete the message
        manager.delete_message("test_id").unwrap();

        // Verify the message was deleted
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_get_pending_messages() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        // Save messages with different statuses
        let pending_message = EventMessage {
            id: "pending_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        let delivered_message = EventMessage {
            id: "delivered_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Delivered,
            retry_count: 0,
            max_retries: 3,
        };

        manager.save_message(&pending_message).unwrap();
        manager.save_message(&delivered_message).unwrap();

        // Get all messages and filter for Pending ones
        let messages = manager.load_messages().unwrap();
        let pending_messages: Vec<_> = messages
            .into_iter()
            .filter(|m| m.status == DeliveryStatus::Pending)
            .collect();

        assert_eq!(pending_messages.len(), 1);
        assert_eq!(pending_messages[0].id, "pending_id");
    }

    #[test]
    fn test_get_failed_messages() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        // Save messages with different statuses
        let failed_message = EventMessage {
            id: "failed_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 2,
            max_retries: 3,
        };

        let delivered_message = EventMessage {
            id: "delivered_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Delivered,
            retry_count: 0,
            max_retries: 3,
        };

        manager.save_message(&failed_message).unwrap();
        manager.save_message(&delivered_message).unwrap();

        // Get all messages and filter for Failed ones
        let messages = manager.load_messages().unwrap();
        let failed_messages: Vec<_> = messages
            .into_iter()
            .filter(|m| m.status == DeliveryStatus::Failed)
            .collect();

        assert_eq!(failed_messages.len(), 1);
        assert_eq!(failed_messages[0].id, "failed_id");
        assert_eq!(failed_messages[0].retry_count, 2);
    }

    #[test]
    fn test_cleanup_old_messages() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        // Save old and new messages
        let old_message = EventMessage {
            id: "old_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now() - Duration::from_secs(3600), // 1 hour ago
            status: DeliveryStatus::Delivered,
            retry_count: 0,
            max_retries: 3,
        };

        let new_message = EventMessage {
            id: "new_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        manager.save_message(&old_message).unwrap();
        manager.save_message(&new_message).unwrap();

        // Check message count before cleanup
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 2);

        // Clean up messages older than 30 minutes
        manager.cleanup_old_messages(1800).unwrap(); // 30 minutes = 1800 seconds

        // Check message count after cleanup
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "new_id");
    }

    #[test]
    fn test_get_statistics() {
        let (manager, _temp_dir) = create_temp_manager();
        let event = Arc::new(TestEvent::new("test_message"));

        // Save multiple messages
        for i in 0..5 {
            let message = EventMessage {
                id: format!("test_id_{i}"),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: DeliveryStatus::Pending,
                retry_count: 0,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Get statistics
        let stats = manager.get_stats().unwrap();
        assert_eq!(stats.get("message_count").unwrap(), &5);
        assert!(stats.get("total_size_bytes").unwrap() > &0);
    }

    #[test]
    fn test_compact_database() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save multiple messages
        for i in 0..10 {
            let event = Arc::new(TestEvent::new(&format!("compact_test_{i}")));
            let message = EventMessage {
                id: format!("compact_id_{i}"),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: DeliveryStatus::Failed,
                retry_count: 3,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Compact the database
        let result = manager.compact();
        assert!(result.is_ok());

        // Verify messages remain after compaction
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 10);
    }

    #[test]
    fn test_dead_letter_persistence_and_restore() {
        let (manager, _temp_dir) = create_temp_manager();

        // Message to save as dead letter
        let event = Arc::new(TestEvent::new("dead_letter_test"));
        let message = EventMessage {
            id: "dead_letter_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };

        // Save the message
        manager.save_message(&message).unwrap();

        // Restore the message
        let restored_messages = manager.load_messages().unwrap();
        assert_eq!(restored_messages.len(), 1);

        let restored = &restored_messages[0];
        assert_eq!(restored.id, "dead_letter_id");
        assert_eq!(restored.status, DeliveryStatus::Failed);
        assert_eq!(restored.retry_count, 3);
        assert_eq!(restored.max_retries, 3);
    }

    #[test]
    fn test_multiple_dead_letters_management() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save multiple dead letters
        for i in 0..5 {
            let event = Arc::new(TestEvent::new(&format!("dead_letter_{i}")));
            let message = EventMessage {
                id: format!("dead_letter_id_{i}"),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: DeliveryStatus::Failed,
                retry_count: 3,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Restore all messages
        let restored_messages = manager.load_messages().unwrap();
        assert_eq!(restored_messages.len(), 5);

        // Check the state of each message
        for (i, message) in restored_messages.iter().enumerate() {
            assert_eq!(message.id, format!("dead_letter_id_{i}"));
            assert_eq!(message.status, DeliveryStatus::Failed);
            assert_eq!(message.retry_count, 3);
        }
    }

    #[test]
    fn test_dead_letter_status_transitions() {
        let (manager, _temp_dir) = create_temp_manager();

        let event = Arc::new(TestEvent::new("status_test"));
        let message = EventMessage {
            id: "status_test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save in initial state
        manager.save_message(&message).unwrap();

        // Update during retry
        let retrying_message = EventMessage {
            id: "status_test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Retrying,
            retry_count: 1,
            max_retries: 3,
        };
        manager.save_message(&retrying_message).unwrap();

        // Update to failed state
        let failed_message = EventMessage {
            id: "status_test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };
        manager.save_message(&failed_message).unwrap();

        // Check final state
        let restored_messages = manager.load_messages().unwrap();
        assert_eq!(restored_messages.len(), 1);
        assert_eq!(restored_messages[0].status, DeliveryStatus::Failed);
        assert_eq!(restored_messages[0].retry_count, 3);
    }

    #[test]
    fn test_dead_letter_cleanup_by_age() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save old message
        let old_event = Arc::new(TestEvent::new("old_message"));
        let old_message = EventMessage {
            id: "old_id".to_string(),
            event: old_event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*old_event).unwrap_or_default(),
            timestamp: Instant::now() - Duration::from_secs(100),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };
        manager.save_message(&old_message).unwrap();

        // Save new message
        let new_event = Arc::new(TestEvent::new("new_message"));
        let new_message = EventMessage {
            id: "new_id".to_string(),
            event: new_event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*new_event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };
        manager.save_message(&new_message).unwrap();

        // Clean up messages older than 50 seconds
        manager.cleanup_old_messages(50).unwrap();

        // Old messages are deleted, new messages remain
        let remaining_messages = manager.load_messages().unwrap();
        assert_eq!(remaining_messages.len(), 1);
        assert_eq!(remaining_messages[0].id, "new_id");
    }

    #[test]
    fn test_dead_letter_retry_count_tracking() {
        let (manager, _temp_dir) = create_temp_manager();

        let event = Arc::new(TestEvent::new("retry_test"));
        let message = EventMessage {
            id: "retry_test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save in initial state
        manager.save_message(&message).unwrap();

        // Update while incrementing retry count
        for retry_count in 1..=3 {
            let updated_message = EventMessage {
                id: "retry_test_id".to_string(),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: if retry_count < 3 {
                    DeliveryStatus::Retrying
                } else {
                    DeliveryStatus::Failed
                },
                retry_count,
                max_retries: 3,
            };
            manager.save_message(&updated_message).unwrap();
        }

        // Check final state
        let restored_messages = manager.load_messages().unwrap();
        assert_eq!(restored_messages.len(), 1);
        assert_eq!(restored_messages[0].retry_count, 3);
        assert_eq!(restored_messages[0].status, DeliveryStatus::Failed);
    }

    #[test]
    fn test_dead_letter_database_statistics() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save multiple dead letters
        for i in 0..10 {
            let event = Arc::new(TestEvent::new(&format!("stats_test_{i}")));
            let message = EventMessage {
                id: format!("stats_id_{i}"),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: DeliveryStatus::Failed,
                retry_count: 3,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Get statistics
        let stats = manager.get_stats().unwrap();
        assert_eq!(stats["message_count"], 10);
        assert!(stats["total_size_bytes"] > 0);

        // Delete a message
        manager.delete_message("stats_id_0").unwrap();

        // Check updated statistics
        let updated_stats = manager.get_stats().unwrap();
        assert_eq!(updated_stats["message_count"], 9);
    }

    #[test]
    fn test_dead_letter_concurrent_access() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save messages concurrently from multiple threads
        let mut handles = Vec::new();
        for i in 0..5 {
            let manager_clone = manager.clone();
            let handle = std::thread::spawn(move || {
                let event = Arc::new(TestEvent::new(&format!("concurrent_test_{i}")));
                let message = EventMessage {
                    id: format!("concurrent_id_{i}"),
                    event: event.clone(),
                    event_type: TestEvent::event_type().to_string(),
                    event_data: serde_json::to_string(&*event).unwrap_or_default(),
                    timestamp: Instant::now(),
                    status: DeliveryStatus::Failed,
                    retry_count: 3,
                    max_retries: 3,
                };
                manager_clone.save_message(&message)
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            assert!(handle.join().unwrap().is_ok());
        }

        // Verify all messages were saved
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 5);
    }

    #[test]
    fn test_dead_letter_error_handling() {
        let (manager, _temp_dir) = create_temp_manager();

        // Try to create manager with invalid path
        let invalid_result = SledPersistenceManager::new("/invalid/path/that/does/not/exist");
        assert!(invalid_result.is_err());

        // Save message with valid manager
        let event = Arc::new(TestEvent::new("error_test"));
        let message = EventMessage {
            id: "error_test_id".to_string(),
            event: event.clone(),
            event_type: TestEvent::event_type().to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };

        let result = manager.save_message(&message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dead_letter_persistence_consistency() {
        let (manager, _temp_dir) = create_temp_manager();

        // Save the same message ID multiple times
        let event = Arc::new(TestEvent::new("consistency_test"));
        for retry_count in 0..3 {
            let message = EventMessage {
                id: "consistency_id".to_string(),
                event: event.clone(),
                event_type: TestEvent::event_type().to_string(),
                event_data: serde_json::to_string(&*event).unwrap_or_default(),
                timestamp: Instant::now(),
                status: if retry_count < 2 {
                    DeliveryStatus::Retrying
                } else {
                    DeliveryStatus::Failed
                },
                retry_count,
                max_retries: 3,
            };
            manager.save_message(&message).unwrap();
        }

        // Verify only the last state is saved
        let messages = manager.load_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].retry_count, 2);
        assert_eq!(messages[0].status, DeliveryStatus::Failed);
    }
}
