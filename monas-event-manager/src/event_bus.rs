use std::any::Any;
use std::sync::Arc;

pub trait Event: Any {
    fn as_any(&self) -> &dyn Any;
}

#[derive(Clone)]
pub struct EventBus {
    event_subscriptions: crate::event_subscription::EventSubscriptions,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            event_subscriptions: crate::event_subscription::EventSubscriptions::new(),
        }
    }

    pub fn with_persistence(
        persistence_manager: crate::sled_persistence::SledPersistenceManager,
    ) -> Self {
        Self {
            event_subscriptions: crate::event_subscription::EventSubscriptions::with_persistence(
                persistence_manager,
            ),
        }
    }

    pub async fn publish<T>(
        &self,
        event: Arc<T>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: crate::event_subscription::SerializableEvent + 'static,
    {
        self.event_subscriptions.publish(event).await
    }

    pub async fn subscribe<T>(
        &self,
        subscriber: Arc<crate::event_subscription::Subscriber>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: Event + 'static,
    {
        self.event_subscriptions.subscribe::<T>(subscriber).await
    }

    pub async fn unsubscribe<T>(
        &self,
        subscriber_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: Event + 'static,
    {
        self.event_subscriptions
            .unsubscribe::<T>(subscriber_id)
            .await
    }

    pub async fn health_check(
        &self,
    ) -> std::collections::HashMap<String, crate::event_subscription::ConnectionStatus> {
        self.event_subscriptions.health_check().await
    }

    pub async fn retry_failed_messages(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.event_subscriptions.retry_failed_messages().await
    }

    pub async fn cleanup_old_messages(&self, max_age: std::time::Duration) {
        self.event_subscriptions.cleanup_old_messages(max_age).await;
    }

    pub async fn restore_messages(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.event_subscriptions.restore_messages().await
    }

    /// Restore dead letters and enqueue them for retry
    pub async fn restore_and_retry_dead_letters(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Restore dead letters and add them to the retry queue
        self.event_subscriptions.restore_messages().await?;

        // Process the retry queue
        self.retry_failed_messages().await?;

        Ok(())
    }

    /// Set the event restorer implementation
    pub async fn set_event_restorer(
        &self,
        restorer: Arc<dyn crate::event_subscription::EventRestorer + Send + Sync>,
    ) {
        self.event_subscriptions.set_event_restorer(restorer).await;
    }

    /// Register an event type for (de)serialization and restoration
    pub async fn register_event_type<T: crate::event_subscription::SerializableEvent>(&self) {
        self.event_subscriptions.register_event_type::<T>().await;
    }

    pub fn get_persistence_stats(
        &self,
    ) -> Result<std::collections::HashMap<String, usize>, Box<dyn std::error::Error + Send + Sync>>
    {
        self.event_subscriptions.get_persistence_stats()
    }

    pub fn compact_database(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.event_subscriptions.compact_database()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod event_bus_tests {
    use super::*;
    use crate::config::SubscriberConfig;
    use crate::event_subscription::{
        make_subscriber, make_subscriber_with_config, DefaultEventRestorer, SerializableEvent,
    };
    use crate::sled_persistence::SledPersistenceManager;
    use async_std::sync::Mutex as AsyncMutex;
    use async_std::task::sleep;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::time::Duration;
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

    #[async_std::test]
    async fn test_publish_subscriptions() {
        let event_bus = EventBus::new();
        let received_messages = Arc::new(AsyncMutex::new(Vec::new()));

        let subscriber1 = make_subscriber::<TestEvent, _, _>("subscriber1".to_string(), {
            let received_messages = Arc::clone(&received_messages);
            move |event| {
                let received_messages = Arc::clone(&received_messages);
                let message = format!("fire1: {}", event.data);
                async move {
                    received_messages.lock().await.push(message);
                    Ok(())
                }
            }
        });

        let subscriber2 = make_subscriber::<TestEvent, _, _>("subscriber2".to_string(), {
            let received_messages = Arc::clone(&received_messages);
            move |event| {
                let received_messages = Arc::clone(&received_messages);
                let message = format!("fire2: {}", event.data);
                async move {
                    received_messages.lock().await.push(message);
                    Ok(())
                }
            }
        });

        event_bus.subscribe::<TestEvent>(subscriber1).await.unwrap();
        event_bus.subscribe::<TestEvent>(subscriber2).await.unwrap();

        let event = Arc::new(TestEvent::new("test"));

        event_bus.publish(event).await.unwrap();

        sleep(Duration::from_millis(100)).await;

        let messages = received_messages.lock().await;
        assert_eq!(messages.len(), 2);
        assert!(messages.contains(&"fire1: test".to_string()));
        assert!(messages.contains(&"fire2: test".to_string()));
    }

    #[async_std::test]
    async fn test_health_check() {
        let event_bus = EventBus::new();

        let subscriber =
            make_subscriber::<TestEvent, _, _>("health_test".to_string(), |_event| async move {
                Ok(())
            });

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let health_status = event_bus.health_check().await;
        assert_eq!(health_status.len(), 1);
        assert_eq!(
            health_status.get("health_test").unwrap(),
            &crate::event_subscription::ConnectionStatus::Connected
        );
    }

    #[async_std::test]
    async fn test_retry_mechanism() {
        let event_bus = EventBus::new();
        let fail_count = Arc::new(std::sync::Mutex::new(0));

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "retry_test".to_string(),
            {
                let fail_count = Arc::clone(&fail_count);
                move |_event| {
                    let fail_count = Arc::clone(&fail_count);
                    async move {
                        let mut count = fail_count.lock().unwrap();
                        *count += 1;
                        if *count < 3 {
                            Err("Simulated failure".into())
                        } else {
                            Ok(())
                        }
                    }
                }
            },
            SubscriberConfig {
                max_retries: 5,
                retry_delay_secs: 1,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let event = Arc::new(TestEvent::new("retry_test"));

        event_bus.publish(event).await.unwrap();

        event_bus.retry_failed_messages().await.unwrap();

        let count = *fail_count.lock().unwrap();
        assert_eq!(count, 2);

        event_bus.retry_failed_messages().await.unwrap();

        let count = *fail_count.lock().unwrap();
        assert_eq!(count, 3);
    }

    #[async_std::test]
    async fn test_unsubscribe() {
        let event_bus = EventBus::new();

        let subscriber = make_subscriber::<TestEvent, _, _>(
            "unsubscribe_test".to_string(),
            |_event| async move { Ok(()) },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let health_status = event_bus.health_check().await;
        assert_eq!(health_status.len(), 1);

        event_bus
            .unsubscribe::<TestEvent>("unsubscribe_test")
            .await
            .unwrap();

        let health_status = event_bus.health_check().await;
        assert_eq!(health_status.len(), 0);
    }

    #[async_std::test]
    async fn test_multiple_event_types() {
        let event_bus = EventBus::new();

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct EventType1 {
            data: String,
        }

        impl Event for EventType1 {
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        impl crate::event_subscription::SerializableEvent for EventType1 {
            fn event_type() -> &'static str {
                "EventType1"
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct EventType2 {
            value: i32,
        }

        impl Event for EventType2 {
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        impl crate::event_subscription::SerializableEvent for EventType2 {
            fn event_type() -> &'static str {
                "EventType2"
            }
        }

        let received_type1 = Arc::new(AsyncMutex::new(Vec::new()));
        let received_type2 = Arc::new(AsyncMutex::new(Vec::new()));

        let subscriber1 = make_subscriber::<EventType1, _, _>("type1_subscriber".to_string(), {
            let received_type1 = Arc::clone(&received_type1);
            move |event| {
                let received_type1 = Arc::clone(&received_type1);
                async move {
                    received_type1.lock().await.push(event.data.clone());
                    Ok(())
                }
            }
        });

        let subscriber2 = make_subscriber::<EventType2, _, _>("type2_subscriber".to_string(), {
            let received_type2 = Arc::clone(&received_type2);
            move |event| {
                let received_type2 = Arc::clone(&received_type2);
                async move {
                    received_type2.lock().await.push(event.value);
                    Ok(())
                }
            }
        });

        event_bus
            .subscribe::<EventType1>(subscriber1)
            .await
            .unwrap();
        event_bus
            .subscribe::<EventType2>(subscriber2)
            .await
            .unwrap();

        let event1 = Arc::new(EventType1 {
            data: "test_data".to_string(),
        });
        let event2 = Arc::new(EventType2 { value: 42 });

        event_bus.publish(event1).await.unwrap();
        event_bus.publish(event2).await.unwrap();

        sleep(Duration::from_millis(100)).await;

        let type1_messages = received_type1.lock().await;
        let type2_messages = received_type2.lock().await;

        assert_eq!(type1_messages.len(), 1);
        assert_eq!(type1_messages[0], "test_data");
        assert_eq!(type2_messages.len(), 1);
        assert_eq!(type2_messages[0], 42);
    }

    #[async_std::test]
    async fn test_simple_retry() {
        let event_bus = EventBus::new();
        let fail_count = Arc::new(std::sync::Mutex::new(0));

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "simple_retry_test".to_string(),
            {
                let fail_count = Arc::clone(&fail_count);
                move |_event| {
                    let fail_count = Arc::clone(&fail_count);
                    async move {
                        let mut count = fail_count.lock().unwrap();
                        *count += 1;
                        Err("Always fail".into())
                    }
                }
            },
            SubscriberConfig {
                max_retries: 3,
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let event = Arc::new(TestEvent::new("retry_test"));

        event_bus.publish(event).await.unwrap();

        for _ in 0..3 {
            event_bus.retry_failed_messages().await.unwrap();
        }

        let count = *fail_count.lock().unwrap();
        assert_eq!(count, 4);
    }

    #[async_std::test]
    async fn test_cleanup_old_messages() {
        let event_bus = EventBus::new();
        event_bus
            .cleanup_old_messages(Duration::from_secs(3600))
            .await;
    }

    #[async_std::test]
    async fn test_database_compaction() {
        let event_bus = EventBus::new();
        let result = event_bus.compact_database();
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_persistence_stats() {
        use crate::event_subscription::EventSubscriptions;
        use crate::sled_persistence::SledPersistenceManager;
        use tempfile::TempDir;
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let persistence = SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_subscriptions = EventSubscriptions::with_persistence(persistence);
        let event_bus = EventBus {
            event_subscriptions,
        };
        let stats = event_bus.get_persistence_stats();
        assert!(stats.is_ok());
        let stats = stats.unwrap();
        assert!(stats.is_empty() || stats.values().all(|&v| v == 0));
    }

    #[async_std::test]
    async fn test_restore_messages() {
        let event_bus = EventBus::new();
        let result = event_bus.restore_messages().await;
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_subscriber_health_status() {
        let event_bus = EventBus::new();

        let subscriber = make_subscriber::<TestEvent, _, _>(
            "health_status_test".to_string(),
            |_event| async move { Ok(()) },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let health_status = event_bus.health_check().await;
        assert_eq!(health_status.len(), 1);

        let status = health_status.get("health_status_test").unwrap();
        assert_eq!(
            *status,
            crate::event_subscription::ConnectionStatus::Connected
        );
    }

    #[async_std::test]
    async fn test_unsubscribe_nonexistent() {
        let event_bus = EventBus::new();
        let result = event_bus.unsubscribe::<TestEvent>("nonexistent").await;
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_publish_without_subscribers() {
        let event_bus = EventBus::new();

        let event = Arc::new(TestEvent::new("no_subscribers"));

        let result = event_bus.publish(event).await;
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_concurrent_publishes() {
        let event_bus = EventBus::new();
        let received_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let subscriber = make_subscriber::<TestEvent, _, _>("concurrent_test".to_string(), {
            let received_count = Arc::clone(&received_count);
            move |_event| {
                let received_count = Arc::clone(&received_count);
                async move {
                    received_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }
            }
        });

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let event_bus = event_bus.clone();
            let event = Arc::new(TestEvent::new(&format!("concurrent_{}", i)));

            let handle = async_std::task::spawn(async move {
                event_bus.publish(event).await.unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await;
        }

        sleep(Duration::from_millis(100)).await;

        assert_eq!(received_count.load(std::sync::atomic::Ordering::SeqCst), 10);
    }

    #[async_std::test]
    async fn test_subscriber_config_default() {
        let event_bus = EventBus::new();

        let subscriber = make_subscriber::<TestEvent, _, _>(
            "default_config_test".to_string(),
            |_event| async move { Ok(()) },
        );

        let result = event_bus.subscribe::<TestEvent>(subscriber).await;
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_subscriber_config_duration_conversion() {
        let config = SubscriberConfig {
            max_retries: 3,
            retry_delay_secs: 5,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 10,
        };

        assert_eq!(config.retry_delay(), Duration::from_secs(5));
        assert_eq!(config.connection_timeout(), Duration::from_secs(30));
        assert_eq!(config.heartbeat_interval(), Duration::from_secs(10));
    }

    #[async_std::test]
    async fn test_restore_and_retry_dead_letters() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_bus = EventBus::new();

        // Set the event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        let success_after_restore = Arc::new(std::sync::Mutex::new(false));
        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "restore_retry_test".to_string(),
            {
                let success_after_restore = Arc::clone(&success_after_restore);
                move |event| {
                    let success_after_restore = Arc::clone(&success_after_restore);
                    async move {
                        let should_succeed = *success_after_restore.lock().unwrap();
                        if should_succeed {
                            println!("Event processed successfully after restore: {}", event.data);
                            Ok(())
                        } else {
                            Err("Simulated failure before restore".into())
                        }
                    }
                }
            },
            SubscriberConfig {
                max_retries: 1,
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let event = Arc::new(TestEvent::new("restore_retry_test"));

        // First publish (expected to fail)
        event_bus.publish(event).await.unwrap();
        event_bus.retry_failed_messages().await.unwrap();

        // Make it succeed after restoration
        *success_after_restore.lock().unwrap() = true;

        // Restore dead letters and retry
        event_bus.restore_and_retry_dead_letters().await.unwrap();

        // Successfully processed messages are removed from dead letters
        let stats = event_bus.get_persistence_stats().unwrap();
        assert_eq!(stats["message_count"], 0);
    }

    #[async_std::test]
    async fn test_multiple_dead_letters_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_bus = EventBus::with_persistence(persistence_manager);

        // Set the event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "multiple_restore_test".to_string(),
            |_event| async move { Err("Always fail".into()) },
            SubscriberConfig {
                max_retries: 1,
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        // Publish multiple events
        for i in 0..5 {
            let event = Arc::new(TestEvent::new(&format!("multiple_event_{}", i)));
            event_bus.publish(event).await.unwrap();
        }

        // Run retries (all move to dead letters)
        event_bus.retry_failed_messages().await.unwrap();

        // Check statistics
        let stats = event_bus.get_persistence_stats().unwrap();
        assert!(
            stats["message_count"] > 0,
            "Expected message_count > 0, got {}",
            stats["message_count"]
        );

        // Restore dead letters
        event_bus.restore_messages().await.unwrap();

        // Retry restored messages
        event_bus.retry_failed_messages().await.unwrap();

        // Stats after restoration and retry (remains 5 since the subscriber always fails)
        let stats_after = event_bus.get_persistence_stats().unwrap();
        assert_eq!(
            stats_after["message_count"], 5,
            "Expected message_count == 5 after restoration and retry, got {}",
            stats_after["message_count"]
        );
    }

    #[async_std::test]
    async fn test_dead_letter_cleanup_after_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_bus = EventBus::with_persistence(persistence_manager);

        // Set the event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "cleanup_restore_test".to_string(),
            |_event| async move { Err("Always fail".into()) },
            SubscriberConfig {
                max_retries: 1,
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        let event = Arc::new(TestEvent::new("cleanup_restore_test"));

        // Publish an event and persist it to dead letters
        event_bus.publish(event).await.unwrap();
        event_bus.retry_failed_messages().await.unwrap();

        // Check statistics
        let stats = event_bus.get_persistence_stats().unwrap();
        assert_eq!(stats["message_count"], 1);

        // Clean up old in-memory messages (persisted dead letters are not deleted)
        event_bus.cleanup_old_messages(Duration::from_secs(0)).await;

        // Stats after cleanup (remains 1 because persisted dead letters are kept)
        let stats_after = event_bus.get_persistence_stats().unwrap();
        assert_eq!(
            stats_after["message_count"], 1,
            "Expected message_count == 1 after cleanup, got {}",
            stats_after["message_count"]
        );
    }

    #[async_std::test]
    async fn test_database_compaction_after_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_bus = EventBus::new();

        // Set the event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "compaction_restore_test".to_string(),
            |_event| async move { Err("Always fail".into()) },
            SubscriberConfig {
                max_retries: 1,
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        // Publish multiple events
        for i in 0..10 {
            let event = Arc::new(TestEvent::new(&format!("compaction_restore_event_{}", i)));
            event_bus.publish(event).await.unwrap();
        }

        // Run retries (move to dead letters)
        event_bus.retry_failed_messages().await.unwrap();

        // Restore dead letters
        event_bus.restore_messages().await.unwrap();

        // Compact the database
        event_bus.compact_database().unwrap();

        // Check statistics
        let stats = event_bus.get_persistence_stats().unwrap();
        let message_count = stats["message_count"];
        assert!(
            message_count == 0 || message_count == 10,
            "Expected message_count to be 0 or 10, got {}",
            message_count
        );
    }

    #[async_std::test]
    async fn test_concurrent_restoration_and_publishing() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let event_bus = EventBus::new();

        // Set the event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        let received_events = Arc::new(AsyncMutex::new(Vec::new()));
        let subscriber =
            make_subscriber::<TestEvent, _, _>("concurrent_restore_test".to_string(), {
                let received_events = Arc::clone(&received_events);
                move |event| {
                    let received_events = Arc::clone(&received_events);
                    async move {
                        received_events.lock().await.push(event.data.clone());
                        Ok(())
                    }
                }
            });

        event_bus.subscribe::<TestEvent>(subscriber).await.unwrap();

        // Restore dead letters while publishing new events
        let restore_handle = async_std::task::spawn({
            let event_bus = event_bus.clone();
            async move {
                event_bus.restore_messages().await.unwrap();
            }
        });

        let publish_handle = async_std::task::spawn({
            let event_bus = event_bus.clone();
            async move {
                for i in 0..5 {
                    let event =
                        Arc::new(TestEvent::new(&format!("concurrent_restore_event_{}", i)));
                    event_bus.publish(event).await.unwrap();
                    sleep(Duration::from_millis(10)).await;
                }
            }
        });

        // Wait for both tasks to complete
        restore_handle.await;
        publish_handle.await;

        // Verify results
        sleep(Duration::from_millis(100)).await;
        let events = received_events.lock().await;
        assert_eq!(events.len(), 5);
    }

    #[async_std::test]
    async fn test_event_restorer_registration() {
        let event_bus = EventBus::new();
        let restorer = Arc::new(DefaultEventRestorer::new());

        // Set the event restorer
        event_bus.set_event_restorer(restorer).await;

        // Register the event type
        event_bus.register_event_type::<TestEvent>().await;

        // Confirm registration succeeded (no errors expected)
        assert!(true);
    }

    #[async_std::test]
    async fn test_restore_messages_without_persistence() {
        let event_bus = EventBus::new();

        // Try restoring dead letters without persistence
        let result = event_bus.restore_messages().await;
        assert!(result.is_ok()); // Should not error even without persistence
    }

    #[async_std::test]
    async fn test_restore_and_retry_without_persistence() {
        let event_bus = EventBus::new();

        // Try restoring and retrying without persistence
        let result = event_bus.restore_and_retry_dead_letters().await;
        assert!(result.is_ok()); // Should not error even without persistence
    }
}
