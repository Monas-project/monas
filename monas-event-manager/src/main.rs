use monas_event_manager::event_bus::{Event, EventBus};
use monas_event_manager::event_subscription::{
    make_subscriber, DefaultEventRestorer, SerializableEvent,
};

use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::Arc;

/// Sample event type: user creation
/// In a real application, define domain-specific event types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserCreatedEvent {
    user_id: String,    // User ID
    username: String,   // Username
    email: String,      // Email address
}

/// Implementation of the `Event` trait
/// Required for all event types
impl Event for UserCreatedEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Implementation of the `SerializableEvent` trait
/// Required to enable dead-letter persistence and restoration
impl SerializableEvent for UserCreatedEvent {
    fn event_type() -> &'static str {
        "UserCreatedEvent"
    }
}

/// Entry point: initialize the event manager and run a simple demo
/// Demonstrates basic usage at application startup
#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create an event bus (without persistence)
    let event_bus = EventBus::new();

    println!("Event Manager started");

    // Set the event restorer (required to restore persisted events)
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<UserCreatedEvent>().await;
    event_bus.set_event_restorer(restorer).await;

    // Register the event type (required when using persistence)
    event_bus.register_event_type::<UserCreatedEvent>().await;

    // Register a subscriber (service that receives and handles events)
    let subscriber =
        make_subscriber::<UserCreatedEvent, _, _>("user_service".to_string(), |event| async move {
            println!("Received user creation event: {}", event.username);
            Ok(())
        });
    event_bus.subscribe::<UserCreatedEvent>(subscriber).await?;

    // Restore dead letters and retry (startup recovery step)
    if let Err(e) = event_bus.restore_and_retry_dead_letters().await {
        eprintln!("Failed to restore and retry dead letters: {}", e);
    }

    // Get persistence stats (useful for monitoring)
    if let Ok(stats) = event_bus.get_persistence_stats() {
        println!("Database stats: {:?}", stats);
    }

    // Clean up old in-memory messages (periodic maintenance)
    event_bus
        .cleanup_old_messages(std::time::Duration::from_secs(24 * 60 * 60))
        .await;

    println!("Event Manager initialized successfully!");

    Ok(())
}

/// Test module used for local and CI verification
#[cfg(test)]
mod main_tests {
    use super::*;
    use std::sync::Arc;

    /// Verifies the `UserCreatedEvent` implementation
    #[async_std::test]
    async fn test_user_created_event_implementation() {
        let event = UserCreatedEvent {
            user_id: "123".to_string(),
            username: "test_user".to_string(),
            email: "test@example.com".to_string(),
        };

        let any_ref = event.as_any();
        assert!(any_ref.downcast_ref::<UserCreatedEvent>().is_some());

        assert_eq!(UserCreatedEvent::event_type(), "UserCreatedEvent");
    }

    /// Validates the main startup logic
    #[async_std::test]
    async fn test_main_function_logic() {
        let event_bus = EventBus::new();

        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<UserCreatedEvent>().await;
        event_bus.set_event_restorer(restorer).await;

        event_bus.register_event_type::<UserCreatedEvent>().await;

        let subscriber = make_subscriber::<UserCreatedEvent, _, _>(
            "user_service".to_string(),
            |event| async move {
                println!("Received user creation event: {}", event.username);
                Ok(())
            },
        );
        event_bus
            .subscribe::<UserCreatedEvent>(subscriber)
            .await
            .unwrap();

        let result = event_bus.restore_and_retry_dead_letters().await;
        assert!(result.is_ok());

        let stats = event_bus.get_persistence_stats();
        assert!(stats.is_ok());

        event_bus
            .cleanup_old_messages(std::time::Duration::from_secs(24 * 60 * 60))
            .await;
    }

    /// Ensures `UserCreatedEvent` can be serialized/deserialized correctly
    #[async_std::test]
    async fn test_user_created_event_serialization() {
        let event = UserCreatedEvent {
            user_id: "456".to_string(),
            username: "serialize_test".to_string(),
            email: "serialize@example.com".to_string(),
        };

        // Round-trip serialization test
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: UserCreatedEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(event.user_id, deserialized.user_id);
        assert_eq!(event.username, deserialized.username);
        assert_eq!(event.email, deserialized.email);
    }

    /// Integration test: event bus with `UserCreatedEvent`
    #[async_std::test]
    async fn test_event_bus_with_user_created_event() {
        let event_bus = EventBus::new();

        let received_events = Arc::new(std::sync::Mutex::new(Vec::new()));

        let subscriber = make_subscriber::<UserCreatedEvent, _, _>("test_service".to_string(), {
            let received_events = Arc::clone(&received_events);
            move |event| {
                let received_events = Arc::clone(&received_events);
                async move {
                    received_events.lock().unwrap().push(event.username.clone());
                    Ok(())
                }
            }
        });

        event_bus
            .subscribe::<UserCreatedEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(UserCreatedEvent {
            user_id: "789".to_string(),
            username: "test_event".to_string(),
            email: "test@example.com".to_string(),
        });

        event_bus.publish(event.clone()).await.unwrap();

        // Wait briefly before checking results
        async_std::task::sleep(std::time::Duration::from_millis(100)).await;

        let events = received_events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "test_event");
    }

    /// Ensures the app does not crash on handler errors
    #[async_std::test]
    async fn test_error_handling_in_main_logic() {
        let event_bus = EventBus::new();

        // Create a subscriber that returns an error (negative case)
        let subscriber = make_subscriber::<UserCreatedEvent, _, _>(
            "error_test".to_string(),
            |_event| async move { Err("Simulated error".into()) },
        );

        event_bus
            .subscribe::<UserCreatedEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(UserCreatedEvent {
            user_id: "error_test".to_string(),
            username: "error_user".to_string(),
            email: "error@example.com".to_string(),
        });

        // Publishing still succeeds without crashing
        event_bus.publish(event).await.unwrap();
    }
}
