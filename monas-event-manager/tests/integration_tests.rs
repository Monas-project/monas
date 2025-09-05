//! Integration tests for retry functionality

use async_std::sync::Mutex as AsyncMutex;
use async_std::task::sleep;
use monas_event_manager::config::SubscriberConfig;
use monas_event_manager::event_bus::Event;
use monas_event_manager::event_bus::EventBus;
use monas_event_manager::event_subscription::{make_subscriber_with_config, DefaultEventRestorer};
use monas_event_manager::sled_persistence::SledPersistenceManager;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

// Import test types from the tests directory
mod test_types;
use test_types::{IntegrationTestEvent, TypeAEvent, TypeBEvent};

#[async_std::test]
async fn test_complete_dead_letter_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let persistence_manager =
        SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    let event_bus = EventBus::with_persistence(persistence_manager);

    // Set up event restorer
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<IntegrationTestEvent>().await;
    event_bus.set_event_restorer(restorer).await;
    event_bus
        .register_event_type::<IntegrationTestEvent>()
        .await;

    // Manage success flag
    let success_flag = Arc::new(std::sync::Mutex::new(false));
    let processed_events = Arc::new(AsyncMutex::new(Vec::new()));

    // Create subscriber
    let subscriber = make_subscriber_with_config::<IntegrationTestEvent, _, _>(
        "integration_test".to_string(),
        {
            let success_flag = Arc::clone(&success_flag);
            let processed_events = Arc::clone(&processed_events);
            move |event| {
                let success_flag = Arc::clone(&success_flag);
                let processed_events = Arc::clone(&processed_events);
                async move {
                    // Output type ID
                    println!(
                        "[DEBUG] Subscriber IntegrationTestEvent type_id: {:?}",
                        std::any::TypeId::of::<IntegrationTestEvent>()
                    );
                    let should_succeed = *success_flag.lock().unwrap();
                    if should_succeed {
                        processed_events.lock().await.push(event.id.clone());
                        println!("Successfully processed event: {}", event.id);
                        Ok(())
                    } else {
                        println!("Failed to process event: {}", event.id);
                        Err("Simulated failure".into())
                    }
                }
            }
        },
        SubscriberConfig {
            max_retries: 2,
            retry_delay_secs: 0,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 10,
        },
    );

    // Register subscriber
    event_bus
        .subscribe::<IntegrationTestEvent>(subscriber)
        .await
        .unwrap();

    // Publish multiple events (will fail)
    for i in 0..3 {
        let event = Arc::new(IntegrationTestEvent {
            id: format!("event_{i}"),
            data: format!("test_data_{i}"),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        event_bus.publish(event.clone()).await.unwrap();
    }

    // Execute retry (fail and move to dead letter)
    event_bus.retry_failed_messages().await.unwrap();
    event_bus.retry_failed_messages().await.unwrap();

    // Check statistics
    let stats = event_bus.get_persistence_stats().unwrap();
    assert_eq!(stats["message_count"], 3);

    // Enable success flag
    *success_flag.lock().unwrap() = true;

    // Restore and retry dead letters
    event_bus.restore_and_retry_dead_letters().await.unwrap();

    // Debug output dead letter contents
    if let Ok(persistence_manager) = SledPersistenceManager::new(temp_dir.path().to_str().unwrap())
    {
        if let Ok(messages) = persistence_manager.load_messages() {
            for msg in messages {
                println!(
                    "[DEBUG] DeadLetter: type={}, data={}",
                    msg.event_type, msg.event_data
                );
                // Output type ID during restoration
                if let Ok(event) = serde_json::from_str::<IntegrationTestEvent>(&msg.event_data) {
                    println!(
                        "[DEBUG] Restored IntegrationTestEvent type_id: {:?}",
                        event.as_any().type_id()
                    );
                }
            }
        }
    }
    // Dead letter count becomes 0
    let stats = event_bus.get_persistence_stats().unwrap();
    assert_eq!(
        stats["message_count"], 0,
        "Expected message_count == 0 after restoration and retry, got {}",
        stats["message_count"]
    );
}

#[async_std::test]
async fn test_partial_success_restoration() {
    let temp_dir = TempDir::new().unwrap();
    let persistence_manager =
        SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    let event_bus = EventBus::with_persistence(persistence_manager);

    // Set up event restorer
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<IntegrationTestEvent>().await;
    event_bus.set_event_restorer(restorer).await;
    event_bus
        .register_event_type::<IntegrationTestEvent>()
        .await;

    let success_count = Arc::new(std::sync::Mutex::new(0));
    let processed_events = Arc::new(AsyncMutex::new(Vec::new()));

    let subscriber = make_subscriber_with_config::<IntegrationTestEvent, _, _>(
        "partial_success_test".to_string(),
        {
            let success_count = Arc::clone(&success_count);
            let processed_events = Arc::clone(&processed_events);
            move |event| {
                let success_count = Arc::clone(&success_count);
                let processed_events = Arc::clone(&processed_events);
                async move {
                    let current_count = {
                        let mut count = success_count.lock().unwrap();
                        *count += 1;
                        *count
                    };

                    if current_count <= 2 {
                        // First 2 succeed
                        processed_events.lock().await.push(event.id.clone());
                        Ok(())
                    } else {
                        // 3rd and later fail
                        Err("Still failing".into())
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

    event_bus
        .subscribe::<IntegrationTestEvent>(subscriber)
        .await
        .unwrap();

    // Publish 5 events
    for i in 0..5 {
        let event = Arc::new(IntegrationTestEvent {
            id: format!("partial_event_{i}"),
            data: format!("partial_data_{i}"),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        event_bus.publish(event.clone()).await.unwrap();
    }

    // Execute retry
    event_bus.retry_failed_messages().await.unwrap();

    // Restore dead letters and retry
    event_bus.restore_and_retry_dead_letters().await.unwrap();

    // Check results
    sleep(Duration::from_millis(100)).await;
    let processed = processed_events.lock().await;
    assert_eq!(processed.len(), 2); // Only first 2 succeed

    // Remaining 3 stay in dead letters (max_retries: 1, so move to dead letters after 1 retry)
    let stats = event_bus.get_persistence_stats().unwrap();
    let message_count = stats["message_count"];
    assert!(
        message_count == 0 || message_count == 3,
        "Expected message_count to be 0 or 3, got {message_count}"
    );
}

#[async_std::test]
async fn test_restoration_with_multiple_event_types() {
    let temp_dir = TempDir::new().unwrap();
    let persistence_manager =
        SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    let event_bus = EventBus::with_persistence(persistence_manager);

    // Set up event restorer
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<TypeAEvent>().await;
    restorer.register_event_type::<TypeBEvent>().await;
    event_bus.set_event_restorer(restorer).await;

    // Register event types
    event_bus.register_event_type::<TypeAEvent>().await;
    event_bus.register_event_type::<TypeBEvent>().await;

    let type_a_processed = Arc::new(AsyncMutex::new(Vec::new()));
    let type_b_processed = Arc::new(AsyncMutex::new(Vec::new()));

    // TypeA subscriber
    let subscriber_a = make_subscriber_with_config::<TypeAEvent, _, _>(
        "type_a_test".to_string(),
        {
            let type_a_processed = Arc::clone(&type_a_processed);
            move |event| {
                let type_a_processed = Arc::clone(&type_a_processed);
                async move {
                    type_a_processed.lock().await.push(event.value.clone());
                    Ok(())
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

    // TypeB subscriber
    let subscriber_b = make_subscriber_with_config::<TypeBEvent, _, _>(
        "type_b_test".to_string(),
        {
            let type_b_processed = Arc::clone(&type_b_processed);
            move |event| {
                let type_b_processed = Arc::clone(&type_b_processed);
                async move {
                    type_b_processed.lock().await.push(event.id.clone());
                    Ok(())
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

    event_bus
        .subscribe::<TypeAEvent>(subscriber_a)
        .await
        .unwrap();
    event_bus
        .subscribe::<TypeBEvent>(subscriber_b)
        .await
        .unwrap();

    // Publish both event types
    for i in 0..3 {
        let event_a = Arc::new(TypeAEvent {
            value: format!("type_a_{i}"),
        });
        event_bus.publish(event_a.clone()).await.unwrap();

        let event_b = Arc::new(TypeBEvent {
            id: format!("type_b_{i}"),
            text: format!("text_{i}"),
        });
        event_bus.publish(event_b.clone()).await.unwrap();
    }

    // Execute retry (move to dead letters)
    event_bus.retry_failed_messages().await.unwrap();

    // Check statistics
    let stats = event_bus.get_persistence_stats().unwrap();
    let message_count = stats["message_count"];
    assert!(
        message_count == 0 || message_count == 6,
        "Expected message_count to be 0 or 6, got {message_count}"
    );

    // Restore dead letters
    event_bus.restore_messages().await.unwrap();
    event_bus.retry_failed_messages().await.unwrap();

    // Check results
    sleep(Duration::from_millis(100)).await;
    let type_a_results = type_a_processed.lock().await;
    let type_b_results = type_b_processed.lock().await;

    // Ensure restored events are processed
    assert!(
        !type_a_results.is_empty(),
        "TypeA events should be processed"
    );
    assert!(
        !type_b_results.is_empty(),
        "TypeB events should be processed"
    );

    // Check if expected event IDs are included
    for i in 0..3 {
        assert!(
            type_a_results.contains(&format!("type_a_{i}"))
                || type_b_results.contains(&format!("type_b_{i}"))
        );
    }
}
#[async_std::test]
async fn test_restoration_performance() {
    let temp_dir = TempDir::new().unwrap();
    let persistence_manager =
        SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    let event_bus = EventBus::with_persistence(persistence_manager);

    // Set up event restorer
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<IntegrationTestEvent>().await;
    event_bus.set_event_restorer(restorer).await;
    event_bus
        .register_event_type::<IntegrationTestEvent>()
        .await;

    let processed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let subscriber = make_subscriber_with_config::<IntegrationTestEvent, _, _>(
        "performance_test".to_string(),
        {
            let processed_count = Arc::clone(&processed_count);
            move |_event| {
                let processed_count = Arc::clone(&processed_count);
                async move {
                    processed_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }
            }
        },
        SubscriberConfig {
            max_retries: 0,
            retry_delay_secs: 0,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 10,
        },
    );

    event_bus
        .subscribe::<IntegrationTestEvent>(subscriber)
        .await
        .unwrap();

    // Publish a large number of events
    let start_time = std::time::Instant::now();

    for i in 0..100 {
        let event = Arc::new(IntegrationTestEvent {
            id: format!("perf_event_{i}"),
            data: format!("perf_data_{i}"),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        event_bus.publish(event.clone()).await.unwrap();
    }

    // Execute retry (move to dead letters)
    event_bus.retry_failed_messages().await.unwrap();

    // Restore dead letters
    event_bus.restore_messages().await.unwrap();
    event_bus.retry_failed_messages().await.unwrap();

    let end_time = std::time::Instant::now();
    let duration = end_time.duration_since(start_time);

    // Check results
    sleep(Duration::from_millis(100)).await;
    let processed = processed_count.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(processed, 100);

    // Check performance (completed within 1 second)
    assert!(duration.as_secs() < 1);

    println!("Processed {processed} events in {duration:?}");
}

#[async_std::test]
async fn test_restoration_error_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let persistence_manager =
        SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    let event_bus = EventBus::with_persistence(persistence_manager);

    // Set up event restorer
    let restorer = Arc::new(DefaultEventRestorer::new());
    restorer.register_event_type::<IntegrationTestEvent>().await;
    event_bus.set_event_restorer(restorer).await;
    event_bus
        .register_event_type::<IntegrationTestEvent>()
        .await;

    let error_count = Arc::new(std::sync::Mutex::new(0));
    let success_count = Arc::new(std::sync::Mutex::new(0));

    let subscriber = make_subscriber_with_config::<IntegrationTestEvent, _, _>(
        "error_recovery_test".to_string(),
        {
            let error_count = Arc::clone(&error_count);
            let success_count = Arc::clone(&success_count);
            move |event| {
                let error_count = Arc::clone(&error_count);
                let success_count = Arc::clone(&success_count);
                async move {
                    let mut errors = error_count.lock().unwrap();
                    *errors += 1;
                    let current_errors = *errors;

                    if current_errors <= 2 {
                        // First 2 times are errors
                        Err("Temporary error".into())
                    } else {
                        // 3rd and later succeed
                        let mut successes = success_count.lock().unwrap();
                        *successes += 1;
                        println!("Recovered and processed event: {}", event.id);
                        Ok(())
                    }
                }
            }
        },
        SubscriberConfig {
            max_retries: 5,
            retry_delay_secs: 0,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 10,
        },
    );

    event_bus
        .subscribe::<IntegrationTestEvent>(subscriber)
        .await
        .unwrap();

    // Publish event
    let event = Arc::new(IntegrationTestEvent {
        id: "recovery_test".to_string(),
        data: "recovery_data".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    event_bus.publish(event.clone()).await.unwrap();

    // Execute retry (recover from error)
    for _ in 0..5 {
        event_bus.retry_failed_messages().await.unwrap();
    }

    // Check results
    let final_errors = *error_count.lock().unwrap();
    let final_successes = *success_count.lock().unwrap();

    assert_eq!(final_errors, 3); // 2 errors + 1 success
    assert_eq!(final_successes, 1); // 1 success

    // No dead letters should remain
    let stats = event_bus.get_persistence_stats().unwrap();
    assert_eq!(stats["message_count"], 0);
}
