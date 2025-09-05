# Monas Event Manager

An asynchronous, type-safe event-driven messaging library written in Rust. Features automatic retry mechanisms, dead letter queues, and persistent storage capabilities.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
monas-event-manager = "0.1.0"
async-std = "1.12"
serde = { version = "1.0", features = ["derive"] }
sled = "0.34"
```


## Quick Start

### 1. Define Your Event Types

```rust
use monas_event_manager::{Event, SerializableEvent};
use serde::{Deserialize, Serialize};
use std::any::Any;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserCreatedEvent {
    user_id: String,
    username: String,
    email: String,
}

impl Event for UserCreatedEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SerializableEvent for UserCreatedEvent {
    fn event_type() -> &'static str {
        "UserCreatedEvent"
    }
}
```

### 2. Set Up the Event Bus

```rust
use monas_event_manager::{EventBus, DefaultEventRestorer};
use std::sync::Arc;

// Create event bus with persistence
let persistence_manager = SledPersistenceManager::new("./events_db")?;
let event_bus = EventBus::with_persistence(persistence_manager);

// Configure event restoration
let restorer = Arc::new(DefaultEventRestorer::new());
restorer.register_event_type::<UserCreatedEvent>().await;
event_bus.set_event_restorer(restorer).await;
event_bus.register_event_type::<UserCreatedEvent>().await;
```

### 3. Create and Register Subscribers

```rust
use monas_event_manager::{make_subscriber_with_config, SubscriberConfig};

let subscriber = make_subscriber_with_config::<UserCreatedEvent, _, _>(
    "user_service".to_string(),
    |event| async move {
        println!("Processing user creation: {}", event.username);
        // Your business logic here
        Ok(())
    },
    SubscriberConfig {
        max_retries: 3,
        retry_delay_secs: 5,
        connection_timeout_secs: 30,
        heartbeat_interval_secs: 10,
    }
);

event_bus.subscribe::<UserCreatedEvent>(subscriber).await?;
```

### 4. Publish Events

```rust
use std::sync::Arc;

let event = Arc::new(UserCreatedEvent {
    user_id: "123".to_string(),
    username: "john_doe".to_string(),
    email: "john@example.com".to_string(),
});

event_bus.publish(event).await?;
```

## Detailed Usage


### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `max_retries` | Maximum number of retry attempts | 3 |
| `retry_delay_secs` | Delay between retries in seconds | 5 |
| `connection_timeout_secs` | Connection timeout in seconds | 30 |
| `heartbeat_interval_secs` | Health check interval in seconds | 10 |

### Error Handling and Recovery

```rust
// Manual retry of failed messages
event_bus.retry_failed_messages().await?;

// Restore dead letters from persistence
event_bus.restore_and_retry_dead_letters().await?;

// Clean up old messages
event_bus.cleanup_old_messages(Duration::from_secs(24 * 60 * 60)).await;

// Get system statistics
let stats = event_bus.get_persistence_stats()?;
println!("Active messages: {}", stats["message_count"]);
```

### Health Monitoring

```rust
// Check subscriber health
let health_status = event_bus.health_check().await;
for (subscriber_id, status) in health_status {
    match status {
        SubscriberStatus::Healthy => println!("✅ {}: Healthy", subscriber_id),
        SubscriberStatus::Unhealthy => println!("❌ {}: Unhealthy", subscriber_id),
        SubscriberStatus::Disconnected => println!("🔌 {}: Disconnected", subscriber_id),
    }
}
```

## Advanced Features

### Custom Event Processors

```rust
use monas_event_manager::EventProcessor;

struct CustomProcessor;

#[async_trait::async_trait]
impl EventProcessor<UserCreatedEvent> for CustomProcessor {
    async fn process(&self, event: Arc<UserCreatedEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Custom processing logic
        Ok(())
    }
}
```

### Batch Processing

```rust
// Publish multiple events
let events = vec![
    Arc::new(UserCreatedEvent { /* ... */ }),
    Arc::new(UserCreatedEvent { /* ... */ }),
];

for event in events {
    event_bus.publish(event).await?;
}
```

### Event Filtering

```rust
// Subscribe with custom filtering
let filtered_subscriber = make_subscriber_with_config::<UserCreatedEvent, _, _>(
    "filtered_service".to_string(),
    |event| async move {
        if event.username.starts_with("admin") {
            // Process admin users
            Ok(())
        } else {
            // Skip non-admin users
            Err("Not an admin user".into())
        }
    },
    SubscriberConfig::default(),
);
```

## Testing

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin --out Html

# Run specific test
cargo test test_user_created_event

# Run integration tests
cargo test --test integration_tests
```

### Development Setup

```bash
git clone https://github.com/your-org/monas-event-manager.git
cd monas-event-manager
cargo build
cargo test
```

---

**Made with ❤️ by the Monas Team**

