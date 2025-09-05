use std::any::{Any, TypeId};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_std::sync::{Mutex, RwLock};
use futures::future::BoxFuture;
use futures::FutureExt;
use serde::{Deserialize, Serialize};

use crate::config::SubscriberConfig;
use crate::event_bus::Event;
use crate::sled_persistence::SledPersistenceManager;

#[derive(Debug, Clone)]
pub struct DummyEvent;

impl Event for DummyEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Trait for event serialization and deserialization
pub trait SerializableEvent:
    Event + Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static
{
    fn event_type() -> &'static str;
}

// Trait for event restoration
pub trait EventRestorer {
    fn restore_event(
        &self,
        event_type: &str,
        event_data: &str,
    ) -> Option<Arc<dyn Event + Send + Sync>>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

impl serde::Serialize for DeliveryStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DeliveryStatus::Pending => serializer.serialize_str("pending"),
            DeliveryStatus::Delivered => serializer.serialize_str("delivered"),
            DeliveryStatus::Failed => serializer.serialize_str("failed"),
            DeliveryStatus::Retrying => serializer.serialize_str("retrying"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for DeliveryStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DeliveryStatusVisitor;

        impl<'de> serde::de::Visitor<'de> for DeliveryStatusVisitor {
            type Value = DeliveryStatus;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing DeliveryStatus")
            }

            fn visit_str<E>(self, value: &str) -> Result<DeliveryStatus, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "pending" => Ok(DeliveryStatus::Pending),
                    "delivered" => Ok(DeliveryStatus::Delivered),
                    "failed" => Ok(DeliveryStatus::Failed),
                    "retrying" => Ok(DeliveryStatus::Retrying),
                    _ => Err(E::custom(format!("unknown delivery status: {}", value))),
                }
            }
        }

        deserializer.deserialize_str(DeliveryStatusVisitor)
    }
}

#[derive(Clone)]
pub struct EventMessage {
    pub id: String,
    pub event: Arc<dyn Event + Send + Sync>,
    pub event_type: String,
    pub event_data: String,
    pub timestamp: Instant,
    pub status: DeliveryStatus,
    pub retry_count: u32,
    pub max_retries: u32,
}

impl std::fmt::Debug for EventMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventMessage")
            .field("id", &self.id)
            .field("event", &"<dyn Event>")
            .field("timestamp", &self.timestamp)
            .field("status", &self.status)
            .field("retry_count", &self.retry_count)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Reconnecting,
    Failed,
}

pub struct Subscriber {
    id: String,
    handler: Arc<
        dyn Fn(
                &dyn Event,
            )
                -> BoxFuture<'static, Result<(), Box<dyn std::error::Error + Send + Sync>>>
            + Send
            + Sync,
    >,
    config: SubscriberConfig,
    status: Arc<RwLock<ConnectionStatus>>,
    last_heartbeat: Arc<Mutex<Instant>>,
    message_queue: Arc<Mutex<VecDeque<EventMessage>>>,
    failed_messages: Arc<Mutex<Vec<EventMessage>>>,
    dead_letter_callback: Arc<Mutex<Option<Arc<dyn Fn(&EventMessage) + Send + Sync>>>>,
}

impl Subscriber {
    pub fn new<F, Fut>(id: String, handler: F) -> Self
    where
        F: Fn(&dyn Event) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
            + Send
            + 'static,
    {
        Self {
            id,
            handler: Arc::new(move |event| handler(event).boxed()),
            config: SubscriberConfig::default(),
            status: Arc::new(RwLock::new(ConnectionStatus::Connected)),
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            failed_messages: Arc::new(Mutex::new(Vec::new())),
            dead_letter_callback: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_config<F, Fut>(id: String, handler: F, config: SubscriberConfig) -> Self
    where
        F: Fn(&dyn Event) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
            + Send
            + 'static,
    {
        Self {
            id,
            handler: Arc::new(move |event| handler(event).boxed()),
            config,
            status: Arc::new(RwLock::new(ConnectionStatus::Connected)),
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            failed_messages: Arc::new(Mutex::new(Vec::new())),
            dead_letter_callback: Arc::new(Mutex::new(None)),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub async fn status(&self) -> ConnectionStatus {
        self.status.read().await.clone()
    }

    pub async fn update_status(&self, status: ConnectionStatus) {
        *self.status.write().await = status;
    }

    pub async fn update_heartbeat(&self) {
        *self.last_heartbeat.lock().await = Instant::now();
    }

    pub async fn is_healthy(&self) -> bool {
        let last_heartbeat = *self.last_heartbeat.lock().await;
        let status = self.status().await;
        status == ConnectionStatus::Connected
            && last_heartbeat.elapsed() < self.config.connection_timeout()
    }

    /// Process an event and return an error if it fails
    pub async fn process_event(
        &self,
        message: &EventMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("Starting to process event {}", message.id);

        if !self.is_healthy().await {
            eprintln!("Subscriber is not healthy, updating status to Reconnecting");
            self.update_status(ConnectionStatus::Reconnecting).await;
            return Err("Subscriber is not healthy".into());
        }

        eprintln!("Calling handler for event {}", message.id);
        let result = (self.handler)(message.event.as_ref()).await;
        eprintln!(
            "Handler completed for event {} with result: {:?}",
            message.id, result
        );

        match result {
            Ok(_) => {
                eprintln!(
                    "Event {} processed successfully, updating heartbeat",
                    message.id
                );
        self.update_heartbeat().await;
                Ok(())
            }
            Err(e) => {
                eprintln!("Event {} failed with error: {}", message.id, e);
                Err(e)
            }
        }
    }

    pub async fn add_to_retry_queue(&self, message: EventMessage) {
        let mut queue = self.message_queue.lock().await;
        queue.push_back(message);
    }

    pub async fn add_to_failed_messages(&self, message: EventMessage) {
        let mut failed = self.failed_messages.lock().await;
        failed.push(message.clone());

        // Save to dead letter
        if let Some(callback) = &*self.dead_letter_callback.lock().await {
            callback(&message);
        }
    }

    /// Set callback for dead letter saving
    pub async fn set_dead_letter_callback<F>(&self, callback: F)
    where
        F: Fn(&EventMessage) + Send + Sync + 'static,
    {
        *self.dead_letter_callback.lock().await = Some(Arc::new(callback));
    }

    pub async fn process_retry_queue(&self, persistence: Option<&SledPersistenceManager>) {
        let mut queue = self.message_queue.lock().await;
        let mut to_retry = Vec::new();

        let initial_queue_size = queue.len();
        if initial_queue_size > 0 {
            eprintln!(
                "Processing retry queue with {} messages",
                initial_queue_size
            );
        }

        while let Some(message) = queue.pop_front() {
                let result = self.process_event(&message).await;
            if let Err(e) = result {
                eprintln!("Message {} failed with error: {}", message.id, e);
                // Increment retry count and add back to queue on retry failure
                let mut failed_message = message;
                failed_message.retry_count += 1;
                failed_message.status = DeliveryStatus::Retrying;

                // Only add to queue if max retries not reached
                if failed_message.retry_count < failed_message.max_retries {
                    eprintln!(
                        "Adding message {} back to retry queue (retry_count={})",
                        failed_message.id, failed_message.retry_count
                    );
                    to_retry.push(failed_message);
                } else {
                    // Move to failed messages if max retries exceeded
                    eprintln!(
                        "Message {} exceeded max retries, moving to failed messages",
                        failed_message.id
                    );
                    self.add_to_failed_messages(failed_message).await;
                }
            } else {
                eprintln!("Message {} processed successfully", message.id);
                // Remove from persistence store as well
                if let Some(persistence) = persistence {
                    if let Err(e) = persistence.delete_message(&message.id) {
                        eprintln!("Failed to delete message from persistence: {}", e);
                    }
                }
            }
        }

        for message in to_retry {
            queue.push_back(message);
        }

        let final_queue_size = queue.len();
        if final_queue_size != initial_queue_size {
            eprintln!(
                "Retry queue size changed from {} to {}",
                initial_queue_size, final_queue_size
            );
    }
    }

    pub async fn get_failed_messages(&self) -> Vec<EventMessage> {
        self.failed_messages.lock().await.clone()
    }

    pub async fn clear_failed_messages(&self) {
        self.failed_messages.lock().await.clear();
    }
}

#[derive(Clone)]
pub struct EventSubscriptions {
    subscriptions: Arc<RwLock<HashMap<TypeId, Vec<Arc<Subscriber>>>>>,
    // In-memory message management (fast)
    message_store: Arc<Mutex<HashMap<String, EventMessage>>>,
    // Dead letter persistence manager (failed messages only)
    dead_letter_manager: Option<SledPersistenceManager>,
    // Event type registration information
    event_registry: Arc<RwLock<HashMap<String, TypeId>>>,
    // Event restorer
    event_restorer: Arc<Mutex<Option<Arc<dyn EventRestorer + Send + Sync>>>>,
}

impl EventSubscriptions {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            message_store: Arc::new(Mutex::new(HashMap::new())),
            dead_letter_manager: None,
            event_registry: Arc::new(RwLock::new(HashMap::new())),
            event_restorer: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize with persistence manager
    pub fn with_persistence(persistence_manager: SledPersistenceManager) -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            message_store: Arc::new(Mutex::new(HashMap::new())),
            dead_letter_manager: Some(persistence_manager),
            event_registry: Arc::new(RwLock::new(HashMap::new())),
            event_restorer: Arc::new(Mutex::new(None)),
        }
    }

    /// Register event type
    pub async fn register_event_type<T: SerializableEvent>(&self) {
        let mut registry = self.event_registry.write().await;
        registry.insert(T::event_type().to_string(), TypeId::of::<T>());
    }

    /// Set event restorer
    pub async fn set_event_restorer(&self, restorer: Arc<dyn EventRestorer + Send + Sync>) {
        *self.event_restorer.lock().await = Some(restorer);
    }

    /// Register subscriber
    pub async fn subscribe<T>(
        &self,
        subscriber: Arc<Subscriber>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: Event + 'static,
    {
        let type_id = TypeId::of::<T>();
        let mut subscriptions = self.subscriptions.write().await;
        
        // Set dead letter callback
        let dead_letter_manager = self.dead_letter_manager.clone();
        subscriber
            .set_dead_letter_callback(move |message| {
                if let Some(persistence) = &dead_letter_manager {
                    let mut dead_letter_message = message.clone();
                    dead_letter_message.status = DeliveryStatus::Failed;
                    if let Err(e) = persistence.save_message(&dead_letter_message) {
                        eprintln!("Failed to persist dead letter: {}", e);
                    }
                }
            })
            .await;

        subscriptions
            .entry(type_id)
            .or_insert_with(Vec::new)
            .push(subscriber);
        
        Ok(())
    }

    /// Remove subscriber
    pub async fn unsubscribe<T>(
        &self,
        subscriber_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: Event + 'static,
    {
        let type_id = TypeId::of::<T>();
        let mut subscriptions = self.subscriptions.write().await;
        
        if let Some(subscribers) = subscriptions.get_mut(&type_id) {
            subscribers.retain(|sub| sub.id() != subscriber_id);
            if subscribers.is_empty() {
                subscriptions.remove(&type_id);
            }
        }
        
        Ok(())
    }

    /// Publish event
    pub async fn publish<T>(
        &self,
        event: Arc<T>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: SerializableEvent + 'static,
    {
        let type_id = TypeId::of::<T>();
        // Create a base UUID per event and suffix with subscriber ID to ensure uniqueness per subscriber
        let base_uuid = uuid::Uuid::new_v4();

        let subscriptions = self.subscriptions.read().await;
        if let Some(subscribers) = subscriptions.get(&type_id) {
            for subscriber in subscribers {
                // Generate a unique message ID per subscriber
                let message_id = format!("msg_{}::{}", base_uuid, subscriber.id());
                let message = EventMessage {
                    id: message_id.clone(),
                    event: event.clone(),
                    event_type: T::event_type().to_string(),
                    event_data: serde_json::to_string(&*event).unwrap(),
                    timestamp: Instant::now(),
                    status: DeliveryStatus::Pending,
                    retry_count: 0,
                    max_retries: subscriber.config.max_retries,
                };
                // Save message to in-memory store (fast)
                self.message_store
                    .lock()
                    .await
                    .insert(message_id.clone(), message.clone());
                
                let result = subscriber.process_event(&message).await;
                if let Err(e) = result {
                    eprintln!("Error processing event: {}", e);
                    // Add failed message to retry queue
                    let mut failed_message = message.clone();
                    failed_message.status = DeliveryStatus::Retrying;
                    subscriber.add_to_retry_queue(failed_message).await;
                    }
                }
            }
        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> HashMap<String, ConnectionStatus> {
        let subscriptions = self.subscriptions.read().await;
        let mut health_status = HashMap::new();
        
        for (_, subscribers) in subscriptions.iter() {
            for subscriber in subscribers {
                let status = if subscriber.is_healthy().await {
                    ConnectionStatus::Connected
                } else {
                    ConnectionStatus::Disconnected
                };
                health_status.insert(subscriber.id().to_string(), status);
            }
        }
        
        health_status
    }

    /// Retry failed messages
    pub async fn retry_failed_messages(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let subscriptions = self.subscriptions.read().await;
        let persistence = self.dead_letter_manager.as_ref();
        for (_, subscribers) in subscriptions.iter() {
            for subscriber in subscribers {
                subscriber.process_retry_queue(persistence).await;
            }
        }
        Ok(())
    }

    /// Get message from message store
    pub async fn get_message(&self, message_id: &str) -> Option<EventMessage> {
        self.message_store.lock().await.get(message_id).cloned()
    }

    /// Clean up old messages
    pub async fn cleanup_old_messages(&self, max_age: Duration) {
        let mut store = self.message_store.lock().await;
        let now = Instant::now();
        
        store.retain(|_, message| now.duration_since(message.timestamp) < max_age);
    }

    /// Restore messages from persistence and add back to retry queue
    pub async fn restore_messages(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(persistence) = &self.dead_letter_manager {
            let persistent_messages = persistence.load_messages()?;

            for persistent_msg in persistent_messages {
                // Restore event
                let event = if let Some(restorer) = &*self.event_restorer.lock().await {
                    // Use event restorer to actually restore event
                    restorer
                        .restore_event(&persistent_msg.event_type, &persistent_msg.event_data)
                        .unwrap_or_else(|| Arc::new(DummyEvent))
                } else {
                    // If restorer not set, use DummyEvent
                    Arc::new(DummyEvent)
                };

                // Rebuild `Instant` using the elapsed seconds since the persisted UNIX timestamp
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age_secs = now_secs.saturating_sub(persistent_msg.timestamp);

                let message = EventMessage {
                    id: persistent_msg.id,
                    event,
                    event_type: persistent_msg.event_type,
                    event_data: persistent_msg.event_data,
                    timestamp: Instant::now() - Duration::from_secs(age_secs),
                    status: DeliveryStatus::Retrying,
                    retry_count: 0,
                    max_retries: persistent_msg.max_retries,
                };

                // Save to in-memory store
                self.message_store
                    .lock()
                    .await
                    .insert(message.id.clone(), message.clone());

                // Add to dead letter retry queue
                self.add_dead_letter_to_retry_queue(message).await;
            }
        }
        Ok(())
    }

    /// Add dead letter to retry queue
    async fn add_dead_letter_to_retry_queue(&self, message: EventMessage) {
        let subscriptions = self.subscriptions.read().await;
        
        // Add to retry queue of all subscribers
        for (_, subscribers) in subscriptions.iter() {
            for subscriber in subscribers {
                subscriber.add_to_retry_queue(message.clone()).await;
            }
        }
    }

    /// Persist message to dead letter (failed messages only)
    fn persist_dead_letter(&self, message: &EventMessage) {
        if let Some(persistence) = &self.dead_letter_manager {
            if let Err(e) = persistence.save_message(message) {
                eprintln!("Failed to persist dead letter: {}", e);
            }
        }
    }

    /// Save message to dead letter
    pub async fn save_to_dead_letter(&self, message: &EventMessage) {
        let mut dead_letter_message = message.clone();
        dead_letter_message.status = DeliveryStatus::Failed;
        self.persist_dead_letter(&dead_letter_message);
    }

    /// Get database statistics
    pub fn get_persistence_stats(
        &self,
    ) -> Result<HashMap<String, usize>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(persistence) = &self.dead_letter_manager {
            persistence.get_stats()
        } else {
            let mut stats = HashMap::new();
            stats.insert("message_count".to_string(), 0);
            stats.insert("total_size_bytes".to_string(), 0);
            Ok(stats)
        }
    }

    /// Compact database
    pub fn compact_database(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(persistence) = &self.dead_letter_manager {
            persistence.compact()
        } else {
            Ok(())
        }
    }
}

impl Default for EventSubscriptions {
    fn default() -> Self {
        Self::new()
    }
}

pub fn make_subscriber<T, F, Fut>(id: String, handler: F) -> Arc<Subscriber>
where
    T: Event + Clone + 'static,
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + 'static,
{
    let wrapped = move |event: &dyn Event| {
        if let Some(specific) = event.as_any().downcast_ref::<T>() {
            handler(Arc::new(specific.clone())).boxed()
        } else {
            async { Err("Received event of unexpected type".into()) }.boxed()
        }
    };
    Arc::new(Subscriber::new(id, wrapped))
}

pub fn make_subscriber_with_config<T, F, Fut>(
    id: String,
    handler: F,
    config: SubscriberConfig,
) -> Arc<Subscriber>
where
    T: Event + Clone + 'static,
    F: Fn(Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + 'static,
{
    let wrapped = move |event: &dyn Event| {
        if let Some(specific) = event.as_any().downcast_ref::<T>() {
            handler(Arc::new(specific.clone())).boxed()
        } else {
            async { Err("Received event of unexpected type".into()) }.boxed()
        }
    };
    Arc::new(Subscriber::with_config(id, wrapped, config))
}

// Default event restorer
pub struct DefaultEventRestorer {
    event_types: Arc<
        RwLock<
            HashMap<
                String,
                Box<dyn Fn(&str) -> Option<Arc<dyn Event + Send + Sync>> + Send + Sync>,
            >,
        >,
    >,
}

impl DefaultEventRestorer {
    pub fn new() -> Self {
        Self {
            event_types: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_event_type<T: SerializableEvent>(&self) {
        let mut types = self.event_types.write().await;
        let event_type = T::event_type().to_string();
        let deserializer = move |data: &str| {
            serde_json::from_str::<T>(data)
                .ok()
                .map(|event| Arc::new(event) as Arc<dyn Event + Send + Sync>)
        };
        types.insert(event_type, Box::new(deserializer));
    }
}

impl EventRestorer for DefaultEventRestorer {
    fn restore_event(
        &self,
        event_type: &str,
        event_data: &str,
    ) -> Option<Arc<dyn Event + Send + Sync>> {
        // Execution outside of async context, blocking execution
        let types = futures::executor::block_on(async { self.event_types.read().await });

        if let Some(deserializer) = types.get(event_type) {
            let restored = deserializer(event_data);
            if let Some(event) = &restored {
                println!(
                    "[DEBUG] DefaultEventRestorer: restored event_type={}, actual_type_id={:?}",
                    event_type,
                    event.as_any().type_id()
                );
        } else {
                println!(
                    "[DEBUG] DefaultEventRestorer: failed to deserialize event_type={}",
                    event_type
                );
            }
            restored
        } else {
            println!(
                "[DEBUG] DefaultEventRestorer: unknown event_type={}",
                event_type
            );
            None
        }
    }
}

#[cfg(test)]
mod event_subscription_tests {
    use super::*;
    use crate::config::SubscriberConfig;
    use crate::sled_persistence::SledPersistenceManager;
    use async_std::sync::Mutex as AsyncMutex;
    use async_std::task::sleep;
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

    #[async_std::test]
    async fn test_dead_letter_persistence_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

        let fail_count = Arc::new(std::sync::Mutex::new(0));
        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "dead_letter_test".to_string(),
            {
                let fail_count = Arc::clone(&fail_count);
                move |_event| {
                    let fail_count = Arc::clone(&fail_count);
                    async move {
                        let mut count = fail_count.lock().unwrap();
                        *count += 1;
                        // Always fail and saved to dead letter
                        Err("Simulated failure".into())
                    }
                }
            },
            SubscriberConfig {
                max_retries: 1,      // Retry only once
                retry_delay_secs: 0, // Retry immediately
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(TestEvent {
            data: "dead_letter_test".to_string(),
        });

        // Publish event (fail and saved to dead letter)
        subscriptions.publish(event).await.unwrap();

        // Retry execution (fail and move to dead letter)
        subscriptions.retry_failed_messages().await.unwrap();

        // Restore dead letter
        subscriptions.restore_messages().await.unwrap();

        // Restored message added back to retry queue
        subscriptions.retry_failed_messages().await.unwrap();

        // Check statistics
        let stats = subscriptions.get_persistence_stats().unwrap();
        assert!(stats.contains_key("message_count"));
        assert!(stats["message_count"] > 0);
    }

    #[async_std::test]
    async fn test_restore_and_retry_dead_letters() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

        let success_after_restore = Arc::new(std::sync::Mutex::new(false));
        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "restore_test".to_string(),
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

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(TestEvent {
            data: "restore_test".to_string(),
        });

        // First publish (fail)
        subscriptions.publish(event).await.unwrap();
        subscriptions.retry_failed_messages().await.unwrap();

        // Set to succeed after restore
        *success_after_restore.lock().unwrap() = true;

        // Restore and retry
        subscriptions.restore_messages().await.unwrap();
        subscriptions.retry_failed_messages().await.unwrap();

        // Check statistics
        let stats = subscriptions.get_persistence_stats().unwrap();
        let message_count = stats["message_count"];
        assert!(
            message_count == 0 || message_count == 1,
            "Expected message_count to be 0 or 1, got {}",
            message_count
        );
    }

    #[async_std::test]
    async fn test_type_safe_event_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

        let received_events = Arc::new(AsyncMutex::new(Vec::new()));
        let subscriber = make_subscriber::<TestEvent, _, _>("type_safe_test".to_string(), {
            let received_events = Arc::clone(&received_events);
            move |event| {
                let received_events = Arc::clone(&received_events);
                async move {
                    received_events.lock().await.push(event.data.clone());
                    Ok(())
                }
            }
        });

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(TestEvent {
            data: "type_safe_test".to_string(),
        });

        // Publish event and save to dead letter
        subscriptions.publish(event).await.unwrap();

        // Restore dead letter (type safe restoration)
        subscriptions.restore_messages().await.unwrap();

        // Restored event processed correctly
        sleep(Duration::from_millis(100)).await;
        let events = received_events.lock().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "type_safe_test");
    }

    #[async_std::test]
    async fn test_multiple_dead_letters_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

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

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        // Publish multiple events
        for i in 0..5 {
            let event = Arc::new(TestEvent::new(&format!("multiple_event_{}", i)));
            subscriptions.publish(event).await.unwrap();
        }

        // Retry execution (all move to dead letter)
        subscriptions.retry_failed_messages().await.unwrap();

        // Check statistics
        let stats = subscriptions.get_persistence_stats().unwrap();
        assert!(
            stats["message_count"] > 0,
            "Expected message_count > 0, got {}",
            stats["message_count"]
        );

        // Restore dead letter
        subscriptions.restore_messages().await.unwrap();

        // Restored message added back to retry queue
        subscriptions.retry_failed_messages().await.unwrap();

        // Restoration and retry statistics (subscribers always fail, so remains 5)
        let stats_after = subscriptions.get_persistence_stats().unwrap();
        assert_eq!(
            stats_after["message_count"], 5,
            "Expected message_count == 5 after restoration and retry, got {}",
            stats_after["message_count"]
        );
    }

    #[async_std::test]
    async fn test_dead_letter_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "cleanup_test".to_string(),
            |_event| async move { Err("Always fail".into()) },
            SubscriberConfig {
                max_retries: 1, // Change from 0 to 1
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        let event = Arc::new(TestEvent {
            data: "cleanup_test".to_string(),
        });

        // Publish event and save to dead letter
        subscriptions.publish(event).await.unwrap();
        subscriptions.retry_failed_messages().await.unwrap();

        // Check statistics (max_retries: 1, so move to dead letter after 1 retry)
        let stats = subscriptions.get_persistence_stats().unwrap();
        assert_eq!(stats["message_count"], 1);

        // Clean up old messages
        subscriptions
            .cleanup_old_messages(Duration::from_secs(0))
            .await;

        // Post-cleanup statistics
        let stats_after = subscriptions.get_persistence_stats().unwrap();
        assert_eq!(
            stats_after["message_count"], 1,
            "Expected message_count == 1 after cleanup, got {}",
            stats_after["message_count"]
        );
    }

    #[async_std::test]
    async fn test_event_restorer_registration() {
        let restorer = DefaultEventRestorer::new();

        // Register event type
        restorer.register_event_type::<TestEvent>().await;

        // Restore registered event type
        let event_data = r#"{"data": "restorer_test"}"#;
        let restored = restorer.restore_event("TestEvent", event_data);

        assert!(restored.is_some());
        if let Some(event) = restored {
            // Strict downcast assertion
            let test_event = event
                .as_any()
                .downcast_ref::<TestEvent>()
                .expect("Failed to downcast to TestEvent");
            assert_eq!(test_event.data, "restorer_test");
        }
    }

    #[async_std::test]
    async fn test_unknown_event_type_restoration() {
        let restorer = DefaultEventRestorer::new();

        // Try to restore unregistered event type
        let event_data = r#"{"data": "unknown_test"}"#;
        let restored = restorer.restore_event("UnknownEvent", event_data);

        assert!(restored.is_none());
    }

    #[async_std::test]
    async fn test_database_compaction_after_restoration() {
        let temp_dir = TempDir::new().unwrap();
        let persistence_manager =
            SledPersistenceManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        let subscriptions = EventSubscriptions::with_persistence(persistence_manager);

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        subscriptions.set_event_restorer(restorer).await;

        // Register event type
        subscriptions.register_event_type::<TestEvent>().await;

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "compaction_test".to_string(),
            |_event| async move { Err("Always fail".into()) },
            SubscriberConfig {
                max_retries: 1, // Change from 0 to 1
                retry_delay_secs: 0,
                connection_timeout_secs: 30,
                heartbeat_interval_secs: 10,
            },
        );

        subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        // Publish multiple events
        for i in 0..10 {
            let event = Arc::new(TestEvent {
                data: format!("compaction_event_{}", i),
            });
            subscriptions.publish(event).await.unwrap();
        }

        // Retry execution (move to dead letter)
        subscriptions.retry_failed_messages().await.unwrap();

        // Restore dead letter
        subscriptions.restore_messages().await.unwrap();

        // Compact database
        subscriptions.compact_database().unwrap();

        // Check statistics
        let stats = subscriptions.get_persistence_stats().unwrap();
        let message_count = stats["message_count"];
        assert!(
            message_count == 0 || message_count == 10,
            "Expected message_count to be 0 or 10, got {}",
            message_count
        );
    }

    #[async_std::test]
    async fn test_concurrent_restoration_and_publishing() {
        let event_subscriptions = EventSubscriptions::new();

        // Set event restorer
        let restorer = Arc::new(DefaultEventRestorer::new());
        restorer.register_event_type::<TestEvent>().await;
        event_subscriptions.set_event_restorer(restorer).await;

        // Register event type
        event_subscriptions.register_event_type::<TestEvent>().await;

        // Register subscriber
        let subscriber = make_subscriber::<TestEvent, _, _>(
            "concurrent_test".to_string(),
            |_event| async move {
                async_std::task::sleep(std::time::Duration::from_millis(10)).await;
                Ok(())
            },
        );
        event_subscriptions
            .subscribe::<TestEvent>(subscriber)
            .await
            .unwrap();

        // Run concurrent restoration and publishing
        let restore_handle = async_std::task::spawn({
            let event_subscriptions = event_subscriptions.clone();
            async move {
                event_subscriptions.restore_messages().await.unwrap();
            }
        });

        let publish_handle = async_std::task::spawn({
            let event_subscriptions = event_subscriptions.clone();
            async move {
                let event = Arc::new(TestEvent {
                    data: "concurrent_test".to_string(),
                });
                event_subscriptions.publish(event).await.unwrap();
            }
        });

        // Wait for both processes to complete
        let (restore_result, publish_result) = futures::join!(restore_handle, publish_handle);

        // spawn return value is () so no need for is_ok()
        assert_eq!(restore_result, ());
        assert_eq!(publish_result, ());
    }

    #[async_std::test]
    async fn test_subscriber_health_check() {
        let subscriber =
            make_subscriber::<TestEvent, _, _>("health_test".to_string(), |_event| async move {
                Ok(())
            });

        // Initial state is healthy
        assert!(subscriber.is_healthy().await);

        // Update status
        subscriber
            .update_status(ConnectionStatus::Disconnected)
            .await;
        assert!(!subscriber.is_healthy().await);

        // Reconnect
        subscriber.update_status(ConnectionStatus::Connected).await;
        assert!(subscriber.is_healthy().await);
    }

    #[async_std::test]
    async fn test_subscriber_heartbeat() {
        let subscriber =
            make_subscriber::<TestEvent, _, _>("heartbeat_test".to_string(), |_event| async move {
                Ok(())
            });

        let initial_heartbeat = subscriber.last_heartbeat.lock().await;
        let initial_time = *initial_heartbeat;
        drop(initial_heartbeat);

        // Wait a bit
        async_std::task::sleep(std::time::Duration::from_millis(10)).await;

        // Update heartbeat
        subscriber.update_heartbeat().await;

        let updated_heartbeat = subscriber.last_heartbeat.lock().await;
        let updated_time = *updated_heartbeat;
        drop(updated_heartbeat);

        assert!(updated_time > initial_time);
    }

    #[async_std::test]
    async fn test_subscriber_status_transitions() {
        let subscriber =
            make_subscriber::<TestEvent, _, _>("status_test".to_string(), |_event| async move {
                Ok(())
            });

        // Initial state
        assert_eq!(subscriber.status().await, ConnectionStatus::Connected);

        // Status transitions
        subscriber
            .update_status(ConnectionStatus::Reconnecting)
            .await;
        assert_eq!(subscriber.status().await, ConnectionStatus::Reconnecting);

        subscriber.update_status(ConnectionStatus::Failed).await;
        assert_eq!(subscriber.status().await, ConnectionStatus::Failed);

        subscriber.update_status(ConnectionStatus::Connected).await;
        assert_eq!(subscriber.status().await, ConnectionStatus::Connected);
    }

    #[async_std::test]
    async fn test_message_store_operations() {
        let event_subscriptions = EventSubscriptions::new();

        let event = Arc::new(TestEvent {
            data: "store_test".to_string(),
        });
        let message = EventMessage {
            id: "test_message".to_string(),
            event: event.clone(),
            event_type: "TestEvent".to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save message
        event_subscriptions
            .message_store
            .lock()
            .await
            .insert(message.id.clone(), message.clone());

        // Get message
        let retrieved = event_subscriptions.get_message(&message.id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, message.id);

        // Get non-existent message
        let not_found = event_subscriptions.get_message("nonexistent").await;
        assert!(not_found.is_none());
    }

    #[async_std::test]
    async fn test_cleanup_old_messages() {
        let event_subscriptions = EventSubscriptions::new();

        let event = Arc::new(TestEvent {
            data: "cleanup_test".to_string(),
        });

        // Old message
        let old_message = EventMessage {
            id: "old_message".to_string(),
            event: event.clone(),
            event_type: "TestEvent".to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now() - Duration::from_secs(100),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // New message
        let new_message = EventMessage {
            id: "new_message".to_string(),
            event: event.clone(),
            event_type: "TestEvent".to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Pending,
            retry_count: 0,
            max_retries: 3,
        };

        // Save message
        event_subscriptions
            .message_store
            .lock()
            .await
            .insert(old_message.id.clone(), old_message);
        event_subscriptions
            .message_store
            .lock()
            .await
            .insert(new_message.id.clone(), new_message);

        // Run cleanup (remove messages older than 50 seconds)
        event_subscriptions
            .cleanup_old_messages(Duration::from_secs(50))
            .await;

        // Old message removed, new message remains
        assert!(event_subscriptions
            .get_message("old_message")
            .await
            .is_none());
        assert!(event_subscriptions
            .get_message("new_message")
            .await
            .is_some());
    }

    #[async_std::test]
    async fn test_subscriber_failed_messages_management() {
        let subscriber =
            make_subscriber::<TestEvent, _, _>("failed_test".to_string(), |_event| async move {
                Err("Simulated failure".into())
            });

        let event = Arc::new(TestEvent {
            data: "failed_test".to_string(),
        });
        let message = EventMessage {
            id: "failed_message".to_string(),
            event: event.clone(),
            event_type: "TestEvent".to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };

        // Add failed message
        subscriber.add_to_failed_messages(message.clone()).await;

        // Get failed messages
        let failed_messages = subscriber.get_failed_messages().await;
        assert_eq!(failed_messages.len(), 1);
        assert_eq!(failed_messages[0].id, message.id);

        // Clear failed messages
        subscriber.clear_failed_messages().await;
        let cleared_messages = subscriber.get_failed_messages().await;
        assert_eq!(cleared_messages.len(), 0);
    }

    #[async_std::test]
    async fn test_subscriber_dead_letter_callback() {
        let callback_called = Arc::new(std::sync::Mutex::new(false));

        let subscriber =
            make_subscriber::<TestEvent, _, _>("callback_test".to_string(), |_event| async move {
                Ok(())
            });

        // Set dead letter callback
        {
            let callback_called = Arc::clone(&callback_called);
            subscriber
                .set_dead_letter_callback(move |_message| {
                    let mut called = callback_called.lock().unwrap();
                    *called = true;
                })
                .await;
        }

        let event = Arc::new(TestEvent {
            data: "callback_test".to_string(),
        });
        let message = EventMessage {
            id: "callback_message".to_string(),
            event: event.clone(),
            event_type: "TestEvent".to_string(),
            event_data: serde_json::to_string(&*event).unwrap_or_default(),
            timestamp: Instant::now(),
            status: DeliveryStatus::Failed,
            retry_count: 3,
            max_retries: 3,
        };

        // Add failed message (callback called)
        subscriber.add_to_failed_messages(message).await;

        // Verify callback called
        let called = callback_called.lock().unwrap();
        assert!(*called);
    }

    #[async_std::test]
    async fn test_event_subscriptions_without_persistence() {
        let event_subscriptions = EventSubscriptions::new(); // No persistence

        // Get statistics (no persistence case)
        let stats = event_subscriptions.get_persistence_stats().unwrap();
        assert_eq!(stats.get("message_count").unwrap(), &0);
        assert_eq!(stats.get("total_size_bytes").unwrap(), &0);

        // Compact database (no persistence case)
        let result = event_subscriptions.compact_database();
        assert!(result.is_ok());
    }

    #[async_std::test]
    async fn test_delivery_status_serialization() {
        let statuses = vec![
            DeliveryStatus::Pending,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::Retrying,
        ];

        for status in statuses {
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: DeliveryStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[async_std::test]
    async fn test_subscriber_config_conversion() {
        let config = SubscriberConfig {
            max_retries: 5,
            retry_delay_secs: 10,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 15,
        };

        let subscriber = make_subscriber_with_config::<TestEvent, _, _>(
            "config_test".to_string(),
            |_event| async move { Ok(()) },
            config,
        );

        // Verify settings correctly applied
        assert_eq!(subscriber.config.max_retries, 5);
        assert_eq!(subscriber.config.retry_delay(), Duration::from_secs(10));
        assert_eq!(
            subscriber.config.heartbeat_interval(),
            Duration::from_secs(15)
        );
    }

    #[async_std::test]
    async fn test_event_subscriptions_default_implementation() {
        let event_subscriptions = EventSubscriptions::default();

        // Verify default implementation works correctly
        assert!(event_subscriptions.subscriptions.read().await.is_empty());
        assert!(event_subscriptions.message_store.lock().await.is_empty());
        assert!(event_subscriptions.dead_letter_manager.is_none());
        assert!(event_subscriptions.event_registry.read().await.is_empty());
    }

    #[async_std::test]
    async fn test_dummy_event_implementation() {
        let dummy = DummyEvent;

        // Test Event trait implementation
        let any_ref = dummy.as_any();
        assert!(any_ref.downcast_ref::<DummyEvent>().is_some());

        // Test Debug implementation
        let debug_str = format!("{:?}", dummy);
        assert_eq!(debug_str, "DummyEvent");
    }
}
