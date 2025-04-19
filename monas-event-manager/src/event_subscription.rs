use crate::event_bus::Event;
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

pub type SubscribeFn = Arc<dyn Fn(&dyn Event) + Send + Sync>;
pub type Subscribers = Vec<Subscriber>;

pub struct EventSubscriptions {
    pub(crate) subscriptions: HashMap<TypeId, Subscribers>,
}

/// Manages the mapping between events and their subscriber handlers
impl EventSubscriptions {
    /// Returns the Subscribers associated with the given TypeId
    pub fn get_subscribers(&self, lookup: &TypeId) -> Option<&Subscribers> {
        self.subscriptions.get(lookup)
    }

    /// Registers the Subscribers associated with the given TypeId
    pub fn add_subscribers(&mut self, type_id: TypeId, subscribers: Subscribers) {
        self.subscriptions.insert(type_id, subscribers);
    }
}

// Definition of a Subscriber
pub struct Subscriber {
    subscriber: Option<SubscribeFn>,
}

impl Subscriber {
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(&dyn Event) + Send + Sync + 'static,
    {
        Self {
            subscriber: Some(Arc::new(handler)),
        }
    }

    pub fn subscriber(&self) -> SubscribeFn {
        self.subscriber
            .as_ref()
            .expect("No subscriber function found")
            .clone()
    }
}

/// Utility function to create a type-specific handler
pub fn make_subscriber<T, F>(handler: F) -> Subscriber
where
    T: Event + 'static,
    F: Fn(&T) + Send + Sync + 'static,
{
    let wrapped = move |event: &dyn Event| {
        if let Some(specific) = event.as_any().downcast_ref::<T>() {
            handler(specific);
        } else {
            eprintln!("Received event of unexpected type");
        }
    };

    Subscriber::new(wrapped)
}

// TODO: test
