use crate::event_subscription::event_subscription::EventSubscriptions;
use std::any::Any;

// publisher側はこの型を継承してね
pub trait Event: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> Event for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// イベント処理
pub struct EventBus {
    event_subscriptions: EventSubscriptions,
}

impl EventBus {
    pub fn initialize(event_subscriptions: EventSubscriptions) -> Self {
        Self {
            event_subscriptions: event_subscriptions,
        }
    }

    fn publish(&self, event: &dyn Event) -> Option<()> {
        let type_id = event.as_any().type_id();
        if let Some(subscribers) = self.event_subscriptions.get_subscriptions().get(&type_id) {
            for subscriber in subscribers {
                subscriber.subscriber()(event);
            }
            Some(())
        } else {
            eprintln!("No subscribers found for event type: {:?}", type_id);
            None
        }
    }
}
