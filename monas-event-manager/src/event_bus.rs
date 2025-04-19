use crate::event_subscription::EventSubscriptions;
use std::any::Any;

// Publishers should implement this trait
pub trait Event: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> Event for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Event processor: TODO Consider renaming
pub struct EventBus {
    event_subscriptions: EventSubscriptions,
}

impl EventBus {
    fn publish(&self, event: &dyn Event) -> Option<()> {
        let type_id = event.as_any().type_id();
        if let Some(subscribers) = self.event_subscriptions.get_subscribers(&type_id) {
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

#[cfg(test)]
mod event_bus_tests {
    use crate::event_bus::EventBus;
    use crate::event_subscription::{make_subscriber, EventSubscriptions};
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn publish_subscriptions_test() {
        struct TestMessageEvent {
            message: &'static str,
        }

        let shared_str1 = Arc::new(Mutex::new(String::from("")));
        let shared_str_clone1 = Arc::clone(&shared_str1);

        let shared_str2 = Arc::new(Mutex::new(String::from("")));
        let shared_str_clone2 = Arc::clone(&shared_str2);

        let mut subscriptions = EventSubscriptions {
            subscriptions: HashMap::new(),
        };

        let event1 = TestMessageEvent { message: "test" };

        subscriptions.add_subscribers(
            TypeId::of::<TestMessageEvent>(),
            vec![
                make_subscriber(move |test_event: &TestMessageEvent| {
                    let mut ev_message1 = shared_str1.lock().unwrap();
                    *ev_message1 = format!("fire1: {}", test_event.message)
                }),
                make_subscriber(move |test_event: &TestMessageEvent| {
                    let mut ev_message2 = shared_str2.lock().unwrap();
                    *ev_message2 = format!("fire2: {}", test_event.message)
                }),
            ],
        );

        let publisher = EventBus {
            event_subscriptions: subscriptions,
        };

        publisher.publish(&event1);

        assert_eq!(*shared_str_clone1.lock().unwrap(), "fire1: test");
        assert_eq!(*shared_str_clone2.lock().unwrap(), "fire2: test");
    }

    #[test]
    fn publish_all_event_test() {
        struct TestMessageEvent1 {
            message: &'static str,
        }

        struct TestMessageEvent2 {
            message: &'static str,
        }

        let shared_str1 = Arc::new(Mutex::new(String::from("")));
        let shared_str_clone1 = Arc::clone(&shared_str1);

        let shared_str2 = Arc::new(Mutex::new(String::from("")));
        let shared_str_clone2 = Arc::clone(&shared_str2);

        let mut subscriptions = EventSubscriptions {
            subscriptions: HashMap::new(),
        };

        let event1 = TestMessageEvent1 { message: "test 1" };

        let event2 = TestMessageEvent2 { message: "test 2" };

        subscriptions.add_subscribers(
            TypeId::of::<TestMessageEvent1>(),
            vec![make_subscriber(move |test_event: &TestMessageEvent1| {
                let mut ev_message1 = shared_str1.lock().unwrap();
                *ev_message1 = format!("fire1: {}", test_event.message)
            })],
        );

        subscriptions.add_subscribers(
            TypeId::of::<TestMessageEvent2>(),
            vec![make_subscriber(move |test_event: &TestMessageEvent2| {
                let mut ev_message2 = shared_str2.lock().unwrap();
                *ev_message2 = format!("fire1: {}", test_event.message)
            })],
        );

        let publisher = EventBus {
            event_subscriptions: subscriptions,
        };

        let result1 = publisher.publish(&event1);

        assert_eq!(*shared_str_clone1.lock().unwrap(), "fire1: test 1");

        let result2 = publisher.publish(&event2);
        assert_eq!(*shared_str_clone2.lock().unwrap(), "fire1: test 2");

        assert_eq!(result1, Some(()));
        assert_eq!(result2, Some(()));
    }

    #[test]
    fn publish_failure_test() {
        struct TestMessageEvent1 {
            message: &'static str,
        }

        struct TestMessageEvent2;

        let mut subscriptions = EventSubscriptions {
            subscriptions: HashMap::new(),
        };

        let empty_event = TestMessageEvent2;

        subscriptions.add_subscribers(
            TypeId::of::<TestMessageEvent1>(),
            vec![make_subscriber(move |test_event: &TestMessageEvent1| {
                println!("empty: {}", test_event.message);
            })],
        );

        let publisher = EventBus {
            event_subscriptions: subscriptions,
        };

        let result = publisher.publish(&empty_event);

        assert!(result.is_none());
    }
}
