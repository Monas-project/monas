use crate::event_bus::event_bus::Event;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

pub type SubscribeFn = Arc<dyn Fn(&dyn Event) + Send + Sync>;
pub type Subscribers = Vec<Subscriber>;

pub struct EventSubscriptions {
    subscriptions: HashMap<TypeId, Subscribers>,
}

/// イベントと購読ハンドラのマッピング管理
impl EventSubscriptions {
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
        }
    }

    pub fn get_subscriptions(&self) -> &HashMap<TypeId, Subscribers> {
        &self.subscriptions
    }

    /// 指定した TypeId に対応する Subscribers を返す
    pub fn lookup_subscribers(&self, lookup: &TypeId) -> Option<&Subscribers> {
        self.subscriptions.get(lookup)
    }

    /// 指定した TypeId に対応する Subscribersを渡す
    pub fn add_subscribers(&mut self, type_id: TypeId, subscribers: Subscribers) {
        self.subscriptions.insert(type_id, subscribers);
    }
}

// Subscriber の定義
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

/// 型特有のハンドラを生成するユーティリティ関数
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

#[cfg(test)]
mod event_subscription_tests {
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::event_subscription::event_subscription::{make_subscriber, EventSubscriptions};

    #[test]
    fn dispatch_subscriptions_test() {
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
                    *ev_message1 = format!("fire1: {}", test_event.message.to_string())
                }),
                make_subscriber(move |test_event: &TestMessageEvent| {
                    let mut ev_message2 = shared_str2.lock().unwrap();
                    *ev_message2 = format!("fire2: {}", test_event.message.to_string())
                }),
            ],
        );

        subscriptions.dispatch(&event1);

        assert_eq!(*shared_str_clone1.lock().unwrap(), "fire1: test");
        assert_eq!(*shared_str_clone2.lock().unwrap(), "fire2: test");
    }

    #[test]
    fn dispatch_all_events_test() {
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
                *ev_message1 = format!("fire1: {}", test_event.message.to_string())
            })],
        );

        subscriptions.add_subscribers(
            TypeId::of::<TestMessageEvent2>(),
            vec![make_subscriber(move |test_event: &TestMessageEvent2| {
                let mut ev_message2 = shared_str2.lock().unwrap();
                *ev_message2 = format!("fire1: {}", test_event.message.to_string())
            })],
        );

        subscriptions.dispatch(&event1);

        assert_eq!(*shared_str_clone1.lock().unwrap(), "fire1: test 1");

        subscriptions.dispatch(&event2);
        assert_eq!(*shared_str_clone2.lock().unwrap(), "fire1: test 2");
    }
}
