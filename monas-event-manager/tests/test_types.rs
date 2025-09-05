use monas_event_manager::event_bus::Event;
use monas_event_manager::event_subscription::SerializableEvent;
use serde::{Deserialize, Serialize};
use std::any::Any;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationTestEvent {
    pub id: String,
    pub data: String,
    pub timestamp: u64,
}

impl Event for IntegrationTestEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SerializableEvent for IntegrationTestEvent {
    fn event_type() -> &'static str {
        "IntegrationTestEvent"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeAEvent {
    pub value: String,
}

impl Event for TypeAEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SerializableEvent for TypeAEvent {
    fn event_type() -> &'static str {
        "TypeAEvent"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeBEvent {
    pub id: String,
    pub text: String,
}

impl Event for TypeBEvent {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SerializableEvent for TypeBEvent {
    fn event_type() -> &'static str {
        "TypeBEvent"
    }
} 