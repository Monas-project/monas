//! Event adapters for integrating domain events with monas-event-manager.
//!
//! This module provides trait implementations that bridge the domain layer's
//! Event type with the external monas-event-manager crate, keeping the domain
//! layer free from external dependencies.

use crate::domain::events::Event;
use std::any::Any;

// Implement monas_event_manager::event_bus::Event trait for integration
impl monas_event_manager::event_bus::Event for Event {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Implement SerializableEvent for monas-event-manager compatibility
impl monas_event_manager::SerializableEvent for Event {
    fn event_type() -> &'static str {
        "StateNodeEvent"
    }
}

