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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::current_timestamp;
    use monas_event_manager::event_bus::Event as EventBusTrait;
    use monas_event_manager::SerializableEvent;

    #[test]
    fn test_as_any_returns_self() {
        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: current_timestamp(),
        };

        let any_ref = event.as_any();

        // Should be able to downcast back to Event
        assert!(any_ref.is::<Event>());

        let downcasted = any_ref.downcast_ref::<Event>();
        assert!(downcasted.is_some());

        if let Some(Event::NodeCreated { node_id, .. }) = downcasted {
            assert_eq!(node_id, "node-1");
        } else {
            panic!("Expected NodeCreated event");
        }
    }

    #[test]
    fn test_as_any_with_different_event_types() {
        let events = vec![
            Event::NodeCreated {
                node_id: "node-1".to_string(),
                total_capacity: 1000,
                available_capacity: 1000,
                timestamp: current_timestamp(),
            },
            Event::ContentCreated {
                content_id: "cid-1".to_string(),
                creator_node_id: "node-1".to_string(),
                content_size: 100,
                member_nodes: vec!["node-1".to_string()],
                timestamp: current_timestamp(),
            },
            Event::ContentUpdated {
                content_id: "cid-1".to_string(),
                updated_node_id: "node-1".to_string(),
                timestamp: current_timestamp(),
            },
            Event::AssignmentDecided {
                assigning_node_id: "node-1".to_string(),
                assigned_node_id: "node-2".to_string(),
                content_id: "cid-1".to_string(),
                timestamp: current_timestamp(),
            },
            Event::ContentNetworkManagerAdded {
                content_id: "cid-1".to_string(),
                added_node_id: "node-2".to_string(),
                member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
                timestamp: current_timestamp(),
            },
        ];

        for event in events {
            let any_ref = event.as_any();
            assert!(any_ref.is::<Event>());
            assert!(any_ref.downcast_ref::<Event>().is_some());
        }
    }

    #[test]
    fn test_serializable_event_type_returns_correct_string() {
        // Test the SerializableEvent trait implementation
        let event_type = <Event as SerializableEvent>::event_type();
        assert_eq!(event_type, "StateNodeEvent");
    }

    #[test]
    fn test_serializable_event_type_is_static() {
        // event_type() should return a static string
        let type1 = <Event as SerializableEvent>::event_type();
        let type2 = <Event as SerializableEvent>::event_type();

        // Should be the same static reference
        assert_eq!(type1, type2);
        assert!(std::ptr::eq(type1.as_ptr(), type2.as_ptr()));
    }

    #[test]
    fn test_as_any_does_not_match_other_types() {
        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: current_timestamp(),
        };

        let any_ref = event.as_any();

        // Should not match other types
        assert!(!any_ref.is::<String>());
        assert!(!any_ref.is::<u64>());
        assert!(!any_ref.is::<Vec<u8>>());
    }
}

