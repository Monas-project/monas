use serde::{Deserialize, Serialize};
use std::any::Any;

/// Domain events for the state node system.
///
/// These events are used for:
/// - Local event bus communication (via monas-event-manager)
/// - Network event propagation (via Gossipsub)
/// - Persistence and replay
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// A new node has been created and registered.
    NodeCreated {
        node_id: String,
        total_capacity: u64,
        available_capacity: u64,
        timestamp: u64,
    },

    /// Content assignment has been decided.
    AssignmentDecided {
        assigning_node_id: String,
        assigned_node_id: String,
        content_id: String,
        timestamp: u64,
    },

    /// A node has been added to a content network as a manager.
    ContentNetworkManagerAdded {
        content_id: String,
        added_node_id: String,
        member_nodes: Vec<String>,
        timestamp: u64,
    },

    /// Content has been updated on a node.
    ContentUpdated {
        content_id: String,
        updated_node_id: String,
        timestamp: u64,
    },

    /// New content has been created.
    ContentCreated {
        /// The content ID (CID) of the created content.
        content_id: String,
        /// The node that created the content.
        creator_node_id: String,
        /// Size of the content in bytes.
        content_size: u64,
        /// Initial member nodes for the content network.
        member_nodes: Vec<String>,
        /// Creation timestamp.
        timestamp: u64,
    },

    /// Content sync has been requested.
    ContentSyncRequested {
        /// The content ID to sync.
        content_id: String,
        /// The node requesting the sync.
        requesting_node_id: String,
        /// The target node to sync from.
        source_node_id: String,
        /// Request timestamp.
        timestamp: u64,
    },
}

impl Event {
    /// Returns the event type as a string for routing and serialization.
    pub fn event_type(&self) -> &'static str {
        match self {
            Event::NodeCreated { .. } => "NodeCreated",
            Event::AssignmentDecided { .. } => "AssignmentDecided",
            Event::ContentNetworkManagerAdded { .. } => "ContentNetworkManagerAdded",
            Event::ContentUpdated { .. } => "ContentUpdated",
            Event::ContentCreated { .. } => "ContentCreated",
            Event::ContentSyncRequested { .. } => "ContentSyncRequested",
        }
    }

    /// Returns the content ID if this event is content-related.
    pub fn content_id(&self) -> Option<&str> {
        match self {
            Event::AssignmentDecided { content_id, .. } => Some(content_id),
            Event::ContentNetworkManagerAdded { content_id, .. } => Some(content_id),
            Event::ContentUpdated { content_id, .. } => Some(content_id),
            Event::ContentCreated { content_id, .. } => Some(content_id),
            Event::ContentSyncRequested { content_id, .. } => Some(content_id),
            Event::NodeCreated { .. } => None,
        }
    }

    /// Returns the timestamp of the event.
    pub fn timestamp(&self) -> u64 {
        match self {
            Event::NodeCreated { timestamp, .. } => *timestamp,
            Event::AssignmentDecided { timestamp, .. } => *timestamp,
            Event::ContentNetworkManagerAdded { timestamp, .. } => *timestamp,
            Event::ContentUpdated { timestamp, .. } => *timestamp,
            Event::ContentCreated { timestamp, .. } => *timestamp,
            Event::ContentSyncRequested { timestamp, .. } => *timestamp,
        }
    }
}

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

/// Get the current timestamp in seconds since UNIX epoch.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type() {
        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };
        assert_eq!(event.event_type(), "NodeCreated");

        let event = Event::ContentCreated {
            content_id: "cid-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12345,
        };
        assert_eq!(event.event_type(), "ContentCreated");
    }

    #[test]
    fn test_event_content_id() {
        let event = Event::ContentUpdated {
            content_id: "cid-1".to_string(),
            updated_node_id: "node-1".to_string(),
            timestamp: 12345,
        };
        assert_eq!(event.content_id(), Some("cid-1"));

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };
        assert_eq!(event.content_id(), None);
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::ContentCreated {
            content_id: "cid-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timestamp: 12345,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }
}
