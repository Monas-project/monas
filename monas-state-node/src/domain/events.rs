use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StateNodeEvent {
    NodeCreated {
        node_id: String,
        total_capacity: u64,
        timestamp: u64,
    },
    RegisteredToUniversal {
        node_id: String,
        timestamp: u64,
    },
    JoinedContentNetwork {
        node_id: String,
        content_id: String,
        timestamp: u64,
    },
    NodeAssigned {
        assigning_node_id: String,
        assigned_node_id: String,
        content_network: String,
        timestamp: u64,
    },
    StorageAllocated {
        node_id: String,
        amount: u64,
        remaining_capacity: u64,
        timestamp: u64,
    },
    NodeSynchronized {
        node_id: String,
        timestamp: u64,
    },
    LeftNetwork {
        node_id: String,
        timestamp: u64,
    },
}
