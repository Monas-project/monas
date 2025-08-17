use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    NodeCreated {
        node_id: String,
        total_capacity: u64,
        available_capacity: u64,
        timestamp: u64,
    },
    AssignmentDecided {
        assigning_node_id: String,
        assigned_node_id: String,
        content_id: String,
        timestamp: u64,
    },
    ContentNetworkManagerAdded {
        content_id: String,
        added_node_id: String,
        member_nodes: Vec<String>,
        timestamp: u64,
    },
}

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
