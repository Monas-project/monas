use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};
use super::events::{Event, current_timestamp};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    pub content_id: String,
    pub managing_nodes: BTreeSet<String>,
}

pub fn add_manager(mut network: ContentNetwork, added_node_id: String) -> (ContentNetwork, Vec<Event>) {
    network.managing_nodes.insert(added_node_id.clone());
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id.clone(),
        added_node_id,
        managing_nodes: network.managing_nodes.iter().cloned().collect(),
        timestamp: current_timestamp(),
    };
    (network, vec![event])
}
