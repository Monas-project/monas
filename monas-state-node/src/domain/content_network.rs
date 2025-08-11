use super::events::{current_timestamp, Event};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    pub content_id: String,
    pub managing_nodes: BTreeSet<String>,
}

pub fn add_manager(
    mut network: ContentNetwork,
    added_node_id: String,
) -> (ContentNetwork, Vec<Event>) {
    network.managing_nodes.insert(added_node_id.clone());
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id.clone(),
        added_node_id,
        managing_nodes: network.managing_nodes.iter().cloned().collect(),
        timestamp: current_timestamp(),
    };
    (network, vec![event])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_manager_emits_event_and_updates_set() {
        let net = ContentNetwork {
            content_id: "cid-1".into(),
            managing_nodes: BTreeSet::new(),
        };
        let (net, events) = add_manager(net, "node-A".into());
        assert!(net.managing_nodes.contains("node-A"));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::ContentNetworkManagerAdded {
                content_id,
                added_node_id,
                managing_nodes,
                ..
            } => {
                assert_eq!(content_id, "cid-1");
                assert_eq!(added_node_id, "node-A");
                assert!(managing_nodes.contains(&"node-A".to_string()));
            }
            _ => panic!("expected ContentNetworkManagerAdded"),
        }
    }
}
