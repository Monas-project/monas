use super::events::{current_timestamp, Event};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    pub content_id: String,
    pub member_nodes: BTreeSet<String>,
}

pub fn add_member_node(
    mut network: ContentNetwork,
    added_node_id: String,
) -> (ContentNetwork, Vec<Event>) {
    network.member_nodes.insert(added_node_id.clone());
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id.clone(),
        added_node_id,
        member_nodes: network.member_nodes.iter().cloned().collect(),
        timestamp: current_timestamp(),
    };
    (network, vec![event])
}

/// Remove a member node from a content network.
///
/// Returns the updated network and a ContentNetworkManagerRemoved event.
/// If the node is not a member, returns the network unchanged with no events.
pub fn remove_member_node(
    mut network: ContentNetwork,
    removed_node_id: String,
    reason: String,
) -> (ContentNetwork, Vec<Event>) {
    if !network.member_nodes.remove(&removed_node_id) {
        // Node was not a member, no change
        return (network, vec![]);
    }
    let event = Event::ContentNetworkManagerRemoved {
        content_id: network.content_id.clone(),
        removed_node_id,
        member_nodes: network.member_nodes.iter().cloned().collect(),
        reason,
        timestamp: current_timestamp(),
    };
    (network, vec![event])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_member_node_emits_event_and_updates_set() {
        let net = ContentNetwork {
            content_id: "cid-1".into(),
            member_nodes: BTreeSet::new(),
        };
        let (net, events) = add_member_node(net, "node-A".into());
        assert!(net.member_nodes.contains("node-A"));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::ContentNetworkManagerAdded {
                content_id,
                added_node_id,
                member_nodes,
                ..
            } => {
                assert_eq!(content_id, "cid-1");
                assert_eq!(added_node_id, "node-A");
                assert!(member_nodes.contains(&"node-A".to_string()));
            }
            _ => panic!("expected ContentNetworkManagerAdded"),
        }
    }

    #[test]
    fn remove_member_node_emits_event_and_updates_set() {
        let mut members = BTreeSet::new();
        members.insert("node-A".to_string());
        members.insert("node-B".to_string());
        let net = ContentNetwork {
            content_id: "cid-1".into(),
            member_nodes: members,
        };
        let (net, events) = remove_member_node(net, "node-A".into(), "low_capacity".into());
        assert!(!net.member_nodes.contains("node-A"));
        assert!(net.member_nodes.contains("node-B"));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::ContentNetworkManagerRemoved {
                content_id,
                removed_node_id,
                member_nodes,
                reason,
                ..
            } => {
                assert_eq!(content_id, "cid-1");
                assert_eq!(removed_node_id, "node-A");
                assert!(!member_nodes.contains(&"node-A".to_string()));
                assert!(member_nodes.contains(&"node-B".to_string()));
                assert_eq!(reason, "low_capacity");
            }
            _ => panic!("expected ContentNetworkManagerRemoved"),
        }
    }

    #[test]
    fn remove_member_node_no_op_if_not_member() {
        let net = ContentNetwork {
            content_id: "cid-1".into(),
            member_nodes: BTreeSet::new(),
        };
        let (net, events) = remove_member_node(net, "node-X".into(), "test".into());
        assert!(events.is_empty());
        assert!(net.member_nodes.is_empty());
    }
}
