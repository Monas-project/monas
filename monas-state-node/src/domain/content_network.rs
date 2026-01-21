use super::events::{current_timestamp, Event};
use super::value_objects::{ContentId, NodeId, ValueError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Content Network represents the set of nodes that store and manage a specific content.
///
/// Invariants:
/// - Must have at least one member node
/// - Each member node must be valid (enforced by NodeId)
/// - Content ID must be valid (enforced by ContentId)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    content_id: ContentId,
    member_nodes: BTreeSet<NodeId>,
}

impl ContentNetwork {
    /// Create a new content network with at least one member node.
    pub fn new(content_id: ContentId, initial_member: NodeId) -> Self {
        let mut member_nodes = BTreeSet::new();
        member_nodes.insert(initial_member);
        Self {
            content_id,
            member_nodes,
        }
    }

    /// Get the content ID.
    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// Get member nodes as an iterator.
    pub fn member_nodes(&self) -> impl Iterator<Item = &NodeId> + '_ {
        self.member_nodes.iter()
    }

    /// Get member nodes as a vector of strings (for compatibility).
    pub fn member_nodes_as_strings(&self) -> Vec<String> {
        self.member_nodes
            .iter()
            .map(|n| n.as_str().to_string())
            .collect()
    }

    /// Check if a node is a member.
    pub fn has_member(&self, node_id: &NodeId) -> bool {
        self.member_nodes.contains(node_id)
    }

    /// Get the number of member nodes.
    pub fn member_count(&self) -> usize {
        self.member_nodes.len()
    }

    /// Internal method to add a member (used by domain functions).
    pub(crate) fn insert_member(&mut self, node_id: NodeId) -> bool {
        self.member_nodes.insert(node_id)
    }

    /// Internal method to remove a member (used by domain functions).
    pub(crate) fn remove_member(&mut self, node_id: &NodeId) -> bool {
        self.member_nodes.remove(node_id)
    }

    /// Check if a node (by string ID) is a member (convenience method for backward compatibility).
    pub fn has_member_str(&self, node_id: &str) -> bool {
        self.member_nodes.iter().any(|n| n.as_str() == node_id)
    }

    /// Create from a list of member nodes (convenience constructor for backward compatibility).
    ///
    /// Returns an error if the member list is empty or contains invalid IDs.
    pub fn from_strings(content_id: String, member_nodes: Vec<String>) -> Result<Self, ValueError> {
        if member_nodes.is_empty() {
            return Err(ValueError::EmptyMemberNodes);
        }

        let content_id = ContentId::new(content_id)?;
        let first_member = NodeId::new(member_nodes[0].clone())?;
        let mut network = Self::new(content_id, first_member);

        for member in &member_nodes[1..] {
            network.insert_member(NodeId::new(member.clone())?);
        }

        Ok(network)
    }
}

/// Add a member node to a content network (pure function for event sourcing).
///
/// Returns the updated network and a ContentNetworkManagerAdded event.
pub fn add_member_node(
    mut network: ContentNetwork,
    added_node_id: NodeId,
) -> (ContentNetwork, Vec<Event>) {
    network.insert_member(added_node_id.clone());
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id().as_str().to_string(),
        added_node_id: added_node_id.as_str().to_string(),
        member_nodes: network.member_nodes_as_strings(),
        timestamp: current_timestamp(),
    };
    (network, vec![event])
}

/// Remove a member node from a content network (pure function for event sourcing).
///
/// Returns the updated network and a ContentNetworkManagerRemoved event.
/// If the node is not a member, returns the network unchanged with no events.
pub fn remove_member_node(
    mut network: ContentNetwork,
    removed_node_id: NodeId,
    reason: String,
) -> (ContentNetwork, Vec<Event>) {
    if !network.remove_member(&removed_node_id) {
        // Node was not a member, no change
        return (network, vec![]);
    }
    let event = Event::ContentNetworkManagerRemoved {
        content_id: network.content_id().as_str().to_string(),
        removed_node_id: removed_node_id.as_str().to_string(),
        member_nodes: network.member_nodes_as_strings(),
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
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let initial_node = NodeId::new("node-initial".to_string()).unwrap();
        let net = ContentNetwork::new(content_id, initial_node.clone());

        let node_a = NodeId::new("node-A".to_string()).unwrap();
        let (net, events) = add_member_node(net, node_a.clone());

        assert!(net.has_member(&node_a));
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
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let node_a = NodeId::new("node-A".to_string()).unwrap();
        let node_b = NodeId::new("node-B".to_string()).unwrap();

        let mut net = ContentNetwork::new(content_id, node_a.clone());
        net.insert_member(node_b.clone());

        let (net, events) = remove_member_node(net, node_a.clone(), "low_capacity".into());

        assert!(!net.has_member(&node_a));
        assert!(net.has_member(&node_b));
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
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let initial_node = NodeId::new("node-initial".to_string()).unwrap();
        let net = ContentNetwork::new(content_id, initial_node);

        let node_x = NodeId::new("node-X".to_string()).unwrap();
        let (net, events) = remove_member_node(net, node_x.clone(), "test".into());

        assert!(events.is_empty());
        assert!(!net.has_member(&node_x));
    }
}
