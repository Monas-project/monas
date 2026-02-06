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
/// - NodeIds are derived from public keys (cryptographic binding)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    content_id: ContentId,
    /// Member nodes (NodeIds are derived from public keys)
    member_nodes: BTreeSet<NodeId>,
}

impl ContentNetwork {
    /// Create a new content network from a public key.
    ///
    /// The NodeId is derived from the public key hash.
    pub fn from_public_key(
        content_id: ContentId,
        initial_public_key: Vec<u8>,
    ) -> Result<Self, ValueError> {
        let initial_member = NodeId::from_public_key(&initial_public_key)?;
        let mut member_nodes = BTreeSet::new();
        member_nodes.insert(initial_member);

        Ok(Self {
            content_id,
            member_nodes,
        })
    }

    /// Create a new content network with a pre-computed NodeId.
    pub fn new(content_id: ContentId, initial_member: NodeId) -> Result<Self, ValueError> {
        let mut member_nodes = BTreeSet::new();
        member_nodes.insert(initial_member);

        Ok(Self {
            content_id,
            member_nodes,
        })
    }

    /// Get the content ID.
    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// Get member nodes as an iterator.
    pub fn member_nodes(&self) -> impl Iterator<Item = &NodeId> + '_ {
        self.member_nodes.iter()
    }

    /// Get member nodes as a vector of strings.
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

    /// Check if a node is a member using string node_id.
    pub fn has_member_str(&self, node_id: &str) -> bool {
        self.member_nodes.iter().any(|n| n.as_str() == node_id)
    }

    /// Get the number of member nodes.
    pub fn member_count(&self) -> usize {
        self.member_nodes.len()
    }

    /// Add a member node from its public key.
    ///
    /// The NodeId is derived from the public key hash.
    pub fn add_member_from_public_key(&mut self, public_key: Vec<u8>) -> Result<bool, ValueError> {
        let node_id = NodeId::from_public_key(&public_key)?;
        Ok(self.member_nodes.insert(node_id))
    }

    /// Add a member node directly.
    pub fn add_member(&mut self, node_id: NodeId) -> bool {
        self.member_nodes.insert(node_id)
    }

    /// Internal method to remove a member (used by domain functions).
    pub(crate) fn remove_member(&mut self, node_id: &NodeId) -> bool {
        self.member_nodes.remove(node_id)
    }
}

/// Add a member node to a content network (pure function for event sourcing).
///
/// Returns the updated network and a ContentNetworkManagerAdded event.
pub fn add_member_node(
    mut network: ContentNetwork,
    node_id: NodeId,
) -> Result<(ContentNetwork, Vec<Event>), ValueError> {
    network.add_member(node_id.clone());
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id().as_str().to_string(),
        added_node_id: node_id.as_str().to_string(),
        member_nodes: network.member_nodes_as_strings(),
        timestamp: current_timestamp(),
    };
    Ok((network, vec![event]))
}

/// Add a member node to a content network (pure function for event sourcing).
///
/// Returns the updated network and a ContentNetworkManagerAdded event.
/// The NodeId is derived from the public key.
pub fn add_member_node_from_public_key(
    mut network: ContentNetwork,
    public_key: Vec<u8>,
) -> Result<(ContentNetwork, Vec<Event>), ValueError> {
    let added_node_id = NodeId::from_public_key(&public_key)?;
    network.add_member_from_public_key(public_key)?;
    let event = Event::ContentNetworkManagerAdded {
        content_id: network.content_id().as_str().to_string(),
        added_node_id: added_node_id.as_str().to_string(),
        member_nodes: network.member_nodes_as_strings(),
        timestamp: current_timestamp(),
    };
    Ok((network, vec![event]))
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
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    fn generate_test_keypair() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (signing_key, public_key)
    }

    #[test]
    fn add_member_node_emits_event_and_updates_set() {
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let (_, public_key) = generate_test_keypair();
        let initial_node = NodeId::from_public_key(&public_key).unwrap();
        let net = ContentNetwork::new(content_id, initial_node.clone()).unwrap();

        let (_, key_a) = generate_test_keypair();
        let node_a = NodeId::from_public_key(&key_a).unwrap();
        let (net, events) = add_member_node(net, node_a.clone()).unwrap();

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
                assert_eq!(added_node_id, node_a.as_str());
                assert!(member_nodes.contains(&node_a.as_str().to_string()));
            }
            _ => panic!("expected ContentNetworkManagerAdded"),
        }
    }

    #[test]
    fn remove_member_node_emits_event_and_updates_set() {
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let (_, public_key_a) = generate_test_keypair();
        let (_, public_key_b) = generate_test_keypair();
        let node_a = NodeId::from_public_key(&public_key_a).unwrap();
        let node_b = NodeId::from_public_key(&public_key_b).unwrap();

        let mut net = ContentNetwork::new(content_id, node_a.clone()).unwrap();
        net.add_member(node_b.clone());

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
                assert_eq!(removed_node_id, node_a.as_str());
                assert!(!member_nodes.contains(&node_a.as_str().to_string()));
                assert!(member_nodes.contains(&node_b.as_str().to_string()));
                assert_eq!(reason, "low_capacity");
            }
            _ => panic!("expected ContentNetworkManagerRemoved"),
        }
    }

    #[test]
    fn remove_member_node_no_op_if_not_member() {
        let content_id = ContentId::new("cid-1".to_string()).unwrap();
        let (_, public_key) = generate_test_keypair();
        let initial_node = NodeId::from_public_key(&public_key).unwrap();
        let net = ContentNetwork::new(content_id, initial_node).unwrap();

        let (_, key_x) = generate_test_keypair();
        let node_x = NodeId::from_public_key(&key_x).unwrap();
        let (net, events) = remove_member_node(net, node_x.clone(), "test".into());

        assert!(events.is_empty());
        assert!(!net.has_member(&node_x));
    }

    #[test]
    fn test_create_content_network_with_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let (_, public_key) = generate_test_keypair();
        let node_id = NodeId::from_public_key(&public_key).unwrap();

        let network = ContentNetwork::new(content_id.clone(), node_id.clone()).unwrap();

        assert_eq!(network.content_id(), &content_id);
        assert!(network.has_member(&node_id));
    }

    #[test]
    fn test_invalid_public_key_format() {
        // Test that NodeId::from_public_key validates key format
        let invalid_key = vec![0u8; 32]; // Wrong length (should be 65 for uncompressed P-256)

        let result = NodeId::from_public_key(&invalid_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValueError::InvalidPublicKeyFormat(_)
        ));
    }

    #[test]
    fn test_add_member_from_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let (_, key1) = generate_test_keypair();
        let node1 = NodeId::from_public_key(&key1).unwrap();

        let mut network = ContentNetwork::new(content_id, node1).unwrap();

        let (_, key2) = generate_test_keypair();
        let result = network.add_member_from_public_key(key2.clone());
        assert!(result.is_ok());
        assert!(result.unwrap());

        let node2 = NodeId::from_public_key(&key2).unwrap();
        assert!(network.has_member(&node2));
    }

    #[test]
    fn test_remove_member() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let (_, key1) = generate_test_keypair();
        let (_, key2) = generate_test_keypair();
        let node1 = NodeId::from_public_key(&key1).unwrap();
        let node2 = NodeId::from_public_key(&key2).unwrap();

        let mut network = ContentNetwork::new(content_id, node1.clone()).unwrap();
        network.add_member(node2.clone());

        let removed = network.remove_member(&node2);

        assert!(removed);
        assert!(!network.has_member(&node2));
        assert!(network.has_member(&node1));
    }
}
