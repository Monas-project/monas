use super::events::{current_timestamp, Event};
use super::value_objects::{ContentId, NodeId, ValueError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Content Network represents the set of nodes that store and manage a specific content.
///
/// Invariants:
/// - Must have at least one member node
/// - Each member node must be valid (enforced by NodeId)
/// - Content ID must be valid (enforced by ContentId)
/// - Each member node has an associated public key (P-256)
/// - Public keys and member nodes are always in sync (1:1 mapping)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    content_id: ContentId,
    /// Member nodes with their public keys (P-256, SEC1 uncompressed format: 65 bytes)
    /// Maps NodeId -> Public Key
    member_nodes: BTreeMap<NodeId, Vec<u8>>,
}

impl ContentNetwork {
    /// Create a new content network with at least one member node and its public key.
    pub fn new(
        content_id: ContentId,
        initial_member: NodeId,
        initial_public_key: Vec<u8>,
    ) -> Result<Self, ValueError> {
        // Validate public key format (P-256 uncompressed: 65 bytes)
        if initial_public_key.len() != 65 {
            return Err(ValueError::InvalidPublicKeyFormat(format!(
                "Expected 65 bytes (P-256 uncompressed), got {}",
                initial_public_key.len()
            )));
        }

        // Validate public key is valid P-256 point
        if let Err(e) = p256::PublicKey::from_sec1_bytes(&initial_public_key) {
            return Err(ValueError::InvalidPublicKeyFormat(e.to_string()));
        }

        let mut member_nodes = BTreeMap::new();
        member_nodes.insert(initial_member, initial_public_key);

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
        self.member_nodes.keys()
    }

    /// Get member nodes as a vector of strings (for compatibility).
    pub fn member_nodes_as_strings(&self) -> Vec<String> {
        self.member_nodes
            .keys()
            .map(|n| n.as_str().to_string())
            .collect()
    }

    /// Check if a node is a member.
    pub fn has_member(&self, node_id: &NodeId) -> bool {
        self.member_nodes.contains_key(node_id)
    }

    /// Get the number of member nodes.
    pub fn member_count(&self) -> usize {
        self.member_nodes.len()
    }

    /// Get public key for a node
    pub fn get_public_key(&self, node_id: &NodeId) -> Option<&[u8]> {
        self.member_nodes.get(node_id).map(|v| v.as_slice())
    }

    /// Add a member node with its public key
    pub fn add_member_with_public_key(
        &mut self,
        node_id: NodeId,
        public_key: Vec<u8>,
    ) -> Result<bool, ValueError> {
        // Validate public key format
        if public_key.len() != 65 {
            return Err(ValueError::InvalidPublicKeyFormat(format!(
                "Expected 65 bytes (P-256 uncompressed), got {}",
                public_key.len()
            )));
        }

        // Validate public key is valid P-256 point
        if let Err(e) = p256::PublicKey::from_sec1_bytes(&public_key) {
            return Err(ValueError::InvalidPublicKeyFormat(e.to_string()));
        }

        let was_new = self.member_nodes.insert(node_id, public_key).is_none();
        Ok(was_new)
    }

    /// Update public key for an existing member (for key rotation)
    pub fn update_public_key(
        &mut self,
        node_id: &NodeId,
        new_public_key: Vec<u8>,
    ) -> Result<(), ValueError> {
        if !self.member_nodes.contains_key(node_id) {
            return Err(ValueError::NodeNotMember);
        }

        // Validate public key format
        if new_public_key.len() != 65 {
            return Err(ValueError::InvalidPublicKeyFormat(format!(
                "Expected 65 bytes (P-256 uncompressed), got {}",
                new_public_key.len()
            )));
        }

        // Validate public key is valid P-256 point
        if let Err(e) = p256::PublicKey::from_sec1_bytes(&new_public_key) {
            return Err(ValueError::InvalidPublicKeyFormat(e.to_string()));
        }

        self.member_nodes.insert(node_id.clone(), new_public_key);
        Ok(())
    }


    /// Internal method to remove a member (used by domain functions).
    pub(crate) fn remove_member(&mut self, node_id: &NodeId) -> bool {
        self.member_nodes.remove(node_id).is_some()
    }

    /// Check if a node (by string ID) is a member (convenience method for backward compatibility).
    pub fn has_member_str(&self, node_id: &str) -> bool {
        self.member_nodes.keys().any(|n| n.as_str() == node_id)
    }
}

/// Add a member node to a content network (pure function for event sourcing).
///
/// Returns the updated network and a ContentNetworkManagerAdded event.
pub fn add_member_node(
    mut network: ContentNetwork,
    added_node_id: NodeId,
    public_key: Vec<u8>,
) -> Result<(ContentNetwork, Vec<Event>), ValueError> {
    network.add_member_with_public_key(added_node_id.clone(), public_key)?;
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
        let initial_node = NodeId::new("node-initial".to_string()).unwrap();
        let (_, public_key) = generate_test_keypair();
        let net = ContentNetwork::new(content_id, initial_node.clone(), public_key).unwrap();

        let node_a = NodeId::new("node-A".to_string()).unwrap();
        let (_, key_a) = generate_test_keypair();
        let (net, events) = add_member_node(net, node_a.clone(), key_a).unwrap();

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
        let (_, public_key_a) = generate_test_keypair();
        let (_, public_key_b) = generate_test_keypair();

        let mut net = ContentNetwork::new(content_id, node_a.clone(), public_key_a).unwrap();
        net.add_member_with_public_key(node_b.clone(), public_key_b).unwrap();

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
        let (_, public_key) = generate_test_keypair();
        let net = ContentNetwork::new(content_id, initial_node, public_key).unwrap();

        let node_x = NodeId::new("node-X".to_string()).unwrap();
        let (net, events) = remove_member_node(net, node_x.clone(), "test".into());

        assert!(events.is_empty());
        assert!(!net.has_member(&node_x));
    }

    #[test]
    fn test_create_content_network_with_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let node_id = NodeId::new("node-1".to_string()).unwrap();
        let (_, public_key) = generate_test_keypair();

        let network = ContentNetwork::new(content_id.clone(), node_id.clone(), public_key.clone()).unwrap();

        assert_eq!(network.content_id(), &content_id);
        assert!(network.has_member(&node_id));
        assert_eq!(network.get_public_key(&node_id), Some(public_key.as_slice()));
    }

    #[test]
    fn test_invalid_public_key_format() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let node_id = NodeId::new("node-1".to_string()).unwrap();
        let invalid_key = vec![0u8; 32]; // Wrong length

        let result = ContentNetwork::new(content_id, node_id, invalid_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValueError::InvalidPublicKeyFormat(_)));
    }

    #[test]
    fn test_add_member_with_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let node1 = NodeId::new("node-1".to_string()).unwrap();
        let (_, key1) = generate_test_keypair();

        let mut network = ContentNetwork::new(content_id, node1, key1).unwrap();

        let node2 = NodeId::new("node-2".to_string()).unwrap();
        let (_, key2) = generate_test_keypair();

        let result = network.add_member_with_public_key(node2.clone(), key2.clone());
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(network.get_public_key(&node2), Some(key2.as_slice()));
    }

    #[test]
    fn test_update_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let node_id = NodeId::new("node-1".to_string()).unwrap();
        let (_, old_key) = generate_test_keypair();

        let mut network = ContentNetwork::new(content_id, node_id.clone(), old_key.clone()).unwrap();

        let (_, new_key) = generate_test_keypair();
        network.update_public_key(&node_id, new_key.clone()).unwrap();

        assert_eq!(network.get_public_key(&node_id), Some(new_key.as_slice()));
        assert_ne!(network.get_public_key(&node_id), Some(old_key.as_slice()));
    }

    #[test]
    fn test_remove_member_removes_public_key() {
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let node1 = NodeId::new("node-1".to_string()).unwrap();
        let node2 = NodeId::new("node-2".to_string()).unwrap();
        let (_, key1) = generate_test_keypair();
        let (_, key2) = generate_test_keypair();

        let mut network = ContentNetwork::new(content_id, node1, key1).unwrap();
        network.add_member_with_public_key(node2.clone(), key2).unwrap();

        network.remove_member(&node2);

        assert!(!network.has_member(&node2));
        assert_eq!(network.get_public_key(&node2), None);
    }
}
