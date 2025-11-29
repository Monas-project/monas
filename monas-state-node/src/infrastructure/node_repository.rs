//! In-memory node registry implementation.
//!
//! This module provides a simple in-memory implementation for node registry
//! management. For production use, see the sled-based implementation in
//! `persistence/sled_node_registry.rs`.

use crate::domain::state_node::NodeSnapshot;
use std::collections::HashMap;

/// In-memory node registry for testing and simple use cases.
#[derive(Default)]
pub struct NodeRegistryImpl(pub HashMap<String, NodeSnapshot>);

impl NodeRegistryImpl {
    /// Insert or update a node in the registry.
    pub fn upsert_node(&mut self, node: &NodeSnapshot) {
        self.0.insert(node.node_id.clone(), node.clone());
    }

    /// Get the available capacity for a node.
    pub fn get_available_capacity(&self, node_id: &str) -> Option<u64> {
        self.0.get(node_id).map(|n| n.available_capacity)
    }

    /// List all node IDs in the registry.
    pub fn list_nodes(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_get_capacity() {
        let mut repo = NodeRegistryImpl::default();
        let snap = NodeSnapshot {
            node_id: "node-A".into(),
            total_capacity: 1000,
            available_capacity: 800,
        };
        repo.upsert_node(&snap);
        assert_eq!(repo.get_available_capacity("node-A"), Some(800));
        assert_eq!(repo.get_available_capacity("node-X"), None);
    }
}
