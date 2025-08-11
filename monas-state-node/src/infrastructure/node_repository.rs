use crate::application_service::state_node_service::NodeRegistry;
use crate::domain::state_node::NodeSnapshot;
use std::collections::HashMap;

#[derive(Default)]
pub struct NodeRegistryImpl(pub HashMap<String, NodeSnapshot>);

impl NodeRegistry for NodeRegistryImpl {
    fn upsert_node(&mut self, node: &NodeSnapshot) {
        self.0.insert(node.node_id.clone(), node.clone());
    }

    fn get_available_capacity(&self, node_id: &str) -> Option<u64> {
        self.0.get(node_id).map(|n| n.available_capacity)
    }
}


