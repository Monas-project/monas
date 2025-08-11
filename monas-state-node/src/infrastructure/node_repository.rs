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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_service::state_node_service::NodeRegistry;

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
