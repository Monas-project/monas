use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateNode {
    id: String,
    address: String,
}

impl StateNode {
    pub fn new(id: String, address: String) -> Self {
        Self { id, address }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateNodes {
    nodes: Vec<StateNode>,
}

impl StateNodes {
    pub fn new(nodes: Vec<StateNode>) -> Self {
        Self { nodes }
    }

    pub fn add_node(&mut self, node: StateNode) {
        self.nodes.push(node);
    }

    pub fn remove_node(&mut self, node_id: &str) {
        self.nodes.retain(|node| node.id() != node_id);
    }

    pub fn nodes(&self) -> &[StateNode] {
        &self.nodes
    }
}
