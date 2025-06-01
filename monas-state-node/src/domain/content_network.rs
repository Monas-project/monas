use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentNetworkError {
    NodeAlreadyExists,
    NodeNotFound,
    InsufficientNodes,
    ContentIdMismatch,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContentNetwork {
    content_id: String,
    state_node_ids: HashSet<String>,
    minimum_nodes: usize,
}

impl ContentNetwork {
    pub fn new(content_id: String, minimum_nodes: usize) -> Self {
        Self {
            content_id,
            state_node_ids: HashSet::new(),
            minimum_nodes,
        }
    }

    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    pub fn state_node_ids(&self) -> &HashSet<String> {
        &self.state_node_ids
    }

    pub fn node_count(&self) -> usize {
        self.state_node_ids.len()
    }

    pub fn minimum_nodes(&self) -> usize {
        self.minimum_nodes
    }

    pub fn add_node(&mut self, node_id: String) -> Result<(), ContentNetworkError> {
        if self.state_node_ids.contains(&node_id) {
            return Err(ContentNetworkError::NodeAlreadyExists);
        }
        self.state_node_ids.insert(node_id);
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &str) -> Result<(), ContentNetworkError> {
        if !self.state_node_ids.contains(node_id) {
            return Err(ContentNetworkError::NodeNotFound);
        }
        
        if self.state_node_ids.len() <= self.minimum_nodes {
            return Err(ContentNetworkError::InsufficientNodes);
        }
        
        self.state_node_ids.remove(node_id);
        Ok(())
    }

    pub fn contains_node(&self, node_id: &str) -> bool {
        self.state_node_ids.contains(node_id)
    }

    pub fn has_sufficient_nodes(&self) -> bool {
        self.state_node_ids.len() >= self.minimum_nodes
    }

    pub fn can_remove_node(&self) -> bool {
        self.state_node_ids.len() > self.minimum_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_network_creation() {
        let network = ContentNetwork::new("content_123".to_string(), 3);
        assert_eq!(network.content_id(), "content_123");
        assert_eq!(network.node_count(), 0);
        assert_eq!(network.minimum_nodes(), 3);
        assert!(!network.has_sufficient_nodes());
    }

    #[test]
    fn test_add_nodes() {
        let mut network = ContentNetwork::new("content_123".to_string(), 2);
        
        assert!(network.add_node("node_1".to_string()).is_ok());
        assert_eq!(network.node_count(), 1);
        assert!(network.contains_node("node_1"));
        
        assert!(network.add_node("node_2".to_string()).is_ok());
        assert_eq!(network.node_count(), 2);
        assert!(network.has_sufficient_nodes());
        
        assert_eq!(
            network.add_node("node_1".to_string()).unwrap_err(),
            ContentNetworkError::NodeAlreadyExists
        );
    }

    #[test]
    fn test_remove_nodes() {
        let mut network = ContentNetwork::new("content_123".to_string(), 2);
        network.add_node("node_1".to_string()).unwrap();
        network.add_node("node_2".to_string()).unwrap();
        network.add_node("node_3".to_string()).unwrap();
        
        assert!(network.can_remove_node());
        assert!(network.remove_node("node_3").is_ok());
        assert_eq!(network.node_count(), 2);
        assert!(!network.contains_node("node_3"));
        
        assert!(!network.can_remove_node());
        assert_eq!(
            network.remove_node("node_2").unwrap_err(),
            ContentNetworkError::InsufficientNodes
        );
        
        assert_eq!(
            network.remove_node("nonexistent").unwrap_err(),
            ContentNetworkError::NodeNotFound
        );
    }

    #[test]
    fn test_minimum_nodes_enforcement() {
        let mut network = ContentNetwork::new("content_123".to_string(), 3);
        
        network.add_node("node_1".to_string()).unwrap();
        network.add_node("node_2".to_string()).unwrap();
        assert!(!network.has_sufficient_nodes());
        
        network.add_node("node_3".to_string()).unwrap();
        assert!(network.has_sufficient_nodes());
        
        assert_eq!(
            network.remove_node("node_1").unwrap_err(),
            ContentNetworkError::InsufficientNodes
        );
    }
}