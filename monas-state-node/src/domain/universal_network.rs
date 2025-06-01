use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UniversalNetworkError {
    NodeAlreadyExists,
    NodeNotFound,
    InsufficientResources,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UniversalNetwork {
    state_node_ids: HashSet<String>,
    node_resources: HashMap<String, u64>,
}

impl UniversalNetwork {
    pub fn new() -> Self {
        Self {
            state_node_ids: HashSet::new(),
            node_resources: HashMap::new(),
        }
    }

    pub fn state_node_ids(&self) -> &HashSet<String> {
        &self.state_node_ids
    }

    pub fn node_count(&self) -> usize {
        self.state_node_ids.len()
    }

    pub fn add_node(&mut self, node_id: String, available_resources: u64) -> Result<(), UniversalNetworkError> {
        if self.state_node_ids.contains(&node_id) {
            return Err(UniversalNetworkError::NodeAlreadyExists);
        }
        
        self.state_node_ids.insert(node_id.clone());
        self.node_resources.insert(node_id, available_resources);
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &str) -> Result<(), UniversalNetworkError> {
        if !self.state_node_ids.contains(node_id) {
            return Err(UniversalNetworkError::NodeNotFound);
        }
        
        self.state_node_ids.remove(node_id);
        self.node_resources.remove(node_id);
        Ok(())
    }

    pub fn contains_node(&self, node_id: &str) -> bool {
        self.state_node_ids.contains(node_id)
    }

    pub fn get_node_resources(&self, node_id: &str) -> Option<u64> {
        self.node_resources.get(node_id).copied()
    }

    pub fn update_node_resources(&mut self, node_id: &str, resources: u64) -> Result<(), UniversalNetworkError> {
        if !self.state_node_ids.contains(node_id) {
            return Err(UniversalNetworkError::NodeNotFound);
        }
        
        self.node_resources.insert(node_id.to_string(), resources);
        Ok(())
    }

    pub fn find_nodes_with_sufficient_resources(&self, required_resources: u64) -> Vec<String> {
        self.node_resources
            .iter()
            .filter(|(_, &resources)| resources >= required_resources)
            .map(|(node_id, _)| node_id.clone())
            .collect()
    }

    pub fn total_available_resources(&self) -> u64 {
        self.node_resources.values().sum()
    }

    pub fn get_unassigned_nodes(&self, assigned_content_networks: &HashMap<String, Vec<String>>) -> HashSet<String> {
        let assigned_nodes: HashSet<String> = assigned_content_networks
            .values()
            .flat_map(|nodes| nodes.iter().cloned())
            .collect();
        
        self.state_node_ids
            .difference(&assigned_nodes)
            .cloned()
            .collect()
    }
}

impl Default for UniversalNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_network_creation() {
        let network = UniversalNetwork::new();
        assert_eq!(network.node_count(), 0);
        assert_eq!(network.total_available_resources(), 0);
    }

    #[test]
    fn test_add_nodes() {
        let mut network = UniversalNetwork::new();
        
        assert!(network.add_node("node_1".to_string(), 1000).is_ok());
        assert_eq!(network.node_count(), 1);
        assert!(network.contains_node("node_1"));
        assert_eq!(network.get_node_resources("node_1"), Some(1000));
        
        assert!(network.add_node("node_2".to_string(), 2000).is_ok());
        assert_eq!(network.total_available_resources(), 3000);
        
        assert_eq!(
            network.add_node("node_1".to_string(), 500).unwrap_err(),
            UniversalNetworkError::NodeAlreadyExists
        );
    }

    #[test]
    fn test_remove_nodes() {
        let mut network = UniversalNetwork::new();
        network.add_node("node_1".to_string(), 1000).unwrap();
        network.add_node("node_2".to_string(), 2000).unwrap();
        
        assert!(network.remove_node("node_1").is_ok());
        assert_eq!(network.node_count(), 1);
        assert!(!network.contains_node("node_1"));
        assert_eq!(network.get_node_resources("node_1"), None);
        assert_eq!(network.total_available_resources(), 2000);
        
        assert_eq!(
            network.remove_node("nonexistent").unwrap_err(),
            UniversalNetworkError::NodeNotFound
        );
    }

    #[test]
    fn test_update_resources() {
        let mut network = UniversalNetwork::new();
        network.add_node("node_1".to_string(), 1000).unwrap();
        
        assert!(network.update_node_resources("node_1", 1500).is_ok());
        assert_eq!(network.get_node_resources("node_1"), Some(1500));
        
        assert_eq!(
            network.update_node_resources("nonexistent", 500).unwrap_err(),
            UniversalNetworkError::NodeNotFound
        );
    }

    #[test]
    fn test_find_nodes_with_sufficient_resources() {
        let mut network = UniversalNetwork::new();
        network.add_node("node_1".to_string(), 1000).unwrap();
        network.add_node("node_2".to_string(), 2000).unwrap();
        network.add_node("node_3".to_string(), 500).unwrap();
        
        let nodes = network.find_nodes_with_sufficient_resources(1000);
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&"node_1".to_string()));
        assert!(nodes.contains(&"node_2".to_string()));
        
        let nodes = network.find_nodes_with_sufficient_resources(2500);
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_get_unassigned_nodes() {
        let mut network = UniversalNetwork::new();
        network.add_node("node_1".to_string(), 1000).unwrap();
        network.add_node("node_2".to_string(), 2000).unwrap();
        network.add_node("node_3".to_string(), 1500).unwrap();
        network.add_node("node_4".to_string(), 500).unwrap();
        
        let mut assigned_networks = HashMap::new();
        assigned_networks.insert("content_1".to_string(), vec!["node_1".to_string(), "node_2".to_string()]);
        assigned_networks.insert("content_2".to_string(), vec!["node_3".to_string()]);
        
        let unassigned = network.get_unassigned_nodes(&assigned_networks);
        assert_eq!(unassigned.len(), 1);
        assert!(unassigned.contains("node_4"));
    }
}