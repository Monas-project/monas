use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OperationType {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrdtOperation {
    pub operation_id: String,
    pub content_id: String,
    pub operation_type: OperationType,
    pub timestamp: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentNetwork {
    content_id: String,
    state_node_ids: HashSet<String>,
    minimum_nodes: usize,
    operations: Vec<CrdtOperation>,
}

#[derive(Debug, PartialEq)]
pub enum ContentNetworkError {
    NodeAlreadyExists(String),
    NodeNotFound(String),
    InsufficientNodes { required: usize, current: usize },
    InvalidContentId(String),
    OperationNotFound(String),
}

impl ContentNetwork {
    pub fn new(content_id: String, minimum_nodes: usize) -> Result<Self, ContentNetworkError> {
        if content_id.is_empty() {
            return Err(ContentNetworkError::InvalidContentId(content_id));
        }

        Ok(Self {
            content_id,
            state_node_ids: HashSet::new(),
            minimum_nodes,
            operations: Vec::new(),
        })
    }

    pub fn add_node(&self, node_id: String) -> Result<Self, ContentNetworkError> {
        if self.state_node_ids.contains(&node_id) {
            return Err(ContentNetworkError::NodeAlreadyExists(node_id));
        }

        let mut new_state_node_ids = self.state_node_ids.clone();
        new_state_node_ids.insert(node_id);

        Ok(Self {
            state_node_ids: new_state_node_ids,
            ..self.clone()
        })
    }

    pub fn remove_node(&self, node_id: &str) -> Result<Self, ContentNetworkError> {
        if !self.state_node_ids.contains(node_id) {
            return Err(ContentNetworkError::NodeNotFound(node_id.to_string()));
        }

        let mut new_state_node_ids = self.state_node_ids.clone();
        new_state_node_ids.remove(node_id);

        Ok(Self {
            state_node_ids: new_state_node_ids,
            ..self.clone()
        })
    }

    pub fn add_operation(&self, operation: CrdtOperation) -> Self {
        let mut new_operations = self.operations.clone();
        new_operations.push(operation);

        Self {
            operations: new_operations,
            ..self.clone()
        }
    }

    pub fn has_sufficient_nodes(&self) -> bool {
        self.state_node_ids.len() >= self.minimum_nodes
    }

    pub fn get_operations_after(&self, timestamp: u64) -> Vec<&CrdtOperation> {
        self.operations
            .iter()
            .filter(|op| op.timestamp > timestamp)
            .collect()
    }

    pub fn get_latest_operations(&self, limit: usize) -> Vec<&CrdtOperation> {
        let mut ops = self.operations.iter().collect::<Vec<_>>();
        ops.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        ops.into_iter().take(limit).collect()
    }

    // Getters
    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    pub fn node_count(&self) -> usize {
        self.state_node_ids.len()
    }

    pub fn minimum_nodes(&self) -> usize {
        self.minimum_nodes
    }

    pub fn contains_node(&self, node_id: &str) -> bool {
        self.state_node_ids.contains(node_id)
    }

    pub fn get_all_nodes(&self) -> Vec<String> {
        self.state_node_ids.iter().cloned().collect()
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub fn is_operational(&self) -> bool {
        self.has_sufficient_nodes()
    }
}

impl CrdtOperation {
    pub fn new(
        operation_id: String,
        content_id: String,
        operation_type: OperationType,
        data: Vec<u8>,
    ) -> Self {
        Self {
            operation_id,
            content_id,
            operation_type,
            timestamp: current_timestamp(),
            data,
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_network_creation() {
        let network = ContentNetwork::new("content-123".to_string(), 3).unwrap();
        
        assert_eq!(network.content_id(), "content-123");
        assert_eq!(network.minimum_nodes(), 3);
        assert_eq!(network.node_count(), 0);
        assert!(!network.has_sufficient_nodes());
    }

    #[test]
    fn test_add_node() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        let updated_network = network.add_node("node-001".to_string()).unwrap();
        
        assert!(updated_network.contains_node("node-001"));
        assert_eq!(updated_network.node_count(), 1);
    }

    #[test]
    fn test_sufficient_nodes() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        let network = network.add_node("node-001".to_string()).unwrap();
        let network = network.add_node("node-002".to_string()).unwrap();
        
        assert!(network.has_sufficient_nodes());
        assert!(network.is_operational());
    }

    #[test]
    fn test_add_duplicate_node() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        let updated_network = network.add_node("node-001".to_string()).unwrap();
        let result = updated_network.add_node("node-001".to_string());
        
        assert!(matches!(result, Err(ContentNetworkError::NodeAlreadyExists(_))));
    }

    #[test]
    fn test_add_operation() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        let operation = CrdtOperation::new(
            "op-001".to_string(),
            "content-123".to_string(),
            OperationType::Create,
            vec![1, 2, 3],
        );
        
        let updated_network = network.add_operation(operation);
        assert_eq!(updated_network.operation_count(), 1);
    }

    #[test]
    fn test_get_latest_operations() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        
        let op1 = CrdtOperation::new(
            "op-001".to_string(),
            "content-123".to_string(),
            OperationType::Create,
            vec![1, 2, 3],
        );
        
        let network = network.add_operation(op1);
        
        let op2 = CrdtOperation::new(
            "op-002".to_string(),
            "content-123".to_string(),
            OperationType::Update,
            vec![4, 5, 6],
        );
        
        let network = network.add_operation(op2);
        
        // 最新の1つを取得
        let latest_ops = network.get_latest_operations(1);
        assert_eq!(latest_ops.len(), 1);
        
        // 全ての操作を取得
        let all_ops = network.get_latest_operations(10);
        assert_eq!(all_ops.len(), 2);
    }

    #[test]
    fn test_remove_node() {
        let network = ContentNetwork::new("content-123".to_string(), 2).unwrap();
        let network = network.add_node("node-001".to_string()).unwrap();
        let network = network.remove_node("node-001").unwrap();
        
        assert!(!network.contains_node("node-001"));
        assert_eq!(network.node_count(), 0);
    }
} 