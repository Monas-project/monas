#[derive(Debug, Clone, PartialEq)]
pub struct StorageResource {
    total_capacity: u64,
    used_capacity: u64,
}

impl StorageResource {
    pub fn new(total_capacity: u64) -> Self {
        Self {
            total_capacity,
            used_capacity: 0,
        }
    }

    pub fn available_capacity(&self) -> u64 {
        self.total_capacity.saturating_sub(self.used_capacity)
    }

    pub fn total_capacity(&self) -> u64 {
        self.total_capacity
    }

    pub fn used_capacity(&self) -> u64 {
        self.used_capacity
    }

    pub fn allocate(&mut self, size: u64) -> Result<(), StateNodeError> {
        if self.available_capacity() < size {
            return Err(StateNodeError::InsufficientStorage);
        }
        self.used_capacity += size;
        Ok(())
    }

    pub fn deallocate(&mut self, size: u64) {
        self.used_capacity = self.used_capacity.saturating_sub(size);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkType {
    UniversalNetwork,
    ContentNetwork(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateNodeStatus {
    Idle,           // In UniversalNetwork but not assigned to any ContentNetwork
    Assigned(String), // Assigned to a specific ContentNetwork (content_id)
    Offline,        // Not in any network
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateNodeError {
    InsufficientStorage,
    AlreadyRegisteredToNetwork,
    NotRegisteredToNetwork,
    NetworkError(String),
    ResourceVerificationFailed,
}

#[derive(Clone)]
pub struct StateNode {
    node_id: String,
    storage_resources: StorageResource,
    status: StateNodeStatus,
    assigned_content_networks: Vec<String>,
}

impl StateNode {
    pub fn new(node_id: String, total_capacity: u64) -> Self {
        Self {
            node_id,
            storage_resources: StorageResource::new(total_capacity),
            status: StateNodeStatus::Offline,
            assigned_content_networks: Vec::new(),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn storage_resources(&self) -> &StorageResource {
        &self.storage_resources
    }

    pub fn status(&self) -> &StateNodeStatus {
        &self.status
    }

    pub fn assigned_content_networks(&self) -> &[String] {
        &self.assigned_content_networks
    }

    pub fn is_in_universal_network(&self) -> bool {
        matches!(self.status, StateNodeStatus::Idle | StateNodeStatus::Assigned(_))
    }

    pub fn is_assigned_to_content(&self, content_id: &str) -> bool {
        matches!(&self.status, StateNodeStatus::Assigned(id) if id == content_id)
    }

    pub fn join_universal_network(&mut self) -> Result<(), StateNodeError> {
        if self.is_in_universal_network() {
            return Err(StateNodeError::AlreadyRegisteredToNetwork);
        }
        self.status = StateNodeStatus::Idle;
        Ok(())
    }

    pub fn assign_to_content_network(&mut self, content_id: String) -> Result<(), StateNodeError> {
        if !self.is_in_universal_network() {
            return Err(StateNodeError::NotRegisteredToNetwork);
        }
        if self.assigned_content_networks.contains(&content_id) {
            return Err(StateNodeError::AlreadyRegisteredToNetwork);
        }
        
        self.assigned_content_networks.push(content_id.clone());
        
        // If this is the first content assignment, update status
        if matches!(self.status, StateNodeStatus::Idle) {
            self.status = StateNodeStatus::Assigned(content_id);
        }
        
        Ok(())
    }

    pub fn unassign_from_content_network(&mut self, content_id: &str) -> Result<(), StateNodeError> {
        let position = self
            .assigned_content_networks
            .iter()
            .position(|id| id == content_id)
            .ok_or(StateNodeError::NotRegisteredToNetwork)?;
        
        self.assigned_content_networks.remove(position);
        
        // Update status based on remaining assignments
        if self.assigned_content_networks.is_empty() {
            self.status = StateNodeStatus::Idle;
        } else {
            // Set status to the first remaining content assignment
            self.status = StateNodeStatus::Assigned(self.assigned_content_networks[0].clone());
        }
        
        Ok(())
    }

    pub fn leave_universal_network(&mut self) -> Result<(), StateNodeError> {
        if !self.is_in_universal_network() {
            return Err(StateNodeError::NotRegisteredToNetwork);
        }
        self.status = StateNodeStatus::Offline;
        self.assigned_content_networks.clear();
        Ok(())
    }

    pub fn verify_resources(&self) -> Result<bool, StateNodeError> {
        Ok(self.storage_resources.total_capacity > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_resource_creation() {
        let storage = StorageResource::new(1000);
        assert_eq!(storage.total_capacity(), 1000);
        assert_eq!(storage.used_capacity(), 0);
        assert_eq!(storage.available_capacity(), 1000);
    }

    #[test]
    fn test_storage_allocation() {
        let mut storage = StorageResource::new(1000);
        
        assert!(storage.allocate(300).is_ok());
        assert_eq!(storage.used_capacity(), 300);
        assert_eq!(storage.available_capacity(), 700);

        assert!(storage.allocate(800).is_err());
        assert_eq!(storage.used_capacity(), 300);
    }

    #[test]
    fn test_storage_deallocation() {
        let mut storage = StorageResource::new(1000);
        storage.allocate(500).unwrap();
        
        storage.deallocate(200);
        assert_eq!(storage.used_capacity(), 300);
        assert_eq!(storage.available_capacity(), 700);

        storage.deallocate(1000);
        assert_eq!(storage.used_capacity(), 0);
    }

    #[test]
    fn test_state_node_creation() {
        let node = StateNode::new("node_123".to_string(), 2000);
        assert_eq!(node.node_id(), "node_123");
        assert_eq!(node.storage_resources().total_capacity(), 2000);
        assert!(!node.is_in_universal_network());
        assert!(node.assigned_content_networks().is_empty());
        assert_eq!(node.status(), &StateNodeStatus::Offline);
    }

    #[test]
    fn test_universal_network_joining() {
        let mut node = StateNode::new("node_123".to_string(), 2000);
        
        assert!(node.join_universal_network().is_ok());
        assert!(node.is_in_universal_network());
        assert_eq!(node.status(), &StateNodeStatus::Idle);

        assert_eq!(
            node.join_universal_network().unwrap_err(),
            StateNodeError::AlreadyRegisteredToNetwork
        );
    }

    #[test]
    fn test_content_network_assignment() {
        let mut node = StateNode::new("node_123".to_string(), 2000);
        node.join_universal_network().unwrap();
        
        assert!(node.assign_to_content_network("content_1".to_string()).is_ok());
        assert!(node.assigned_content_networks().contains(&"content_1".to_string()));
        assert!(node.is_assigned_to_content("content_1"));
        assert_eq!(node.status(), &StateNodeStatus::Assigned("content_1".to_string()));

        assert_eq!(
            node.assign_to_content_network("content_1".to_string()).unwrap_err(),
            StateNodeError::AlreadyRegisteredToNetwork
        );

        assert!(node.unassign_from_content_network("content_1").is_ok());
        assert!(!node.assigned_content_networks().contains(&"content_1".to_string()));
        assert_eq!(node.status(), &StateNodeStatus::Idle);

        assert_eq!(
            node.unassign_from_content_network("content_1").unwrap_err(),
            StateNodeError::NotRegisteredToNetwork
        );
    }

    #[test]
    fn test_universal_network_leave() {
        let mut node = StateNode::new("node_123".to_string(), 2000);
        node.join_universal_network().unwrap();
        node.assign_to_content_network("content_1".to_string()).unwrap();
        
        assert!(node.leave_universal_network().is_ok());
        assert!(!node.is_in_universal_network());
        assert!(node.assigned_content_networks().is_empty());
        assert_eq!(node.status(), &StateNodeStatus::Offline);

        assert_eq!(
            node.leave_universal_network().unwrap_err(),
            StateNodeError::NotRegisteredToNetwork
        );
    }
    
    #[test]
    fn test_multiple_content_assignments() {
        let mut node = StateNode::new("node_123".to_string(), 2000);
        node.join_universal_network().unwrap();
        
        node.assign_to_content_network("content_1".to_string()).unwrap();
        node.assign_to_content_network("content_2".to_string()).unwrap();
        
        assert_eq!(node.assigned_content_networks().len(), 2);
        assert_eq!(node.status(), &StateNodeStatus::Assigned("content_1".to_string()));
        
        node.unassign_from_content_network("content_1").unwrap();
        assert_eq!(node.assigned_content_networks().len(), 1);
        assert_eq!(node.status(), &StateNodeStatus::Assigned("content_2".to_string()));
        
        node.unassign_from_content_network("content_2").unwrap();
        assert_eq!(node.status(), &StateNodeStatus::Idle);
    }
    
    #[test]
    fn test_assignment_requires_universal_network() {
        let mut node = StateNode::new("node_123".to_string(), 2000);
        
        assert_eq!(
            node.assign_to_content_network("content_1".to_string()).unwrap_err(),
            StateNodeError::NotRegisteredToNetwork
        );
    }

    #[test]
    fn test_resource_verification() {
        let node = StateNode::new("node_123".to_string(), 2000);
        assert!(node.verify_resources().unwrap());
        
        let empty_node = StateNode::new("node_456".to_string(), 0);
        assert!(!empty_node.verify_resources().unwrap());
    }
}