use crate::domain::{events::StateNodeEvent, storage::{Storage, StorageError}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rand::seq::SliceRandom;

// P2P network service trait
pub trait NetworkService {
    /// Discover available peer nodes
    fn discover_peers(&self) -> Result<Vec<String>, StateNodeError>;
    
    /// Send assignment request to specified node
    fn send_assignment_request(&self, target_node_id: &str, requesting_node_id: &str) -> Result<Option<String>, StateNodeError>;
    
    /// Check node connection status
    fn is_node_available(&self, node_id: &str) -> bool;
}

// Domain event type
pub type DomainEvents = Vec<StateNodeEvent>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentRequest {
    pub requesting_node_id: String,
    pub node_capacity: u64,
    pub available_capacity: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentResponse {
    pub assigned_content_network: Option<String>,
    pub assigning_node_id: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    Initialized,
    JoinedContentNetwork(String),
    Synchronized,
    Leaving,
    Disconnected,
}

#[derive(Debug, PartialEq)]
pub enum StateNodeError {
    InvalidStateTransition {
        from: String,
        to: String,
    },
    StorageError(StorageError),
    NetworkError(String),
    AlreadyExists(String),
}

impl From<StorageError> for StateNodeError {
    fn from(error: StorageError) -> Self {
        StateNodeError::StorageError(error)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateNode {
    node_id: String,
    storages: Storage,
    content_networks: Vec<String>,
    // Manage network capacity with (required_capacity, max_capacity) tuple
    network_capacities: HashMap<String, (u64, u64)>,
    status: NodeStatus,
}

impl StateNode {
    pub fn new(node_id: String, total_capacity: u64) -> Result<(Self, StateNodeEvent), StateNodeError> {
        let storages = Storage::new(total_capacity)?;
        
        let node = Self {
            node_id: node_id.clone(),
            storages,
            content_networks: Vec::new(),
            network_capacities: HashMap::new(),
            status: NodeStatus::Initialized,
        };

        let event = StateNodeEvent::NodeCreated {
            node_id,
            total_capacity,
            timestamp: current_timestamp(),
        };

        Ok((node, event))
    }

    /// Add content network and capacity settings
    pub fn add_content_network(&self, network_id: String, required_capacity: u64, max_capacity: u64) -> Self {
        let mut updated_node = self.clone();
        updated_node.content_networks.push(network_id.clone());
        updated_node.network_capacities.insert(network_id, (required_capacity, max_capacity));
        updated_node
    }

    pub fn request_assignment(&self, network_service: &dyn NetworkService) -> Result<AssignmentResponse, StateNodeError> {
        // search peer with libp2p
        let peer_id = "";
        // TODO: Implement libp2p search peer

        // When no assignment is received from any peer
        Ok(AssignmentResponse {
            assigned_content_network: None,
            assigning_node_id: String::new(),
            timestamp: current_timestamp(),
        })
    }

    /// Process assignment requests from other nodes
    pub fn assign_node(&self, request: AssignmentRequest) -> Result<(Self, StateNodeEvent, AssignmentResponse), StateNodeError> {

        let assigned_network = self.determine_content_network(&request)?;
        
        let response = AssignmentResponse {
            assigned_content_network: Some(assigned_network.clone()),
            assigning_node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        };

        let event = StateNodeEvent::NodeAssigned {
            assigning_node_id: self.node_id.clone(),
            assigned_node_id: request.requesting_node_id.clone(),
            content_network: assigned_network,
            timestamp: current_timestamp(),
        };

        Ok((self.clone(), event, response))
    }

    /// Logic to determine content network based on request
    fn determine_content_network(&self, request: &AssignmentRequest) -> Result<String, StateNodeError> {
        // Get all networks this node participates in that match the request's available_capacity
        let matching_networks: Vec<&String> = self.content_networks
            .iter()
            .filter(|network_id| {
                if let Some((required_capacity, max_capacity)) = self.network_capacities.get(*network_id) {
                    // Select networks where available_capacity is above minimum required and below maximum capacity
                    request.available_capacity >= *required_capacity && 
                    request.available_capacity <= *max_capacity
                } else {
                    false
                }
            })
            .collect();
        
        // Return error if no matching networks are found
        if matching_networks.is_empty() {
            return Err(StateNodeError::NetworkError(
                format!("No suitable content network found for capacity: {}", request.available_capacity)
            ));
        }
        
        // Randomly select one from the matches
        let mut rng = rand::thread_rng();
        let selected_network = matching_networks
            .choose(&mut rng)
            .ok_or_else(|| StateNodeError::NetworkError("Failed to select random network".to_string()))?;
        
        Ok(selected_network.clone())
    }

    pub fn join_content_network(&self, network_service: &dyn NetworkService) -> Result<(Self, StateNodeEvent), StateNodeError> {
        match self.status {
            NodeStatus::Initialized => {
                let assignment_response = self.request_assignment(network_service)?;
                
                if let Some(content_id) = assignment_response.assigned_content_network {
                    let mut updated_node = self.clone();
                    updated_node.content_networks.push(content_id.clone());
                    updated_node.status = NodeStatus::JoinedContentNetwork(content_id.clone());

                    let event = StateNodeEvent::JoinedContentNetwork {
                        node_id: self.node_id.clone(),
                        content_id,
                        timestamp: current_timestamp(),
                    };

                    Ok((updated_node, event))
                } else {
                    Err(StateNodeError::NetworkError("Failed to get content network assignment".to_string()))
                }
            }
            _ => Err(StateNodeError::InvalidStateTransition {
                from: format!("{:?}", self.status),
                to: "JoinedContentNetwork".to_string(),
            }),
        }
    }

    pub fn allocate_storage(&self, amount: u64) -> Result<(Self, StateNodeEvent), StateNodeError> {
        let new_storage = self.storages.allocate(amount)?;
        
        let updated_node = Self {
            storages: new_storage.clone(),
            ..self.clone()
        };

        let event = StateNodeEvent::StorageAllocated {
            node_id: self.node_id.clone(),
            amount,
            remaining_capacity: new_storage.available_capacity(),
            timestamp: current_timestamp(),
        };

        Ok((updated_node, event))
    }

    pub fn synchronize(&self) -> (Self, StateNodeEvent) {
        let updated_node = Self {
            status: NodeStatus::Synchronized,
            ..self.clone()
        };

        let event = StateNodeEvent::NodeSynchronized {
            node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        };

        (updated_node, event)
    }

    pub fn leave_network(&self) -> (Self, StateNodeEvent) {
        let updated_node = Self {
            status: NodeStatus::Leaving,
            ..self.clone()
        };

        let event = StateNodeEvent::LeftNetwork {
            node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        };

        (updated_node, event)
    }

    // Getters
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn storages(&self) -> &Storage {
        &self.storages
    }

    pub fn content_networks(&self) -> &[String] {
        &self.content_networks
    }

    pub fn status(&self) -> &NodeStatus {
        &self.status
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, NodeStatus::Synchronized | NodeStatus::JoinedContentNetwork(_))
    }

    /// Create AssignmentRequest from own information
    pub fn create_assignment_request(&self) -> AssignmentRequest {
        AssignmentRequest {
            requesting_node_id: self.node_id.clone(),
            node_capacity: self.storages.total_capacity(),
            available_capacity: self.storages.available_capacity(),
            timestamp: current_timestamp(),
        }
    }

    /// Integrated method to handle assignment request via network service
    pub fn handle_assignment_request(&self, request: AssignmentRequest, network_service: &dyn NetworkService) -> Result<AssignmentResponse, StateNodeError> {
        // First, check if own assignment is possible
        if let Ok((_, _, response)) = self.assign_node(request) {
            Ok(response)
        } else {
            // If own assignment is not possible, forward to other peers
            if let Ok(peers) = network_service.discover_peers() {
                for peer_id in peers {
                    if network_service.is_node_available(&peer_id) {
                        // Forward request to other peers (actual implementation requires appropriate forwarding logic)
                        if let Ok(Some(content_network)) = network_service.send_assignment_request(&peer_id, &request.requesting_node_id) {
                            return Ok(AssignmentResponse {
                                assigned_content_network: Some(content_network),
                                assigning_node_id: peer_id,
                                timestamp: current_timestamp(),
                            });
                        }
                    }
                }
            }
            
            Ok(AssignmentResponse {
                assigned_content_network: None,
                assigning_node_id: String::new(),
                timestamp: current_timestamp(),
            })
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

    // Test mock NetworkService
    struct MockNetworkService {
        available_peers: Vec<String>,
        assignment_result: Option<String>,
    }

    impl MockNetworkService {
        fn new(peers: Vec<String>, assignment: Option<String>) -> Self {
            Self {
                available_peers: peers,
                assignment_result: assignment,
            }
        }
    }

    impl NetworkService for MockNetworkService {
        fn discover_peers(&self) -> Result<Vec<String>, StateNodeError> {
            Ok(self.available_peers.clone())
        }

        fn send_assignment_request(&self, _target_node_id: &str, _requesting_node_id: &str) -> Result<Option<String>, StateNodeError> {
            Ok(self.assignment_result.clone())
        }

        fn is_node_available(&self, _node_id: &str) -> bool {
            true
        }
    }

    #[test]
    fn test_node_creation() {
        let (node, event) = StateNode::new("node-001".to_string(), 1000).unwrap();
        
        assert_eq!(node.node_id(), "node-001");
        assert_eq!(node.storages().total_capacity(), 1000);
        assert_eq!(node.status(), &NodeStatus::Initialized);
        
        matches!(event, StateNodeEvent::NodeCreated { .. });
    }

    #[test]
    fn test_request_assignment() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let network_service = MockNetworkService::new(
            vec!["peer-001".to_string()],
            Some("high-capacity-network".to_string())
        );
        
        let response = node.request_assignment(&network_service).unwrap();
        assert!(response.assigned_content_network.is_none()); // Current implementation always returns None
    }

    #[test]
    fn test_assign_node() {
        let (assigning_node, _) = StateNode::new("assigner-001".to_string(), 1000).unwrap();
        
        // Add test content networks
        let assigning_node = assigning_node
            .add_content_network("high-capacity-network".to_string(), 500, 1000)
            .add_content_network("low-capacity-network".to_string(), 100, 500);
        
        let request = AssignmentRequest {
            requesting_node_id: "requester-001".to_string(),
            node_capacity: 1000,
            available_capacity: 800,
            timestamp: current_timestamp(),
        };
        
        let (_, event, response) = assigning_node.assign_node(request).unwrap();
        
        assert!(response.assigned_content_network.is_some());
        // 800 capacity, so high-capacity-network should be selected
        assert_eq!(response.assigned_content_network.unwrap(), "high-capacity-network");
        matches!(event, StateNodeEvent::NodeAssigned { .. });
    }

    #[test]
    fn test_join_content_network_success() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let network_service = MockNetworkService::new(
            vec!["peer-001".to_string()],
            Some("test-network".to_string())
        );
        
        let (updated_node, event) = node.join_content_network(&network_service).unwrap();
        
        assert!(matches!(updated_node.status(), NodeStatus::JoinedContentNetwork(_)));
        assert_eq!(updated_node.content_networks().len(), 1);
        assert_eq!(updated_node.content_networks()[0], "test-network");
        matches!(event, StateNodeEvent::JoinedContentNetwork { .. });
    }

    #[test]
    fn test_join_content_network_no_peers() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let network_service = MockNetworkService::new(vec![], None);
        
        let result = node.join_content_network(&network_service);
        assert!(matches!(result, Err(StateNodeError::NetworkError(_))));
    }

    #[test]
    fn test_join_content_network_no_assignment() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let network_service = MockNetworkService::new(
            vec!["peer-001".to_string()],
            None // Assignment not returned
        );
        
        let result = node.join_content_network(&network_service);
        assert!(matches!(result, Err(StateNodeError::NetworkError(_))));
    }

    #[test]
    fn test_invalid_state_transition() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let (synchronized_node, _) = node.synchronize();
        let network_service = MockNetworkService::new(
            vec!["peer-001".to_string()],
            Some("test-network".to_string())
        );
        
        let result = synchronized_node.join_content_network(&network_service);
        assert!(matches!(result, Err(StateNodeError::InvalidStateTransition { .. })));
    }

    #[test]
    fn test_storage_allocation() {
        let (node, _) = StateNode::new("node-001".to_string(), 1000).unwrap();
        let (updated_node, event) = node.allocate_storage(300).unwrap();
        
        assert_eq!(updated_node.storages().used_capacity(), 300);
        assert_eq!(updated_node.storages().available_capacity(), 700);
        matches!(event, StateNodeEvent::StorageAllocated { .. });
    }

    #[test]
    fn test_capacity_based_network_assignment() {
        let (assigning_node, _) = StateNode::new("assigner-001".to_string(), 2000).unwrap();
        
        // Add multiple content networks
        let assigning_node = assigning_node
            .add_content_network("small-network".to_string(), 100, 300)
            .add_content_network("medium-network".to_string(), 300, 800)
            .add_content_network("large-network".to_string(), 800, 1500);
        
        // Small capacity request
        let small_request = AssignmentRequest {
            requesting_node_id: "requester-001".to_string(),
            node_capacity: 1000,
            available_capacity: 200,
            timestamp: current_timestamp(),
        };
        
        let (_, _, response) = assigning_node.assign_node(small_request).unwrap();
        assert_eq!(response.assigned_content_network.unwrap(), "small-network");
        
        // Medium capacity request
        let medium_request = AssignmentRequest {
            requesting_node_id: "requester-002".to_string(),
            node_capacity: 1000,
            available_capacity: 500,
            timestamp: current_timestamp(),
        };
        
        let (_, _, response) = assigning_node.assign_node(medium_request).unwrap();
        assert_eq!(response.assigned_content_network.unwrap(), "medium-network");
        
        // Large capacity request
        let large_request = AssignmentRequest {
            requesting_node_id: "requester-003".to_string(),
            node_capacity: 1000,
            available_capacity: 1000,
            timestamp: current_timestamp(),
        };
        
        let (_, _, response) = assigning_node.assign_node(large_request).unwrap();
        assert_eq!(response.assigned_content_network.unwrap(), "large-network");
    }

    #[test]
    fn test_no_suitable_network_found() {
        let (assigning_node, _) = StateNode::new("assigner-001".to_string(), 1000).unwrap();
        
        // Add only small capacity networks
        let assigning_node = assigning_node.add_content_network("small-network".to_string(), 100, 300);
        
        // Large capacity request
        let large_request = AssignmentRequest {
            requesting_node_id: "requester-001".to_string(),
            node_capacity: 1000,
            available_capacity: 500,
            timestamp: current_timestamp(),
        };
        
        let result = assigning_node.assign_node(large_request);
        assert!(matches!(result, Err(StateNodeError::NetworkError(_))));
    }

    #[test]
    fn test_multiple_matching_networks_random_selection() {
        let (assigning_node, _) = StateNode::new("assigner-001".to_string(), 2000).unwrap();
        
        // Add multiple networks with the same capacity range (random selection test)
        let assigning_node = assigning_node
            .add_content_network("network-a".to_string(), 200, 600)
            .add_content_network("network-b".to_string(), 200, 600)
            .add_content_network("network-c".to_string(), 200, 600);
        
        let request = AssignmentRequest {
            requesting_node_id: "requester-001".to_string(),
            node_capacity: 1000,
            available_capacity: 400,
            timestamp: current_timestamp(),
        };
        
        // Multiple executions to confirm randomness (actual test may not be reliable)
        let (_, _, response) = assigning_node.assign_node(request).unwrap();
        let selected = response.assigned_content_network.unwrap();
        
        // Confirm that one of the networks is selected
        assert!(["network-a", "network-b", "network-c"].contains(&selected.as_str()));
    }
} 