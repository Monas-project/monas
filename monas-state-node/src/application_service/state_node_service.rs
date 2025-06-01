use crate::domain::{
    content_network::ContentNetwork,
    events::StateNodeEvent,
    state_node::{NetworkType, StateNode, StateNodeError},
    universal_network::UniversalNetwork,
};

#[derive(Debug)]
pub enum StateNodeServiceError {
    DomainError(StateNodeError),
    RepositoryError(String),
    NetworkError(String),
}

impl From<StateNodeError> for StateNodeServiceError {
    fn from(error: StateNodeError) -> Self {
        StateNodeServiceError::DomainError(error)
    }
}

#[async_trait::async_trait]
pub trait StateNodeService {
    async fn verify_resources(&self, node_id: &str) -> Result<StateNodeEvent, StateNodeServiceError>;
    async fn join_universal_network(
        &self,
        node_id: &str,
    ) -> Result<StateNodeEvent, StateNodeServiceError>;
    async fn assign_to_content_network(
        &self,
        node_id: &str,
        content_id: &str,
    ) -> Result<StateNodeEvent, StateNodeServiceError>;
    async fn synchronize_node(
        &self,
        node_id: &str,
        network_type: NetworkType,
    ) -> Result<StateNodeEvent, StateNodeServiceError>;
    async fn leave_network(
        &self,
        node_id: &str,
        network_type: NetworkType,
    ) -> Result<StateNodeEvent, StateNodeServiceError>;
}

pub struct StateNodeApplicationService<R, U, C> {
    state_node_repository: R,
    universal_network_repository: U,
    content_network_repository: C,
}

impl<R, U, C> StateNodeApplicationService<R, U, C> {
    pub fn new(
        state_node_repository: R,
        universal_network_repository: U,
        content_network_repository: C,
    ) -> Self {
        Self {
            state_node_repository,
            universal_network_repository,
            content_network_repository,
        }
    }
}

#[async_trait::async_trait]
impl<R, U, C> StateNodeService for StateNodeApplicationService<R, U, C>
where
    R: StateNodeRepository + Send + Sync,
    U: UniversalNetworkRepository + Send + Sync,
    C: ContentNetworkRepository + Send + Sync,
{
    async fn verify_resources(&self, node_id: &str) -> Result<StateNodeEvent, StateNodeServiceError> {
        let state_node = self
            .state_node_repository
            .find_by_id(node_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .ok_or_else(|| StateNodeServiceError::RepositoryError("Node not found".to_string()))?;

        let verified = state_node.verify_resources()?;
        
        Ok(StateNodeEvent::ResourceVerified {
            node_id: node_id.to_string(),
            resources: state_node.storage_resources().clone(),
            verified,
        })
    }

    async fn join_universal_network(
        &self,
        node_id: &str,
    ) -> Result<StateNodeEvent, StateNodeServiceError> {
        let mut state_node = self
            .state_node_repository
            .find_by_id(node_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .ok_or_else(|| StateNodeServiceError::RepositoryError("Node not found".to_string()))?;

        state_node.join_universal_network()?;
        
        // Add node to universal network
        let mut universal_network = self
            .universal_network_repository
            .get()
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
        
        universal_network.add_node(
            node_id.to_string(),
            state_node.storage_resources().available_capacity(),
        )
        .map_err(|_| StateNodeServiceError::DomainError(StateNodeError::AlreadyRegisteredToNetwork))?;
        
        self.state_node_repository
            .save(&state_node)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
            
        self.universal_network_repository
            .save(&universal_network)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(StateNodeEvent::RegisteredToUniversal {
            node_id: node_id.to_string(),
            resources: state_node.storage_resources().clone(),
            timestamp,
        })
    }

    async fn assign_to_content_network(
        &self,
        node_id: &str,
        content_id: &str,
    ) -> Result<StateNodeEvent, StateNodeServiceError> {
        let mut state_node = self
            .state_node_repository
            .find_by_id(node_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .ok_or_else(|| StateNodeServiceError::RepositoryError("Node not found".to_string()))?;

        state_node.assign_to_content_network(content_id.to_string())?;
        
        // Add node to content network or create new one
        let mut content_network = self
            .content_network_repository
            .find_by_content_id(content_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .unwrap_or_else(|| ContentNetwork::new(content_id.to_string(), 1));
        
        content_network.add_node(node_id.to_string())
            .map_err(|_| StateNodeServiceError::DomainError(StateNodeError::AlreadyRegisteredToNetwork))?;
        
        self.state_node_repository
            .save(&state_node)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
            
        self.content_network_repository
            .save(&content_network)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(StateNodeEvent::JoinedContentNetwork {
            node_id: node_id.to_string(),
            content_id: content_id.to_string(),
            timestamp,
        })
    }

    async fn synchronize_node(
        &self,
        node_id: &str,
        network_type: NetworkType,
    ) -> Result<StateNodeEvent, StateNodeServiceError> {
        let state_node = self
            .state_node_repository
            .find_by_id(node_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .ok_or_else(|| StateNodeServiceError::RepositoryError("Node not found".to_string()))?;

        match &network_type {
            NetworkType::UniversalNetwork => {
                if !state_node.is_in_universal_network() {
                    return Err(StateNodeServiceError::DomainError(
                        StateNodeError::NotRegisteredToNetwork,
                    ));
                }
            }
            NetworkType::ContentNetwork(content_id) => {
                if !state_node.assigned_content_networks().contains(content_id) {
                    return Err(StateNodeServiceError::DomainError(
                        StateNodeError::NotRegisteredToNetwork,
                    ));
                }
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(StateNodeEvent::Synchronized {
            node_id: node_id.to_string(),
            network: network_type,
            timestamp,
        })
    }

    async fn leave_network(
        &self,
        node_id: &str,
        network_type: NetworkType,
    ) -> Result<StateNodeEvent, StateNodeServiceError> {
        let mut state_node = self
            .state_node_repository
            .find_by_id(node_id)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?
            .ok_or_else(|| StateNodeServiceError::RepositoryError("Node not found".to_string()))?;

        match &network_type {
            NetworkType::UniversalNetwork => {
                state_node.leave_universal_network()?;
                
                // Remove from universal network
                let mut universal_network = self
                    .universal_network_repository
                    .get()
                    .await
                    .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
                    
                universal_network.remove_node(node_id)
                    .map_err(|_| StateNodeServiceError::DomainError(StateNodeError::NotRegisteredToNetwork))?;
                    
                self.universal_network_repository
                    .save(&universal_network)
                    .await
                    .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
            }
            NetworkType::ContentNetwork(content_id) => {
                state_node.unassign_from_content_network(content_id)?;
                
                // Remove from content network
                if let Some(mut content_network) = self
                    .content_network_repository
                    .find_by_content_id(content_id)
                    .await
                    .map_err(|e| StateNodeServiceError::RepositoryError(e))? {
                    
                    content_network.remove_node(node_id)
                        .map_err(|_| StateNodeServiceError::DomainError(StateNodeError::NotRegisteredToNetwork))?;
                        
                    self.content_network_repository
                        .save(&content_network)
                        .await
                        .map_err(|e| StateNodeServiceError::RepositoryError(e))?;
                }
            }
        }

        self.state_node_repository
            .save(&state_node)
            .await
            .map_err(|e| StateNodeServiceError::RepositoryError(e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(StateNodeEvent::LeftNetwork {
            node_id: node_id.to_string(),
            network: network_type,
            timestamp,
        })
    }
}

#[async_trait::async_trait]
pub trait StateNodeRepository {
    async fn find_by_id(&self, node_id: &str) -> Result<Option<StateNode>, String>;
    async fn save(&self, state_node: &StateNode) -> Result<(), String>;
}

#[async_trait::async_trait]
pub trait UniversalNetworkRepository {
    async fn get(&self) -> Result<UniversalNetwork, String>;
    async fn save(&self, network: &UniversalNetwork) -> Result<(), String>;
}

#[async_trait::async_trait]
pub trait ContentNetworkRepository {
    async fn find_by_content_id(&self, content_id: &str) -> Result<Option<ContentNetwork>, String>;
    async fn save(&self, network: &ContentNetwork) -> Result<(), String>;
    async fn find_all(&self) -> Result<Vec<ContentNetwork>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::repository::{
        InMemoryContentNetworkRepository, InMemoryStateNodeRepository,
        InMemoryUniversalNetworkRepository,
    };

    #[tokio::test]
    async fn test_verify_resources() {
        let state_repo = InMemoryStateNodeRepository::new();
        let universal_repo = InMemoryUniversalNetworkRepository::new();
        let content_repo = InMemoryContentNetworkRepository::new();
        let service = StateNodeApplicationService::new(state_repo.clone(), universal_repo, content_repo);
        
        let node = StateNode::new("test_node".to_string(), 1000);
        state_repo.save(&node).await.unwrap();

        let result = service.verify_resources("test_node").await.unwrap();
        
        match result {
            StateNodeEvent::ResourceVerified { node_id, verified, .. } => {
                assert_eq!(node_id, "test_node");
                assert!(verified);
            }
            _ => panic!("Unexpected event type"),
        }
    }

    #[tokio::test]
    async fn test_join_universal_network() {
        let state_repo = InMemoryStateNodeRepository::new();
        let universal_repo = InMemoryUniversalNetworkRepository::new();
        let content_repo = InMemoryContentNetworkRepository::new();
        let service = StateNodeApplicationService::new(state_repo.clone(), universal_repo.clone(), content_repo);
        
        let node = StateNode::new("test_node".to_string(), 1000);
        state_repo.save(&node).await.unwrap();

        let result = service
            .join_universal_network("test_node")
            .await
            .unwrap();

        match result {
            StateNodeEvent::RegisteredToUniversal { node_id, .. } => {
                assert_eq!(node_id, "test_node");
            }
            _ => panic!("Unexpected event type"),
        }

        let updated_node = state_repo.find_by_id("test_node").await.unwrap().unwrap();
        assert!(updated_node.is_in_universal_network());
        
        let universal_network = universal_repo.get().await.unwrap();
        assert!(universal_network.contains_node("test_node"));
    }

    #[tokio::test]
    async fn test_assign_to_content_network() {
        let state_repo = InMemoryStateNodeRepository::new();
        let universal_repo = InMemoryUniversalNetworkRepository::new();
        let content_repo = InMemoryContentNetworkRepository::new();
        let service = StateNodeApplicationService::new(state_repo.clone(), universal_repo, content_repo.clone());
        
        let mut node = StateNode::new("test_node".to_string(), 1000);
        node.join_universal_network().unwrap();
        state_repo.save(&node).await.unwrap();

        let result = service
            .assign_to_content_network("test_node", "content_123")
            .await
            .unwrap();

        match result {
            StateNodeEvent::JoinedContentNetwork { node_id, content_id, .. } => {
                assert_eq!(node_id, "test_node");
                assert_eq!(content_id, "content_123");
            }
            _ => panic!("Unexpected event type"),
        }

        let updated_node = state_repo.find_by_id("test_node").await.unwrap().unwrap();
        assert!(updated_node.assigned_content_networks().contains(&"content_123".to_string()));
        
        let content_network = content_repo.find_by_content_id("content_123").await.unwrap().unwrap();
        assert!(content_network.contains_node("test_node"));
    }
}