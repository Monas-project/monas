use crate::{
    application_service::state_node_service::{
        ContentNetworkRepository, StateNodeRepository, UniversalNetworkRepository,
    },
    domain::{
        content_network::ContentNetwork,
        state_node::StateNode,
        universal_network::UniversalNetwork,
    },
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct InMemoryStateNodeRepository {
    nodes: Arc<Mutex<HashMap<String, StateNode>>>,
}

impl InMemoryStateNodeRepository {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStateNodeRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct InMemoryUniversalNetworkRepository {
    network: Arc<Mutex<UniversalNetwork>>,
}

impl InMemoryUniversalNetworkRepository {
    pub fn new() -> Self {
        Self {
            network: Arc::new(Mutex::new(UniversalNetwork::new())),
        }
    }
}

impl Default for InMemoryUniversalNetworkRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct InMemoryContentNetworkRepository {
    networks: Arc<Mutex<HashMap<String, ContentNetwork>>>,
}

impl InMemoryContentNetworkRepository {
    pub fn new() -> Self {
        Self {
            networks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryContentNetworkRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StateNodeRepository for InMemoryStateNodeRepository {
    async fn find_by_id(&self, node_id: &str) -> Result<Option<StateNode>, String> {
        let nodes = self.nodes.lock().await;
        Ok(nodes.get(node_id).cloned())
    }

    async fn save(&self, state_node: &StateNode) -> Result<(), String> {
        let mut nodes = self.nodes.lock().await;
        nodes.insert(state_node.node_id().to_string(), state_node.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl UniversalNetworkRepository for InMemoryUniversalNetworkRepository {
    async fn get(&self) -> Result<UniversalNetwork, String> {
        let network = self.network.lock().await;
        Ok(network.clone())
    }

    async fn save(&self, network: &UniversalNetwork) -> Result<(), String> {
        let mut stored_network = self.network.lock().await;
        *stored_network = network.clone();
        Ok(())
    }
}

#[async_trait::async_trait]
impl ContentNetworkRepository for InMemoryContentNetworkRepository {
    async fn find_by_content_id(&self, content_id: &str) -> Result<Option<ContentNetwork>, String> {
        let networks = self.networks.lock().await;
        Ok(networks.get(content_id).cloned())
    }

    async fn save(&self, network: &ContentNetwork) -> Result<(), String> {
        let mut networks = self.networks.lock().await;
        networks.insert(network.content_id().to_string(), network.clone());
        Ok(())
    }

    async fn find_all(&self) -> Result<Vec<ContentNetwork>, String> {
        let networks = self.networks.lock().await;
        Ok(networks.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_save_and_find() {
        let repository = InMemoryStateNodeRepository::new();
        let node = StateNode::new("test_node".to_string(), 1000);

        repository.save(&node).await.unwrap();
        
        let found_node = repository.find_by_id("test_node").await.unwrap();
        assert!(found_node.is_some());
        assert_eq!(found_node.unwrap().node_id(), "test_node");
    }

    #[tokio::test]
    async fn test_find_nonexistent() {
        let repository = InMemoryStateNodeRepository::new();
        
        let found_node = repository.find_by_id("nonexistent").await.unwrap();
        assert!(found_node.is_none());
    }

    #[tokio::test]
    async fn test_update_existing() {
        let repository = InMemoryStateNodeRepository::new();
        let mut node = StateNode::new("test_node".to_string(), 1000);
        
        repository.save(&node).await.unwrap();
        
        node.join_universal_network().unwrap();
        repository.save(&node).await.unwrap();
        
        let found_node = repository.find_by_id("test_node").await.unwrap().unwrap();
        assert!(found_node.is_in_universal_network());
    }
    
    #[tokio::test]
    async fn test_universal_network_repository() {
        let repository = InMemoryUniversalNetworkRepository::new();
        
        let mut network = repository.get().await.unwrap();
        network.add_node("node_1".to_string(), 1000).unwrap();
        repository.save(&network).await.unwrap();
        
        let retrieved_network = repository.get().await.unwrap();
        assert!(retrieved_network.contains_node("node_1"));
        assert_eq!(retrieved_network.get_node_resources("node_1"), Some(1000));
    }
    
    #[tokio::test]
    async fn test_content_network_repository() {
        let repository = InMemoryContentNetworkRepository::new();
        
        let mut network = ContentNetwork::new("content_123".to_string(), 2);
        network.add_node("node_1".to_string()).unwrap();
        repository.save(&network).await.unwrap();
        
        let retrieved_network = repository.find_by_content_id("content_123").await.unwrap();
        assert!(retrieved_network.is_some());
        let network = retrieved_network.unwrap();
        assert!(network.contains_node("node_1"));
        
        let all_networks = repository.find_all().await.unwrap();
        assert_eq!(all_networks.len(), 1);
    }
}