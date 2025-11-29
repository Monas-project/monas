//! Integration tests for the state node.
//!
//! These tests verify the end-to-end functionality of the state node,
//! including content creation, node registration, and event handling.

use monas_state_node::application_service::state_node_service::StateNodeService;
use monas_state_node::domain::events::Event;
use monas_state_node::infrastructure::event_bus_publisher::EventBusPublisher;
use monas_state_node::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
use monas_state_node::infrastructure::persistence::{
    SledContentNetworkRepository, SledNodeRegistry,
};
use monas_state_node::port::peer_network::PeerNetwork;
use std::sync::Arc;
use tempfile::TempDir;

/// Create a test service with temporary storage and real libp2p network.
async fn create_test_service() -> (
    Arc<StateNodeService<SledNodeRegistry, SledContentNetworkRepository, Libp2pNetwork, EventBusPublisher>>,
    TempDir,
) {
    let temp_dir = TempDir::new().unwrap();
    
    let node_registry = SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
    let content_repo = SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap();
    
    // Use minimal network config for testing (localhost only, no mDNS to avoid interference)
    let network_config = Libp2pNetworkConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_nodes: vec![],
        enable_mdns: false, // Disable mDNS for isolated tests
        gossipsub_topics: vec!["test-events".to_string()],
    };
    
    let network = Arc::new(Libp2pNetwork::new(network_config).await.unwrap());
    
    let event_publisher = EventBusPublisher::new();
    event_publisher.register_event_type().await;
    
    let node_id = network.local_peer_id();
    
    let service = Arc::new(StateNodeService::new(
        node_registry,
        content_repo,
        network,
        event_publisher,
        node_id,
    ));
    
    (service, temp_dir)
}

#[tokio::test]
async fn test_register_node() {
    let (service, _temp_dir) = create_test_service().await;
    
    // Register the local node
    let (snapshot, events) = service.register_node(1000).await.unwrap();
    
    assert_eq!(snapshot.total_capacity, 1000);
    assert_eq!(snapshot.available_capacity, 1000);
    assert_eq!(events.len(), 1);
    
    // Verify the node was persisted
    let retrieved = service.get_node(&snapshot.node_id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().total_capacity, 1000);
}

#[tokio::test]
async fn test_create_content() {
    let (service, _temp_dir) = create_test_service().await;
    
    // First register the local node so it can be assigned content
    service.register_node(10000).await.unwrap();
    
    // Create some content
    let data = b"Hello, World!";
    let event = service.create_content(data).await.unwrap();
    
    // Verify the event
    if let Event::ContentCreated { content_id, member_nodes, content_size, .. } = &event {
        assert!(!content_id.is_empty());
        assert_eq!(content_size, &(data.len() as u64));
        // In isolated test environment, member_nodes might be empty if no peers are found
        // The important thing is that the content network was created
        
        // Verify the content network was persisted
        let network = service.get_content_network(content_id).await.unwrap();
        assert!(network.is_some());
        let network = network.unwrap();
        assert_eq!(network.content_id, *content_id);
    } else {
        panic!("Expected ContentCreated event");
    }
}

#[tokio::test]
async fn test_list_nodes() {
    let (service, _temp_dir) = create_test_service().await;
    
    // Register some nodes
    service.register_node(1000).await.unwrap();
    
    // List nodes
    let nodes = service.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 1);
}

#[tokio::test]
async fn test_list_content_networks() {
    let (service, _temp_dir) = create_test_service().await;
    
    // Register the local node first
    service.register_node(10000).await.unwrap();
    
    // Create some content
    service.create_content(b"Content 1").await.unwrap();
    service.create_content(b"Content 2").await.unwrap();
    
    // List content networks
    let networks = service.list_content_networks().await.unwrap();
    assert_eq!(networks.len(), 2);
}

#[tokio::test]
async fn test_handle_sync_event() {
    let (service, _temp_dir) = create_test_service().await;
    
    // Create a NodeCreated event
    let event = Event::NodeCreated {
        node_id: "external-node-1".to_string(),
        total_capacity: 5000,
        available_capacity: 5000,
        timestamp: 12345,
    };
    
    // Handle the sync event
    let outcome = service.handle_sync_event(&event).await.unwrap();
    assert_eq!(outcome, monas_state_node::application_service::state_node_service::ApplyOutcome::Applied);
    
    // Verify the node was created
    let node = service.get_node("external-node-1").await.unwrap();
    assert!(node.is_some());
    assert_eq!(node.unwrap().total_capacity, 5000);
}

#[tokio::test]
async fn test_handle_content_created_sync() {
    let (service, _temp_dir) = create_test_service().await;
    
    // Create a ContentCreated event from another node
    let event = Event::ContentCreated {
        content_id: "external-content-1".to_string(),
        creator_node_id: "external-node".to_string(),
        content_size: 1024,
        member_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        timestamp: 12345,
    };
    
    // Handle the sync event
    let outcome = service.handle_sync_event(&event).await.unwrap();
    assert_eq!(outcome, monas_state_node::application_service::state_node_service::ApplyOutcome::Applied);
    
    // Verify the content network was created
    let network = service.get_content_network("external-content-1").await.unwrap();
    assert!(network.is_some());
    let network = network.unwrap();
    assert!(network.member_nodes.contains("node-a"));
    assert!(network.member_nodes.contains("node-b"));
}
