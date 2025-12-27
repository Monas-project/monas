//! Integration tests for the state node.
//!
//! These tests verify the end-to-end functionality of the state node,
//! including content creation, node registration, and event handling.

use monas_state_node::application_service::state_node_service::StateNodeService;
use monas_state_node::domain::events::Event;
use monas_state_node::infrastructure::crdt_repository::CrslCrdtRepository;
use monas_state_node::infrastructure::event_bus_publisher::EventBusPublisher;
use monas_state_node::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
use monas_state_node::infrastructure::persistence::{
    SledContentNetworkRepository, SledNodeRegistry,
};
use monas_state_node::port::content_repository::ContentRepository;
use monas_state_node::port::peer_network::PeerNetwork;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// Type alias for the test service.
type TestService = StateNodeService<
    SledNodeRegistry,
    SledContentNetworkRepository,
    Libp2pNetwork,
    EventBusPublisher,
    CrslCrdtRepository,
>;

/// Create a test service with temporary storage and real libp2p network.
async fn create_test_service() -> (Arc<TestService>, Arc<CrslCrdtRepository>, TempDir) {
    let temp_dir = TempDir::new().unwrap();

    let node_registry = SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
    let content_repo = Arc::new(RwLock::new(
        SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap(),
    ));

    // Create CRDT repository for the network and service
    let crdt_repo = Arc::new(CrslCrdtRepository::open(temp_dir.path().join("crdt")).unwrap());
    let crdt_repo_dyn: Arc<dyn ContentRepository> = crdt_repo.clone();
    let data_dir = temp_dir.path().to_path_buf();

    // Use minimal network config for testing (localhost only, no mDNS to avoid interference)
    let network_config = Libp2pNetworkConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_nodes: vec![],
        enable_mdns: false, // Disable mDNS for isolated tests
        gossipsub_topics: vec!["test-events".to_string()],
    };

    let network = Arc::new(
        Libp2pNetwork::new(network_config, crdt_repo_dyn, data_dir)
            .await
            .unwrap(),
    );

    let event_publisher = EventBusPublisher::new();
    event_publisher.register_event_type().await;

    let node_id = network.local_peer_id();

    let service = Arc::new(StateNodeService::new(
        node_registry,
        content_repo,
        network,
        event_publisher,
        crdt_repo.clone(),
        node_id,
    ));

    (service, crdt_repo, temp_dir)
}

#[tokio::test]
async fn test_register_node() {
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

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
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

    // First register the local node so it can be assigned content
    service.register_node(10000).await.unwrap();

    // In isolated test environment, create_content will fail because no other peers are available.
    // This is expected behavior - content creation requires at least one other node to store the content.
    let data = b"Hello, World!";
    let result = service.create_content(data).await;

    // Verify that it fails with the expected error in isolated environment
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("no available member nodes found"));

    // Instead, test content network creation via sync event (simulating receiving from another node)
    let event = Event::ContentCreated {
        content_id: "test-content-id".to_string(),
        creator_node_id: "external-node".to_string(),
        content_size: data.len() as u64,
        member_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        timestamp: 12345,
    };

    let outcome = service.handle_sync_event(&event).await.unwrap();
    assert_eq!(
        outcome,
        monas_state_node::application_service::state_node_service::ApplyOutcome::Applied
    );

    // Verify the content network was persisted
    let networks = service.list_content_networks().await.unwrap();
    assert!(networks.contains(&"test-content-id".to_string()));
}

#[tokio::test]
async fn test_list_nodes() {
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

    // Register some nodes
    service.register_node(1000).await.unwrap();

    // List nodes
    let nodes = service.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 1);
}

#[tokio::test]
async fn test_list_content_networks() {
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

    // Register the local node first
    service.register_node(10000).await.unwrap();

    // In isolated test environment, we can't use create_content directly
    // because it requires other peers. Instead, use sync events to simulate
    // receiving content network information from other nodes.
    let event1 = Event::ContentCreated {
        content_id: "content-1".to_string(),
        creator_node_id: "external-node".to_string(),
        content_size: 100,
        member_nodes: vec!["node-a".to_string()],
        timestamp: 12345,
    };
    let event2 = Event::ContentCreated {
        content_id: "content-2".to_string(),
        creator_node_id: "external-node".to_string(),
        content_size: 200,
        member_nodes: vec!["node-b".to_string()],
        timestamp: 12346,
    };

    service.handle_sync_event(&event1).await.unwrap();
    service.handle_sync_event(&event2).await.unwrap();

    // List content networks
    let networks = service.list_content_networks().await.unwrap();
    assert_eq!(networks.len(), 2);
}

#[tokio::test]
async fn test_handle_sync_event() {
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

    // Create a NodeCreated event
    let event = Event::NodeCreated {
        node_id: "external-node-1".to_string(),
        total_capacity: 5000,
        available_capacity: 5000,
        timestamp: 12345,
    };

    // Handle the sync event
    let outcome = service.handle_sync_event(&event).await.unwrap();
    assert_eq!(
        outcome,
        monas_state_node::application_service::state_node_service::ApplyOutcome::Applied
    );

    // Verify the node was created
    let node = service.get_node("external-node-1").await.unwrap();
    assert!(node.is_some());
    assert_eq!(node.unwrap().total_capacity, 5000);
}

#[tokio::test]
async fn test_handle_content_created_sync() {
    let (service, _crdt_repo, _temp_dir) = create_test_service().await;

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
    assert_eq!(
        outcome,
        monas_state_node::application_service::state_node_service::ApplyOutcome::Applied
    );

    // Verify the content network was created
    let networks = service.list_content_networks().await.unwrap();
    assert!(networks.contains(&"external-content-1".to_string()));
}

// ============================================================================
// CRDT Integration Tests
// ============================================================================

#[tokio::test]
async fn test_crdt_create_and_get_content() {
    let (_service, crdt_repo, _temp_dir) = create_test_service().await;

    // Create content directly in CRDT repository
    let data = b"Test CRDT content";
    let result = crdt_repo.create_content(data, "test-author").await.unwrap();

    assert!(result.is_new);
    assert!(!result.genesis_cid.is_empty());

    // Retrieve the content
    let retrieved = crdt_repo.get_latest(&result.genesis_cid).await.unwrap();
    assert_eq!(retrieved, Some(data.to_vec()));
}

#[tokio::test]
async fn test_crdt_update_content() {
    let (_service, crdt_repo, _temp_dir) = create_test_service().await;

    // Create initial content
    let initial_data = b"Initial content";
    let result = crdt_repo
        .create_content(initial_data, "author1")
        .await
        .unwrap();

    // Update the content
    let updated_data = b"Updated content";
    let update_result = crdt_repo
        .update_content(&result.genesis_cid, updated_data, "author1")
        .await
        .unwrap();

    assert!(!update_result.is_new);
    assert_eq!(update_result.genesis_cid, result.genesis_cid);

    // Verify the update
    let retrieved = crdt_repo.get_latest(&result.genesis_cid).await.unwrap();
    assert_eq!(retrieved, Some(updated_data.to_vec()));
}

#[tokio::test]
async fn test_crdt_version_history() {
    let (_service, crdt_repo, _temp_dir) = create_test_service().await;

    // Create content
    let data1 = b"Version 1";
    let result = crdt_repo.create_content(data1, "author").await.unwrap();

    // Small delay to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Update content
    let data2 = b"Version 2";
    crdt_repo
        .update_content(&result.genesis_cid, data2, "author")
        .await
        .unwrap();

    // Get history
    let history = crdt_repo.get_history(&result.genesis_cid).await.unwrap();
    assert_eq!(history.len(), 2);
}

#[tokio::test]
async fn test_crdt_get_operations() {
    let (_service, crdt_repo, _temp_dir) = create_test_service().await;

    // Create content
    let data = b"Test content";
    let result = crdt_repo.create_content(data, "author").await.unwrap();

    // Get operations
    let operations = crdt_repo
        .get_operations(&result.genesis_cid, None)
        .await
        .unwrap();
    assert!(!operations.is_empty());
    assert_eq!(operations[0].genesis_cid, result.genesis_cid);
}

#[tokio::test]
async fn test_crdt_apply_operations() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    // Create two separate CRDT repositories (simulating two nodes)
    let repo1 = Arc::new(CrslCrdtRepository::open(temp_dir1.path().join("crdt")).unwrap());
    let repo2 = Arc::new(CrslCrdtRepository::open(temp_dir2.path().join("crdt")).unwrap());

    // Create content in repo1
    let data = b"Shared content";
    let result = repo1.create_content(data, "node1").await.unwrap();

    // Get operations from repo1
    let operations = repo1
        .get_operations(&result.genesis_cid, None)
        .await
        .unwrap();

    // Apply operations to repo2
    let applied = repo2.apply_operations(&operations).await.unwrap();
    assert_eq!(applied, 1);

    // Verify content exists in repo2
    let retrieved = repo2.get_latest(&result.genesis_cid).await.unwrap();
    assert_eq!(retrieved, Some(data.to_vec()));
}

#[tokio::test]
async fn test_crdt_since_version_filtering() {
    let (_service, crdt_repo, _temp_dir) = create_test_service().await;

    // Create content with multiple versions
    let data1 = b"Version 1";
    let result = crdt_repo.create_content(data1, "author").await.unwrap();
    let first_version = result.version_cid.clone();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let data2 = b"Version 2";
    crdt_repo
        .update_content(&result.genesis_cid, data2, "author")
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let data3 = b"Version 3";
    crdt_repo
        .update_content(&result.genesis_cid, data3, "author")
        .await
        .unwrap();

    // Get all operations
    let all_ops = crdt_repo
        .get_operations(&result.genesis_cid, None)
        .await
        .unwrap();
    assert_eq!(all_ops.len(), 3);

    // Get operations since first version
    let filtered_ops = crdt_repo
        .get_operations(&result.genesis_cid, Some(&first_version))
        .await
        .unwrap();
    // Should only include operations after the first version
    assert_eq!(filtered_ops.len(), 2);
}
