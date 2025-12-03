//! E2E tests for multi-node scenarios.
//!
//! These tests verify that multiple nodes can:
//! - Connect to each other
//! - Propagate events via Gossipsub
//! - Synchronize content networks

use monas_state_node::application_service::node::{StateNode, StateNodeConfig};
use monas_state_node::domain::events::Event;
use monas_state_node::infrastructure::network::Libp2pNetworkConfig;
use std::time::Duration;
use tempfile::TempDir;

/// The gossipsub topic used for state node events.
/// Must match GossipsubEventPublisher::DEFAULT_EVENT_TOPIC
const EVENTS_TOPIC: &str = "monas-events";

/// Create a test node with a unique data directory and port.
async fn create_test_node(port: u16) -> (StateNode, TempDir) {
    let temp_dir = TempDir::new().unwrap();

    let config = StateNodeConfig {
        data_dir: temp_dir.path().to_path_buf(),
        http_addr: format!("127.0.0.1:{}", port + 1000).parse().unwrap(),
        network_config: Libp2pNetworkConfig {
            listen_addrs: vec![format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false, // Disable mDNS to avoid interference between tests
            gossipsub_topics: vec![EVENTS_TOPIC.to_string()],
        },
        node_id: None,
    };

    let node = StateNode::new(config).await.unwrap();
    (node, temp_dir)
}

/// Wait for gossipsub mesh to form between connected peers.
/// Gossipsub requires time to establish mesh connections after TCP dial.
async fn wait_for_gossipsub_mesh() {
    // Gossipsub mesh formation typically needs ~500ms after connection
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn test_two_nodes_can_connect() {
    // Create two nodes
    let (node1, _temp1) = create_test_node(19001).await;
    let (node2, _temp2) = create_test_node(19002).await;

    // Wait for node1 to get its listen address
    tokio::time::sleep(Duration::from_millis(100)).await;

    let node1_addrs = node1.listen_addrs().await;
    assert!(
        !node1_addrs.is_empty(),
        "Node1 should have listen addresses"
    );

    // Node2 connects to Node1
    let addr = &node1_addrs[0];
    let result = node2.dial(addr).await;
    assert!(
        result.is_ok(),
        "Node2 should connect to Node1: {:?}",
        result
    );

    // Allow connection to establish
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("Node1 ID: {}", node1.node_id());
    println!("Node2 ID: {}", node2.node_id());
    println!("Node1 listening on: {:?}", node1_addrs);
}

#[tokio::test]
async fn test_three_nodes_mesh_connection() {
    // Create three nodes
    let (node1, _temp1) = create_test_node(19011).await;
    let (node2, _temp2) = create_test_node(19012).await;
    let (node3, _temp3) = create_test_node(19013).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let node1_addrs = node1.listen_addrs().await;
    let node2_addrs = node2.listen_addrs().await;

    // Node2 connects to Node1
    node2.dial(&node1_addrs[0]).await.unwrap();
    // Node3 connects to Node1 and Node2
    node3.dial(&node1_addrs[0]).await.unwrap();
    node3.dial(&node2_addrs[0]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("Three-node mesh established:");
    println!("  Node1: {}", node1.node_id());
    println!("  Node2: {}", node2.node_id());
    println!("  Node3: {}", node3.node_id());
}

#[tokio::test]
async fn test_node_registration_propagates() {
    // Create two nodes
    let (node1, _temp1) = create_test_node(19021).await;
    let (node2, _temp2) = create_test_node(19022).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect nodes
    let node1_addrs = node1.listen_addrs().await;
    node2.dial(&node1_addrs[0]).await.unwrap();

    // Wait for gossipsub mesh to form
    wait_for_gossipsub_mesh().await;

    // Subscribe to events on node2
    let mut event_rx = node2.network().subscribe_events();

    // Register node1
    let (snapshot, _events) = node1.service().register_node(10000).await.unwrap();
    println!("Node1 registered: {:?}", snapshot);

    // Wait for event to propagate to node2
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match event_rx.recv().await {
                Ok(received) => {
                    if let Event::NodeCreated { node_id, .. } = &received.event {
                        if node_id == node1.node_id() {
                            return Some(received);
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    })
    .await;

    assert!(
        received.is_ok(),
        "Node2 should receive NodeCreated event from Node1"
    );
    println!("Event propagated successfully!");
}

#[tokio::test]
async fn test_content_network_sync_via_event() {
    // Create two nodes
    let (node1, _temp1) = create_test_node(19031).await;
    let (node2, _temp2) = create_test_node(19032).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect nodes
    let node1_addrs = node1.listen_addrs().await;
    node2.dial(&node1_addrs[0]).await.unwrap();

    // Wait for gossipsub mesh to form
    wait_for_gossipsub_mesh().await;

    // Create a content network on node1 via sync event (simulating external creation)
    // Note: This tests local event handling, not network propagation
    let event = Event::ContentCreated {
        content_id: "test-content-e2e".to_string(),
        creator_node_id: "external-creator".to_string(),
        content_size: 1024,
        member_nodes: vec![node1.node_id().to_string(), node2.node_id().to_string()],
        timestamp: 12345,
    };

    // Apply event to node1 (local handling)
    node1.service().handle_sync_event(&event).await.unwrap();

    // Verify node1 has the content network
    let network1 = node1
        .service()
        .get_content_network("test-content-e2e")
        .await
        .unwrap();
    assert!(network1.is_some(), "Node1 should have the content network");
    println!("Content network created on Node1: {:?}", network1);
}

#[tokio::test]
async fn test_handle_sync_event_across_nodes() {
    // Create two nodes with unique ports
    let (node1, _temp1) = create_test_node(19051).await;
    let (node2, _temp2) = create_test_node(19052).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect nodes
    let node1_addrs = node1.listen_addrs().await;
    node2.dial(&node1_addrs[0]).await.unwrap();

    // Wait for gossipsub mesh to form (longer wait)
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Subscribe to events on node2 BEFORE registering
    let mut event_rx = node2.network().subscribe_events();

    // Register node1 - this should propagate to node2
    let register_result = node1.service().register_node(5000).await;
    println!("Register result: {:?}", register_result);
    register_result.unwrap();

    // Wait for and handle the event on node2
    let handle_result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Ok(received) => {
                    println!("Received event: {:?}", received.event.event_type());
                    if let Event::NodeCreated { .. } = &received.event {
                        // Handle the sync event
                        return node2.service().handle_sync_event(&received.event).await;
                    }
                }
                Err(e) => {
                    println!("Event recv error: {:?}", e);
                    continue;
                }
            }
        }
    })
    .await;

    assert!(handle_result.is_ok(), "Should receive and handle event");
    assert!(
        handle_result.unwrap().is_ok(),
        "Event handling should succeed"
    );

    // Verify node2 now knows about node1
    let node1_on_node2 = node2.service().get_node(node1.node_id()).await.unwrap();
    assert!(
        node1_on_node2.is_some(),
        "Node2 should have Node1's info after sync"
    );
    println!(
        "Node2 synchronized Node1's info: {:?}",
        node1_on_node2.unwrap()
    );
}
