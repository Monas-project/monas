//! A remembered address that fails to dial must be dropped from the on-disk
//! peer store, not re-dialled forever.
//!
//! Reproduces the production split: after ECS moved two nodes while they were
//! apart, each held only the other's old IP. Every dial burned the transport
//! timeout on it, the two never connected, and nothing ever refreshed the
//! entry.

use monas_state_node::application_service::node::{StateNode, StateNodeConfig};
use monas_state_node::infrastructure::network::peer_store::PeerStore;
use monas_state_node::infrastructure::network::Libp2pNetworkConfig;
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The peer store is flushed on the 30s connectivity-maintenance tick.
const FLUSH_DEADLINE: Duration = Duration::from_secs(60);

async fn start_node(data_dir: &Path) -> StateNode {
    let config = StateNodeConfig {
        data_dir: data_dir.to_path_buf(),
        http_addr: "127.0.0.1:0".parse().unwrap(),
        network_config: Libp2pNetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false,
            gossipsub_topics: vec!["monas-events".to_string()],
            external_addrs: vec![],
        },
        node_id: None,
        ..StateNodeConfig::default()
    };
    StateNode::new(config).await.unwrap()
}

#[tokio::test]
async fn a_dead_remembered_address_is_forgotten_on_disk() {
    let dir = TempDir::new().unwrap();

    // A peer we met before, remembered at an address nothing listens on any
    // more. Port 1 is reserved, so the connection is refused at once.
    let ghost = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let dead = format!("/ip4/127.0.0.1/tcp/1/p2p/{ghost}");
    std::fs::write(
        PeerStore::path(dir.path()),
        format!(r#"{{"peers":[["{ghost}",["/ip4/127.0.0.1/tcp/1"]]]}}"#),
    )
    .unwrap();

    let node = start_node(dir.path()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Any dial that names the peer will do; in production it is the sync
    // path's fetch_operations.
    node.dial(&dead).await.unwrap();

    let started = Instant::now();
    loop {
        let store = PeerStore::load(dir.path());
        if store.addrs(&ghost).is_none() {
            break;
        }
        assert!(
            started.elapsed() < FLUSH_DEADLINE,
            "dead address still on disk after {:?}: {:?}",
            started.elapsed(),
            store.addrs(&ghost)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
