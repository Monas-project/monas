//! Reproduction test for the create_content push-before-announce race.
//!
//! Spins up 3 real libp2p nodes (A, B, C), has A call `create_content`, and
//! asserts (without waiting for gossipsub settle) that:
//!   1. B and C actually have the CRDT data (the push succeeded)
//!   2. A does NOT retain a local CRDT copy (the creator is not a member)
//!
//! On unfixed code this fails at assertion (1) because the `PushOperations`
//! handler on B/C rejects A's push — they haven't received the
//! `Event::ContentCreated` gossipsub message yet, so they have no
//! `ContentNetwork` record and the membership check returns false.

use monas_state_node::application_service::state_node_service::{
    NoOpAccessControlRepository, ServiceConfig, StateNodeService,
};
use monas_state_node::domain::events::Event;
use monas_state_node::infrastructure::crdt_repository::CrslCrdtRepository;
use monas_state_node::infrastructure::event_bus_publisher::EventBusPublisher;
use monas_state_node::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
use monas_state_node::infrastructure::persistence::{
    SledContentNetworkRepository, SledNodeRegistry,
};
use monas_state_node::port::auth_token::AuthToken;
use monas_state_node::port::authentication_service::AuthenticationService;
use monas_state_node::port::authorization_service::{
    AuthorizationRequest, AuthorizationResult, AuthorizationService,
};
use monas_state_node::port::content_repository::ContentRepository;
use monas_state_node::port::peer_network::PeerNetwork;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;

type TestService = StateNodeService<
    SledNodeRegistry,
    SledContentNetworkRepository,
    Libp2pNetwork,
    EventBusPublisher,
    CrslCrdtRepository,
    NoOpAccessControlRepository,
>;

struct TestAuthService;

#[async_trait::async_trait]
impl AuthenticationService for TestAuthService {
    async fn authenticate(
        &self,
        token: &AuthToken,
        _context: Option<&monas_state_node::port::auth_token::AuthContext>,
    ) -> anyhow::Result<monas_state_node::domain::identity::Identity> {
        monas_state_node::domain::identity::Identity::user(token.as_str().to_string())
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn is_valid(&self, token: &AuthToken) -> anyhow::Result<bool> {
        Ok(!token.is_empty())
    }

    async fn verify_request_signature(
        &self,
        _token: &AuthToken,
        _signature: &[u8],
        _message: &str,
        _timestamp: Option<u64>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn verify_jwt_signature(&self, _token: &AuthToken) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_issuer(
        &self,
        token: &AuthToken,
    ) -> anyhow::Result<Option<monas_state_node::domain::identity::Identity>> {
        Ok(Some(
            monas_state_node::domain::identity::Identity::user(token.as_str().to_string())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ))
    }
}

struct AllowAllAuthorizationService;

#[async_trait::async_trait]
impl AuthorizationService for AllowAllAuthorizationService {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
    ) -> anyhow::Result<AuthorizationResult> {
        Ok(AuthorizationResult::Granted)
    }
}

fn test_token() -> AuthToken {
    AuthToken::new("test-user".to_string())
}

fn test_request_signature() -> Vec<u8> {
    vec![0x01]
}

/// A fully-wired test node (service + network + temp dir owned together).
struct TestNode {
    service: Arc<TestService>,
    network: Arc<Libp2pNetwork>,
    _temp_dir: TempDir,
}

async fn spawn_test_node() -> TestNode {
    let temp_dir = TempDir::new().unwrap();

    let node_registry = SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
    let content_repo = Arc::new(RwLock::new(
        SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap(),
    ));

    let crdt_repo = Arc::new(CrslCrdtRepository::open(temp_dir.path().join("crdt")).unwrap());
    let crdt_repo_dyn: Arc<dyn ContentRepository> = crdt_repo.clone();
    let data_dir = temp_dir.path().to_path_buf();

    // Wire the content_network_repo into the network so the PushOperations
    // handler performs the membership check (same as StateNode::new).
    // Without this, the bug is masked.
    let content_repo_dyn: Arc<
        RwLock<dyn monas_state_node::port::persistence::PersistentContentRepository + Send + Sync>,
    > = content_repo.clone();

    let network_config = Libp2pNetworkConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_nodes: vec![],
        enable_mdns: false,
        gossipsub_topics: vec!["test-events".to_string()],
    };

    let network = Arc::new(
        Libp2pNetwork::with_content_network_repo(
            network_config,
            crdt_repo_dyn,
            data_dir,
            Some(content_repo_dyn),
        )
        .await
        .unwrap(),
    );

    let event_publisher = EventBusPublisher::new();
    event_publisher.register_event_type().await;

    let node_id = network.local_peer_id();

    // Use min_replication_factor = 1 since in a 3-node test mesh we only have
    // 2 candidate members for A (A excludes itself).
    let service = Arc::new(
        StateNodeService::with_config(
            node_registry,
            content_repo,
            network.clone(),
            event_publisher,
            crdt_repo.clone(),
            node_id,
            ServiceConfig {
                min_replication_factor: 1,
                ..ServiceConfig::default()
            },
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService),
    );

    TestNode {
        service,
        network,
        _temp_dir: temp_dir,
    }
}

/// Dial each node to every other node to form a full mesh, then wait for
/// identify/kademlia to populate routing tables.
async fn form_mesh(nodes: &[&TestNode]) {
    // Give each node a moment to bind a listen address.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut addrs: Vec<Vec<libp2p::Multiaddr>> = Vec::with_capacity(nodes.len());
    for n in nodes {
        addrs.push(n.network.listen_addrs_raw().await);
    }

    for (i, src) in nodes.iter().enumerate() {
        for (j, dst_addrs) in addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            if let Some(a) = dst_addrs.first() {
                let _ = src.network.dial(a.clone()).await;
            }
        }
    }

    // Wait for identify + kademlia bootstrap to populate routing tables.
    // The existing e2e tests use 500-800ms; give a bit more for 3 nodes.
    tokio::time::sleep(Duration::from_millis(1200)).await;
}

#[tokio::test]
async fn create_content_delivers_crdt_ops_to_members_without_gossipsub_sync() {
    let a = spawn_test_node().await;
    let b = spawn_test_node().await;
    let c = spawn_test_node().await;

    form_mesh(&[&a, &b, &c]).await;

    // Register each node so their capacities can be queried.
    a.service.register_node(10_000).await.unwrap();
    b.service.register_node(10_000).await.unwrap();
    c.service.register_node(10_000).await.unwrap();

    // Sanity check: each node's Kademlia routing table should know the others.
    let peer_count = a.network.connected_peer_count().await;
    assert!(
        peer_count >= 2,
        "node A should be connected to B and C, got {}",
        peer_count
    );

    let data = b"race-test-payload".to_vec();

    let event = a
        .service
        .create_content(
            &data,
            Some(&test_token()),
            Some(&test_request_signature()),
            None,
        )
        .await
        .expect("create_content on A should succeed");

    let (content_id, member_nodes) = match event {
        Event::ContentCreated {
            content_id,
            member_nodes,
            ..
        } => (content_id, member_nodes),
        other => panic!("expected ContentCreated, got {:?}", other),
    };

    // The creator must not include itself.
    assert!(
        !member_nodes.contains(&a.network.local_peer_id()),
        "A should be excluded from member_nodes: {:?}",
        member_nodes
    );
    assert!(
        !member_nodes.is_empty(),
        "at least one member should be selected"
    );

    // The load-bearing assertion: members must have the CRDT data synchronously
    // after create_content returns. No gossipsub settle sleep.
    for member_id in &member_nodes {
        let node = if *member_id == b.network.local_peer_id() {
            &b
        } else if *member_id == c.network.local_peer_id() {
            &c
        } else {
            panic!("unknown member_id in result: {}", member_id);
        };

        let stored = node
            .service
            .crdt_repo()
            .get_latest(&content_id)
            .await
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some(data.as_slice()),
            "member {} should have the CRDT data immediately after create_content \
             (current code fails here because PushOperations was rejected before \
             the member learned about the content network)",
            member_id
        );
    }

    // Creator must NOT retain CRDT data locally (Bug 2).
    let creator_latest = a.service.crdt_repo().get_latest(&content_id).await.unwrap();
    assert!(
        creator_latest.is_none(),
        "creator A should not retain a local CRDT copy, but got: {:?}",
        creator_latest
    );
}

#[tokio::test]
async fn push_operations_rejects_unknown_network_without_bootstrap() {
    // Negative test: ensure the receiver still rejects pushes when neither a
    // pre-existing ContentNetwork record NOR a bootstrap payload is available.
    // This pins the rejection path so future refactors can't silently make the
    // receiver promiscuous.
    let a = spawn_test_node().await;
    let b = spawn_test_node().await;
    form_mesh(&[&a, &b]).await;

    // Fabricate a random genesis_cid that B has never heard of.
    let fake_cid = "bafkreifakefakefakefakefakefakefakefakefakefakefakefakefa";
    let empty_ops: Vec<monas_state_node::port::content_repository::SerializedOperation> = vec![];

    let result = a
        .network
        .push_operations(&b.network.local_peer_id(), fake_cid, &empty_ops, None)
        .await;

    assert!(
        result.is_err(),
        "pushing ops for an unknown network without bootstrap must be rejected, got {:?}",
        result
    );
}
