//! Integration tests for the state node.
//!
//! These tests verify the end-to-end functionality of the state node,
//! including content creation, node registration, and event handling.

use monas_state_node::application_service::state_node_service::{
    NoOpAccessControlRepository, StateNodeService,
};
use monas_state_node::domain::events::Event;
use monas_state_node::infrastructure::crdt_repository::CrslCrdtRepository;
use monas_state_node::infrastructure::event_bus_publisher::EventBusPublisher;
use monas_state_node::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
use monas_state_node::infrastructure::persistence::{
    SledAccessControlRepository, SledContentNetworkRepository, SledNodeRegistry,
};
use monas_state_node::port::content_repository::ContentRepository;
use monas_state_node::port::peer_network::PeerNetwork;
use monas_state_node::port::{
    auth_token::AuthToken,
    authentication_service::AuthenticationService,
    authorization_service::{AuthorizationRequest, AuthorizationResult, AuthorizationService},
};
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
    NoOpAccessControlRepository,
>;

/// Type alias for the test service with access control.
type TestServiceWithAC = StateNodeService<
    SledNodeRegistry,
    SledContentNetworkRepository,
    Libp2pNetwork,
    EventBusPublisher,
    CrslCrdtRepository,
    SledAccessControlRepository,
>;

struct TestAuthService;

#[async_trait::async_trait]
impl AuthenticationService for TestAuthService {
    async fn authenticate(
        &self,
        token: &AuthToken,
    ) -> anyhow::Result<monas_state_node::domain::identity::Identity> {
        monas_state_node::domain::identity::Identity::user(token.as_str().to_string())
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn is_valid(&self, token: &AuthToken) -> anyhow::Result<bool> {
        Ok(!token.is_empty())
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

fn sign_access_control_update(update: &AccessControlUpdate) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdsa::signature::DigestSigner;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha3::{Digest, Keccak256};

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let message = update.signing_message();
    let (signature, _): (Signature, _) =
        signing_key.sign_digest(Keccak256::new_with_prefix(&message));
    (signature.to_vec(), public_key_bytes)
}

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

    let service = Arc::new(
        StateNodeService::new(
            node_registry,
            content_repo,
            network,
            event_publisher,
            crdt_repo.clone(),
            node_id,
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService),
    );

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
    let result = service
        .create_content(data, Some(&test_token()), Some(&test_request_signature()))
        .await;

    // Verify that it fails with the expected error in isolated environment
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("No available member nodes found"));

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

// ============================================================================
// Access Control Integration Tests
// ============================================================================

use monas_state_node::application_service::state_node_service::ServiceConfig;
use monas_state_node::domain::access_control::AccessControlUpdate;

/// Create a test service with access control repository.
async fn create_test_service_with_ac() -> (Arc<TestServiceWithAC>, Arc<CrslCrdtRepository>, TempDir)
{
    let temp_dir = TempDir::new().unwrap();

    let node_registry = SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
    let content_repo = Arc::new(RwLock::new(
        SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap(),
    ));
    let access_control_repo =
        SledAccessControlRepository::open(temp_dir.path().join("access_control")).unwrap();

    let crdt_repo = Arc::new(CrslCrdtRepository::open(temp_dir.path().join("crdt")).unwrap());
    let crdt_repo_dyn: Arc<dyn ContentRepository> = crdt_repo.clone();
    let data_dir = temp_dir.path().to_path_buf();

    let network_config = Libp2pNetworkConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_nodes: vec![],
        enable_mdns: false,
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

    let service = Arc::new(
        StateNodeService::with_config(
            node_registry,
            content_repo,
            network,
            event_publisher,
            crdt_repo.clone(),
            node_id,
            ServiceConfig::default(),
        )
        .with_access_control_repo(access_control_repo)
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService),
    );

    (service, crdt_repo, temp_dir)
}

#[tokio::test]
async fn test_access_control_verify_access_without_restrictions() {
    let (service, _crdt_repo, _temp_dir) = create_test_service_with_ac().await;

    // Without any access control state, all tokens should be valid
    let result = service.verify_access("content-1", 1000).await.unwrap();
    assert!(result, "Access should be allowed without restrictions");
}

#[tokio::test]
async fn test_access_control_init_and_verify() {
    let (service, _crdt_repo, _temp_dir) = create_test_service_with_ac().await;

    // Initialize access control for a content
    let ac = service.init_access_control("content-1").await.unwrap();
    assert_eq!(ac.content_id(), "content-1");
    assert_eq!(ac.min_valid_issued_at(), 0);

    // All tokens should still be valid (min_valid_issued_at = 0)
    let result = service.verify_access("content-1", 0).await.unwrap();
    assert!(result);

    let result = service.verify_access("content-1", 1000).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_access_control_update_and_verify() {
    let (service, _crdt_repo, _temp_dir) = create_test_service_with_ac().await;

    // Initialize access control
    service.init_access_control("content-1").await.unwrap();

    // Create a signed update (in real usage, signature would come from monas-account)
    let update = AccessControlUpdate::new("content-1".to_string(), 1000);
    let (signature, public_key) = sign_access_control_update(&update);
    let update = update.with_signature(signature, public_key);

    // Apply the update
    let updated_ac = service
        .update_access_control(
            &update,
            Some(&test_token()),
            Some(&test_request_signature()),
        )
        .await
        .unwrap();
    assert_eq!(updated_ac.min_valid_issued_at(), 1000);

    // Verify access with old token (should be denied)
    let result = service.verify_access("content-1", 500).await.unwrap();
    assert!(!result, "Old tokens should be denied");

    // Verify access with new token (should be allowed)
    let result = service.verify_access("content-1", 1000).await.unwrap();
    assert!(result, "New tokens should be allowed");

    let result = service.verify_access("content-1", 1500).await.unwrap();
    assert!(result, "Future tokens should be allowed");
}

#[tokio::test]
async fn test_access_control_get() {
    let (service, _crdt_repo, _temp_dir) = create_test_service_with_ac().await;

    // Initially, no access control state
    let ac = service.get_access_control("content-1").await.unwrap();
    assert!(ac.is_none());

    // Initialize access control
    service.init_access_control("content-1").await.unwrap();

    // Now it should exist
    let ac = service.get_access_control("content-1").await.unwrap();
    assert!(ac.is_some());
    assert_eq!(ac.unwrap().content_id(), "content-1");
}

#[tokio::test]
async fn test_access_control_update_missing_signature() {
    let (service, _crdt_repo, _temp_dir) = create_test_service_with_ac().await;

    // Initialize access control
    service.init_access_control("content-1").await.unwrap();

    // Create an update without signature
    let update = AccessControlUpdate::new("content-1".to_string(), 1000);

    // Update should fail due to missing signature
    let result = service
        .update_access_control(
            &update,
            Some(&test_token()),
            Some(&test_request_signature()),
        )
        .await;
    assert!(result.is_err());
}

// ============================================================
// AuthToken Verification Tests
// ============================================================

mod auth_token_tests {
    use monas_state_node::domain::access_control::ContentAccessControl;
    use monas_state_node::domain::auth_token::{CapabilityAction, KeyId};
    use monas_state_node::domain::auth_token_verifier::{AuthTokenVerifier, AuthTokenVerifyError};
    use p256::ecdsa::signature::DigestSigner;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha3::{Digest, Keccak256};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn generate_test_keypair() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (signing_key, public_key_bytes)
    }

    /// Create and sign a JWT token directly (simulating what a client would do)
    fn create_and_sign_token(
        signing_key: &SigningKey,
        issuer_pk: &[u8],
        audience_pk: &[u8],
        content_id: &str,
        action: CapabilityAction,
        exp: Option<u64>,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "ver": "1.0"
        });

        let payload = serde_json::json!({
            "iss": issuer_pk,
            "aud": audience_pk,
            "exp": exp,
            "iat": now,
            "jti": format!("test-{}", now),
            "att": [{
                "with": format!("monas://content/{}", content_id),
                "can": action
            }]
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let (signature, _): (Signature, _) =
            signing_key.sign_digest(Keccak256::new_with_prefix(signing_input.as_bytes()));
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_vec());

        format!("{}.{}", signing_input, sig_b64)
    }

    fn create_multi_capability_token(
        signing_key: &SigningKey,
        issuer_pk: &[u8],
        audience_pk: &[u8],
        content_id: &str,
        actions: Vec<CapabilityAction>,
        exp: Option<u64>,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "ver": "1.0"
        });

        let capabilities: Vec<serde_json::Value> = actions
            .into_iter()
            .map(|action| {
                serde_json::json!({
                    "with": format!("monas://content/{}", content_id),
                    "can": action
                })
            })
            .collect();

        let payload = serde_json::json!({
            "iss": issuer_pk,
            "aud": audience_pk,
            "exp": exp,
            "iat": now,
            "jti": format!("test-{}", now),
            "att": capabilities
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let (signature, _): (Signature, _) =
            signing_key.sign_digest(Keccak256::new_with_prefix(signing_input.as_bytes()));
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_vec());

        format!("{}.{}", signing_input, sig_b64)
    }

    #[test]
    fn auth_token_verification_integration() {
        // Simulate content owner creating and signing a AuthToken
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-abc123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Owner creates a token granting Read access to recipient
        let jwt = create_and_sign_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600), // 1 hour expiration
        );

        // State Node verifies the token
        let result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            Some(&KeyId::new(recipient_pk.clone())),
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.content_id, content_id);
        assert_eq!(verified.action, CapabilityAction::Read);
    }

    #[test]
    fn auth_token_with_access_control_invalidation() {
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-invalidation";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a token
        let jwt = create_and_sign_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        // Create access control that invalidates all tokens issued before now + 1 hour
        let mut access_control = ContentAccessControl::new(content_id.to_string());
        access_control.invalidate_before(now + 3600).unwrap();

        // Verification should fail due to invalidation
        let result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Read,
            Some(&access_control),
        );

        assert!(matches!(result, Err(AuthTokenVerifyError::Invalidated)));
    }

    #[test]
    fn auth_token_owner_role_capabilities() {
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-owner-role";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Owner grants all owner actions to recipient (simulating Owner role)
        let jwt = create_multi_capability_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::owner_actions(),
            Some(now + 3600),
        );

        // Verify all owner actions are granted
        for action in CapabilityAction::owner_actions() {
            let result = AuthTokenVerifier::verify(&jwt, &owner_pk, None, content_id, action, None);
            assert!(result.is_ok(), "Owner should have {:?} capability", action);
        }
    }

    #[test]
    fn auth_token_editor_role_capabilities() {
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-editor-role";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Owner grants editor actions to recipient
        let jwt = create_multi_capability_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::editor_actions(),
            Some(now + 3600),
        );

        // Editor should have Read and Write
        let read_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Read,
            None,
        );
        assert!(read_result.is_ok());

        let write_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Write,
            None,
        );
        assert!(write_result.is_ok());

        // Editor should NOT have Delete, Share, Revoke, Reencrypt
        let delete_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Delete,
            None,
        );
        assert!(matches!(
            delete_result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }

    #[test]
    fn auth_token_viewer_role_capabilities() {
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-viewer-role";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Owner grants viewer actions to recipient
        let jwt = create_multi_capability_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::viewer_actions(),
            Some(now + 3600),
        );

        // Viewer should have Read
        let read_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Read,
            None,
        );
        assert!(read_result.is_ok());

        // Viewer should NOT have Write
        let write_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Write,
            None,
        );
        assert!(matches!(
            write_result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }

    #[test]
    fn auth_token_reencrypt_permission() {
        let (owner_signing_key, owner_pk) = generate_test_keypair();
        let (_, recipient_pk) = generate_test_keypair();
        let content_id = "test-content-reencrypt";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Grant Reencrypt permission specifically
        let jwt = create_and_sign_token(
            &owner_signing_key,
            &owner_pk,
            &recipient_pk,
            content_id,
            CapabilityAction::Reencrypt,
            Some(now + 3600),
        );

        // Should have Reencrypt
        let result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Reencrypt,
            None,
        );
        assert!(result.is_ok());

        // But NOT Read (Reencrypt doesn't imply Read)
        let read_result = AuthTokenVerifier::verify(
            &jwt,
            &owner_pk,
            None,
            content_id,
            CapabilityAction::Read,
            None,
        );
        assert!(matches!(
            read_result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }
}
