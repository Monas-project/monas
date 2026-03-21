//! State Node - Main node structure combining all components.

#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::content_sync_service::ContentSyncService;
#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::state_node_service::{ServiceConfig, StateNodeService};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::auth::{MonasAccountAdapter, UcanAdapter};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::crdt_repository::CrslCrdtRepository;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::gossipsub_publisher::GossipsubEventPublisher;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::inbox_persistence::SledInboxPersistence;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::key_management::{KeyStore, NodeKeyPair};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::outbox_persistence::SledOutboxPersistence;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::persistence::SledAccessControlRepository;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::persistence::{SledContentNetworkRepository, SledNodeRegistry};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::reliable_event_publisher::{
    ReliableEventPublisher, ReliablePublisherConfig,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::port::peer_network::PeerNetwork;
#[cfg(not(target_arch = "wasm32"))]
use crate::port::public_key_registry::PublicKeyRegistry;
#[cfg(not(target_arch = "wasm32"))]
use crate::presentation::http_api::{create_router, AppState};
#[cfg(not(target_arch = "wasm32"))]
use anyhow::{Context, Result};
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::RwLock;
#[cfg(not(target_arch = "wasm32"))]
use tokio_util::sync::CancellationToken;

/// Configuration for the state node.
#[derive(Debug, Clone)]
#[cfg(not(target_arch = "wasm32"))]
pub struct StateNodeConfig {
    /// Data directory for persistence.
    pub data_dir: PathBuf,
    /// HTTP API listen address.
    pub http_addr: SocketAddr,
    /// Network configuration.
    pub network_config: Libp2pNetworkConfig,
    /// Node ID (optional, generated if not provided).
    pub node_id: Option<String>,
    /// Sync interval in seconds (default: 30).
    pub sync_interval_secs: u64,
    /// Outbox retry interval in seconds (default: 10).
    pub outbox_retry_interval_secs: u64,
    /// Minimum replication factor for content networks (default: 3).
    /// Can be set via MIN_REPLICATION_FACTOR environment variable.
    pub min_replication_factor: usize,
    /// Capacity threshold in bytes below which a node is considered low on storage (default: 1GB).
    /// Can be set via CAPACITY_THRESHOLD_BYTES environment variable.
    pub capacity_threshold_bytes: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for StateNodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            http_addr: "127.0.0.1:8080".parse().unwrap(),
            network_config: Libp2pNetworkConfig::default(),
            node_id: None,
            sync_interval_secs: 30,
            outbox_retry_interval_secs: 10,
            min_replication_factor: std::env::var("MIN_REPLICATION_FACTOR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            capacity_threshold_bytes: std::env::var("CAPACITY_THRESHOLD_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_073_741_824), // 1GB
        }
    }
}

/// Type alias for the sync service.
#[cfg(not(target_arch = "wasm32"))]
pub type SyncService =
    ContentSyncService<Libp2pNetwork, CrslCrdtRepository, SledContentNetworkRepository>;

/// Type alias for the reliable event publisher.
#[cfg(not(target_arch = "wasm32"))]
pub type ReliablePublisher = ReliableEventPublisher<Libp2pNetwork>;

/// State Node instance.
#[cfg(not(target_arch = "wasm32"))]
pub struct StateNode {
    config: StateNodeConfig,
    service: AppState,
    network: Arc<Libp2pNetwork>,
    /// CRDT repository for content storage.
    crdt_repo: Arc<CrslCrdtRepository>,
    /// Content sync service.
    sync_service: SyncService,
    /// Reliable event publisher with outbox/inbox pattern.
    reliable_publisher: Arc<ReliablePublisher>,
    /// Node's P-256 key pair.
    node_key_pair: NodeKeyPair,
    /// Public key registry.
    public_key_registry: Arc<dyn PublicKeyRegistry>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StateNode {
    /// Create a new StateNode with the given configuration.
    pub async fn new(config: StateNodeConfig) -> Result<Self> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir).context("Failed to create data directory")?;

        // Initialize persistence
        let node_registry = SledNodeRegistry::open(config.data_dir.join("nodes"))
            .context("Failed to open node registry")?;
        let content_repo = Arc::new(RwLock::new(
            SledContentNetworkRepository::open(config.data_dir.join("content"))
                .context("Failed to open content repository")?,
        ));
        let access_control_repo =
            SledAccessControlRepository::open(config.data_dir.join("access_control"))
                .context("Failed to open access control repository")?;

        // Initialize CRDT repository
        let crdt_repo = Arc::new(
            CrslCrdtRepository::open(config.data_dir.join("crdt"))
                .context("Failed to open CRDT repository")?,
        );

        // Initialize network with CRDT repository and content network repository for member verification
        let crdt_repo_dyn: Arc<dyn crate::port::content_repository::ContentRepository> =
            crdt_repo.clone();
        let content_repo_dyn: Arc<
            tokio::sync::RwLock<
                dyn crate::port::persistence::PersistentContentRepository + Send + Sync,
            >,
        > = content_repo.clone();
        let network = Arc::new(
            Libp2pNetwork::with_content_network_repo(
                config.network_config.clone(),
                crdt_repo_dyn.clone(),
                config.data_dir.clone(),
                Some(content_repo_dyn),
            )
            .await
            .context("Failed to create network")?,
        );

        // Initialize event publisher with Gossipsub support
        let event_publisher = GossipsubEventPublisher::new(network.clone(), None);
        event_publisher.register_event_type().await;

        // Initialize key store and load/generate P-256 key pair
        let key_store = KeyStore::new(config.data_dir.join("keys"));
        let node_key_pair = key_store
            .get_default_node_key()
            .context("Failed to load/generate node key")?;

        // Use libp2p PeerId as NodeId for consistency with DHT peer discovery
        let node_id = if let Some(ref provided_id) = config.node_id {
            // If a node ID is explicitly provided, use it (for backward compatibility)
            provided_id.clone()
        } else {
            // Use the libp2p PeerId so that NodeId matches what find_closest_peers returns
            network.local_peer_id()
        };

        // Initialize public key registry and register our key
        let public_key_registry: Arc<dyn PublicKeyRegistry> =
            Arc::new(crate::port::public_key_registry::InMemoryPublicKeyRegistry::new());
        public_key_registry
            .register_public_key(node_key_pair.public_key_bytes())
            .await
            .context("Failed to register public key")?;

        // Create sync service
        let sync_service = ContentSyncService::new(
            network.clone(),
            crdt_repo.clone(),
            content_repo.clone(),
            node_id.clone(),
        );

        // Create reliable event publisher with outbox/inbox
        let outbox = SledOutboxPersistence::open(config.data_dir.join("outbox"))
            .context("Failed to open outbox persistence")?;
        let inbox = SledInboxPersistence::open(config.data_dir.join("inbox"))
            .context("Failed to open inbox persistence")?;
        let reliable_publisher = Arc::new(ReliableEventPublisher::new(
            network.clone(),
            outbox,
            inbox,
            ReliablePublisherConfig::default(),
            node_id.clone(),
        ));

        // Create auth services with public key registry for identity verification
        let auth_public_key_repo = Arc::new(
            crate::infrastructure::persistence::SledPublicKeyRepository::open(
                config.data_dir.join("auth_public_keys"),
            )
            .context("Failed to open auth public key repository")?,
        );
        let auth_service = MonasAccountAdapter::new();
        let authz_service =
            UcanAdapter::new(crdt_repo_dyn.clone()).with_nonce_store(auth_public_key_repo.clone());

        // Create service with CRDT repository
        let service = Arc::new(
            StateNodeService::with_config(
                node_registry,
                content_repo,
                network.clone(),
                event_publisher,
                crdt_repo.clone(),
                node_id,
                ServiceConfig {
                    min_replication_factor: config.min_replication_factor,
                    capacity_threshold_bytes: config.capacity_threshold_bytes,
                    ..ServiceConfig::default()
                },
            )
            .with_access_control_repo(access_control_repo)
            .with_authentication_service(auth_service)
            .with_authorization_service(authz_service),
        );

        Ok(Self {
            config,
            service,
            network,
            crdt_repo,
            sync_service,
            reliable_publisher,
            node_key_pair,
            public_key_registry,
        })
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        self.service.local_node_id()
    }

    /// Get the node's public key in uncompressed SEC1 format (65 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.node_key_pair.public_key_bytes()
    }

    /// Get a reference to the node's key pair.
    pub fn key_pair(&self) -> &NodeKeyPair {
        &self.node_key_pair
    }

    /// Get a reference to the public key registry.
    pub fn public_key_registry(&self) -> &Arc<dyn PublicKeyRegistry> {
        &self.public_key_registry
    }

    /// Get a reference to the service.
    pub fn service(&self) -> &AppState {
        &self.service
    }

    /// Get a reference to the CRDT repository.
    pub fn crdt_repo(&self) -> &Arc<CrslCrdtRepository> {
        &self.crdt_repo
    }

    /// Get a reference to the network.
    pub fn network(&self) -> &Arc<Libp2pNetwork> {
        &self.network
    }

    /// Get a reference to the sync service.
    pub fn sync_service(&self) -> &SyncService {
        &self.sync_service
    }

    /// Get a reference to the reliable event publisher.
    pub fn reliable_publisher(&self) -> &Arc<ReliablePublisher> {
        &self.reliable_publisher
    }

    /// Connect to another node at the given multiaddr.
    pub async fn dial(&self, addr: &str) -> Result<()> {
        let multiaddr: libp2p::Multiaddr = addr.parse().context("Invalid multiaddr")?;
        self.network.dial(multiaddr).await
    }

    /// Get the addresses this node is listening on.
    pub async fn listen_addrs(&self) -> Vec<String> {
        self.network
            .listen_addrs_raw()
            .await
            .into_iter()
            .map(|a| a.to_string())
            .collect()
    }

    /// Run the node (HTTP server and event handler).
    ///
    /// Supports graceful shutdown via SIGINT/SIGTERM. When a shutdown signal
    /// is received, the HTTP server stops accepting new connections, in-flight
    /// requests are allowed to complete, and background tasks are cancelled.
    pub async fn run(&self) -> Result<()> {
        let router = create_router(self.service.clone());
        let token = CancellationToken::new();

        tracing::info!(
            "Starting state node {} on {}",
            self.node_id(),
            self.config.http_addr
        );

        // Spawn relay request handler
        if let Some(mut relay_rx) = self.network.take_relay_receiver().await {
            let service_for_relay = self.service.clone();
            let token_relay = token.clone();
            tokio::spawn(async move {
                use crate::infrastructure::network::libp2p_network::RelayRequestKind;
                use crate::port::auth_token::AuthToken;
                tracing::info!("Started relay request handler");
                loop {
                    tokio::select! {
                        _ = token_relay.cancelled() => {
                            tracing::info!("Relay request handler shutting down");
                            break;
                        }
                        req = relay_rx.recv() => {
                            let Some(req) = req else { break };
                            let result = match req.kind {
                                RelayRequestKind::UpdateContent {
                                    content_id,
                                    data,
                                    auth_token,
                                    request_signature,
                                    timestamp,
                                } => {
                                    let token = AuthToken::new(auth_token);
                                    service_for_relay
                                        .update_content(
                                            &content_id,
                                            &data,
                                            Some(&token),
                                            Some(&request_signature),
                                            timestamp,
                                        )
                                        .await
                                        .map(|_| ())
                                }
                                RelayRequestKind::DeleteContent {
                                    content_id,
                                    auth_token,
                                    request_signature,
                                    timestamp,
                                } => {
                                    let token = AuthToken::new(auth_token);
                                    service_for_relay
                                        .delete_content(
                                            &content_id,
                                            Some(&token),
                                            Some(&request_signature),
                                            timestamp,
                                        )
                                        .await
                                        .map(|_| ())
                                }
                                RelayRequestKind::InvalidateTokens {
                                    content_id,
                                    auth_token,
                                    request_signature,
                                    timestamp,
                                } => {
                                    let token = AuthToken::new(auth_token);
                                    service_for_relay
                                        .invalidate_tokens(
                                            &content_id,
                                            &token,
                                            Some(&request_signature),
                                            timestamp,
                                        )
                                        .await
                                        .map(|_| ())
                                }
                            };
                            let _ = req
                                .reply
                                .send(result.map_err(|e| anyhow::anyhow!(e.to_string())));
                        }
                    }
                }
                tracing::info!("Relay request handler stopped");
            });
        }

        // Subscribe to network events
        let mut event_rx = self.network.subscribe_events();
        let service = self.service.clone();
        let service_for_redundancy = service.clone();
        let sync_service_for_events = self.sync_service.clone();

        // Spawn event handler task
        let token_events = token.clone();
        tokio::spawn(async move {
            tracing::info!("Started network event handler");
            loop {
                tokio::select! {
                    _ = token_events.cancelled() => {
                        tracing::info!("Network event handler shutting down");
                        break;
                    }
                    result = event_rx.recv() => {
                        match result {
                            Ok(received) => {
                                tracing::debug!(
                                    "Received event from {}: {:?}",
                                    received.source,
                                    received.event.event_type()
                                );

                                // Forward to service for processing (with source PeerID for verification)
                                match service
                                    .handle_sync_event(&received.event, Some(&received.source))
                                    .await
                                {
                                    Ok(outcome) => {
                                        tracing::debug!("Processed sync event: {:?}", outcome);

                                        // If sync is needed, perform it
                                        if let crate::application_service::state_node_service::ApplyOutcome::NeedsSync { content_id } = outcome {
                                            tracing::info!("Content sync needed for {}, initiating sync", content_id);
                                            match sync_service_for_events.sync_from_peers(&content_id).await {
                                                Ok(result) => {
                                                    tracing::info!(
                                                        "Content sync completed for {}: {} operations applied from {} providers",
                                                        content_id,
                                                        result.operations_applied,
                                                        result.providers_contacted
                                                    );
                                                    if !result.errors.is_empty() {
                                                        tracing::warn!(
                                                            "Sync had {} errors: {:?}",
                                                            result.errors.len(),
                                                            result.errors
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to sync content {}: {}",
                                                        content_id,
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to process sync event: {}", e);
                                    }
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Event handler lagged, missed {} events", n);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                tracing::info!("Event channel closed, stopping handler");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Spawn periodic sync task
        let sync_service = self.sync_service.clone();
        let sync_interval = Duration::from_secs(self.config.sync_interval_secs);
        let token_sync = token.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Started periodic sync task (interval: {}s)",
                sync_interval.as_secs()
            );
            let mut interval = tokio::time::interval(sync_interval);
            loop {
                tokio::select! {
                    _ = token_sync.cancelled() => {
                        tracing::info!("Periodic sync task shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::debug!("Running periodic content sync");
                        match sync_service.sync_all_content().await {
                            Ok(results) => {
                                let total_applied: usize =
                                    results.iter().map(|(_, r)| r.operations_applied).sum();
                                if total_applied > 0 {
                                    tracing::info!(
                                        "Periodic sync completed: {} operations applied across {} contents",
                                        total_applied,
                                        results.len()
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Periodic sync failed: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Spawn periodic redundancy check task (5 minute interval)
        let token_redundancy = token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            tracing::info!("Started periodic redundancy check task (interval: 300s)");
            loop {
                tokio::select! {
                    _ = token_redundancy.cancelled() => {
                        tracing::info!("Periodic redundancy check task shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::debug!("Running periodic redundancy check");
                        match service_for_redundancy.check_all_redundancy().await {
                            Ok(checked) => {
                                if !checked.is_empty() {
                                    tracing::info!(
                                        "Periodic redundancy check completed for {} content networks",
                                        checked.len()
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Periodic redundancy check failed: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Spawn outbox retry task
        let reliable_publisher = self.reliable_publisher.clone();
        let retry_interval = Duration::from_secs(self.config.outbox_retry_interval_secs);
        let token_outbox = token.clone();
        tokio::spawn(async move {
            tracing::info!(
                "Started outbox retry task (interval: {}s)",
                retry_interval.as_secs()
            );
            let mut interval = tokio::time::interval(retry_interval);
            loop {
                tokio::select! {
                    _ = token_outbox.cancelled() => {
                        tracing::info!("Outbox retry task shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::debug!("Running outbox retry");
                        match reliable_publisher.retry_pending().await {
                            Ok(result) => {
                                if result.delivered > 0 || result.dropped > 0 {
                                    tracing::info!(
                                        "Outbox retry: {} delivered, {} failed, {} dropped",
                                        result.delivered,
                                        result.failed,
                                        result.dropped
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Outbox retry failed: {}", e);
                            }
                        }
                    }
                }
            }
        });

        let listener = tokio::net::TcpListener::bind(&self.config.http_addr)
            .await
            .context("Failed to bind HTTP listener")?;

        let shutdown_token = token.clone();
        let shutdown_signal = async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutdown signal received, starting graceful shutdown...");
            shutdown_token.cancel();
        };

        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await
        .context("HTTP server error")?;

        tracing::info!("HTTP server stopped. Shutdown complete.");
        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::port::content_repository::ContentRepository;
    use crate::port::peer_network::PeerNetwork;
    use tempfile::tempdir;

    #[test]
    fn test_state_node_config_default() {
        let config = StateNodeConfig::default();

        assert_eq!(config.data_dir, PathBuf::from("data"));
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8080");
        assert!(config.node_id.is_none());
        assert_eq!(config.sync_interval_secs, 30);
        assert_eq!(config.outbox_retry_interval_secs, 10);
        assert_eq!(config.min_replication_factor, 3);
        assert_eq!(config.capacity_threshold_bytes, 1_073_741_824);
    }

    #[tokio::test]
    async fn test_state_node_creation() {
        let tmp_dir = tempdir().unwrap();

        let config = StateNodeConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            http_addr: "127.0.0.1:0".parse().unwrap(), // Use port 0 for random available port
            network_config: Libp2pNetworkConfig {
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap_nodes: vec![],
                enable_mdns: false,
                gossipsub_topics: vec!["test".to_string()],
            },
            node_id: Some("test-node-id".to_string()),
            sync_interval_secs: 30,
            outbox_retry_interval_secs: 10,
            ..StateNodeConfig::default()
        };

        let node = StateNode::new(config).await.unwrap();

        // Test accessors
        assert_eq!(node.node_id(), "test-node-id");
        assert!(!node.service().local_node_id().is_empty());
        assert!(node.crdt_repo().list_contents().await.unwrap().is_empty());
        assert!(!node.network().local_peer_id().is_empty());
    }

    #[tokio::test]
    async fn test_state_node_listen_addrs() {
        let tmp_dir = tempdir().unwrap();

        let config = StateNodeConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            network_config: Libp2pNetworkConfig {
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap_nodes: vec![],
                enable_mdns: false,
                gossipsub_topics: vec!["test".to_string()],
            },
            node_id: None,
            sync_interval_secs: 30,
            outbox_retry_interval_secs: 10,
            ..StateNodeConfig::default()
        };

        let node = StateNode::new(config).await.unwrap();

        // Wait a bit for the network to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let addrs = node.listen_addrs().await;
        // Should have at least one listening address
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    async fn test_state_node_generated_node_id() {
        let tmp_dir = tempdir().unwrap();

        let config = StateNodeConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            network_config: Libp2pNetworkConfig {
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap_nodes: vec![],
                enable_mdns: false,
                gossipsub_topics: vec!["test".to_string()],
            },
            node_id: None, // Will be auto-generated from libp2p PeerId
            sync_interval_secs: 30,
            outbox_retry_interval_secs: 10,
            ..StateNodeConfig::default()
        };

        let node = StateNode::new(config).await.unwrap();

        // Node ID should be generated from the libp2p PeerId
        let node_id = node.node_id();
        assert!(!node_id.is_empty());

        // The node ID should match the libp2p peer ID
        let peer_id = node.network().local_peer_id();
        assert_eq!(node_id, peer_id);
    }

    #[tokio::test]
    async fn test_state_node_dial_invalid_addr() {
        let tmp_dir = tempdir().unwrap();

        let config = StateNodeConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            network_config: Libp2pNetworkConfig {
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap_nodes: vec![],
                enable_mdns: false,
                gossipsub_topics: vec!["test".to_string()],
            },
            node_id: None,
            sync_interval_secs: 30,
            outbox_retry_interval_secs: 10,
            ..StateNodeConfig::default()
        };

        let node = StateNode::new(config).await.unwrap();

        // Invalid multiaddr should return error
        let result = node.dial("invalid-addr").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid multiaddr"));
    }
}
