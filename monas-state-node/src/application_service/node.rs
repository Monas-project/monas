//! State Node - Main node structure combining all components.

#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::content_sync_service::ContentSyncService;
#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::state_node_service::StateNodeService;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::crdt_repository::CrslCrdtRepository;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::gossipsub_publisher::GossipsubEventPublisher;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::http_api::{create_router, AppState};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::inbox_persistence::SledInboxPersistence;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::outbox_persistence::SledOutboxPersistence;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::persistence::{SledContentNetworkRepository, SledNodeRegistry};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::reliable_event_publisher::{
    ReliableEventPublisher, ReliablePublisherConfig,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::port::peer_network::PeerNetwork;
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

        // Initialize CRDT repository
        let crdt_repo = Arc::new(
            CrslCrdtRepository::open(config.data_dir.join("crdt"))
                .context("Failed to open CRDT repository")?,
        );

        // Initialize network with CRDT repository
        let crdt_repo_dyn: Arc<dyn crate::port::content_repository::ContentRepository> =
            crdt_repo.clone();
        let network = Arc::new(
            Libp2pNetwork::new(
                config.network_config.clone(),
                crdt_repo_dyn,
                config.data_dir.clone(),
            )
            .await
            .context("Failed to create network")?,
        );

        // Initialize event publisher with Gossipsub support
        let event_publisher = GossipsubEventPublisher::new(network.clone(), None);
        event_publisher.register_event_type().await;

        // Generate or use provided node ID
        let node_id = config
            .node_id
            .clone()
            .unwrap_or_else(|| PeerNetwork::local_peer_id(network.as_ref()));

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

        // Create service with CRDT repository
        let service = Arc::new(StateNodeService::new(
            node_registry,
            content_repo,
            network.clone(),
            event_publisher,
            crdt_repo.clone(),
            node_id,
        ));

        Ok(Self {
            config,
            service,
            network,
            crdt_repo,
            sync_service,
            reliable_publisher,
        })
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        self.service.local_node_id()
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
            .listen_addrs()
            .await
            .into_iter()
            .map(|a| a.to_string())
            .collect()
    }

    /// Run the node (HTTP server and event handler).
    pub async fn run(&self) -> Result<()> {
        let router = create_router(self.service.clone());

        tracing::info!(
            "Starting state node {} on {}",
            self.node_id(),
            self.config.http_addr
        );

        // Subscribe to network events
        let mut event_rx = self.network.subscribe_events();
        let service = self.service.clone();

        // Spawn event handler task
        tokio::spawn(async move {
            tracing::info!("Started network event handler");
            loop {
                match event_rx.recv().await {
                    Ok(received) => {
                        tracing::debug!(
                            "Received event from {}: {:?}",
                            received.source,
                            received.event.event_type()
                        );

                        // Forward to service for processing
                        match service.handle_sync_event(&received.event).await {
                            Ok(outcome) => {
                                tracing::debug!("Processed sync event: {:?}", outcome);
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
        });

        // Spawn periodic sync task
        let sync_service = self.sync_service.clone();
        let sync_interval = Duration::from_secs(self.config.sync_interval_secs);
        tokio::spawn(async move {
            tracing::info!(
                "Started periodic sync task (interval: {}s)",
                sync_interval.as_secs()
            );
            let mut interval = tokio::time::interval(sync_interval);
            loop {
                interval.tick().await;
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
        });

        // Spawn outbox retry task
        let reliable_publisher = self.reliable_publisher.clone();
        let retry_interval = Duration::from_secs(self.config.outbox_retry_interval_secs);
        tokio::spawn(async move {
            tracing::info!(
                "Started outbox retry task (interval: {}s)",
                retry_interval.as_secs()
            );
            let mut interval = tokio::time::interval(retry_interval);
            loop {
                interval.tick().await;
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
        });

        let listener = tokio::net::TcpListener::bind(&self.config.http_addr)
            .await
            .context("Failed to bind HTTP listener")?;

        axum::serve(listener, router)
            .await
            .context("HTTP server error")?;

        Ok(())
    }
}
