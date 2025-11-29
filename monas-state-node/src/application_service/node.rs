//! State Node - Main node structure combining all components.

#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::state_node_service::StateNodeService;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::gossipsub_publisher::GossipsubEventPublisher;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::http_api::{create_router, AppState};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::persistence::{SledContentNetworkRepository, SledNodeRegistry};
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
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for StateNodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            http_addr: "127.0.0.1:8080".parse().unwrap(),
            network_config: Libp2pNetworkConfig::default(),
            node_id: None,
        }
    }
}

/// State Node instance.
#[cfg(not(target_arch = "wasm32"))]
pub struct StateNode {
    config: StateNodeConfig,
    service: AppState,
    network: Arc<Libp2pNetwork>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StateNode {
    /// Create a new StateNode with the given configuration.
    pub async fn new(config: StateNodeConfig) -> Result<Self> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)
            .context("Failed to create data directory")?;

        // Initialize persistence
        let node_registry = SledNodeRegistry::open(config.data_dir.join("nodes"))
            .context("Failed to open node registry")?;
        let content_repo = SledContentNetworkRepository::open(config.data_dir.join("content"))
            .context("Failed to open content repository")?;

        // Initialize network
        let network = Arc::new(
            Libp2pNetwork::new(config.network_config.clone())
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
            .unwrap_or_else(|| network.local_peer_id());

        // Create service
        let service = Arc::new(StateNodeService::new(
            node_registry,
            content_repo,
            network.clone(),
            event_publisher,
            node_id,
        ));

        Ok(Self {
            config,
            service,
            network,
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
                                tracing::debug!(
                                    "Processed sync event: {:?}",
                                    outcome
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to process sync event: {}",
                                    e
                                );
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

        let listener = tokio::net::TcpListener::bind(&self.config.http_addr)
            .await
            .context("Failed to bind HTTP listener")?;

        axum::serve(listener, router)
            .await
            .context("HTTP server error")?;

        Ok(())
    }
}

