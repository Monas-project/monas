//! State Node - Main node structure combining all components.

#[cfg(not(target_arch = "wasm32"))]
use crate::application_service::state_node_service::StateNodeService;
#[cfg(not(target_arch = "wasm32"))]
use crate::infrastructure::event_bus_publisher::EventBusPublisher;
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
        let network = Libp2pNetwork::new(config.network_config.clone())
            .await
            .context("Failed to create network")?;

        // Initialize event publisher
        let event_publisher = EventBusPublisher::new();
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
            network,
            event_publisher,
            node_id,
        ));

        Ok(Self { config, service })
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        self.service.local_node_id()
    }

    /// Get a reference to the service.
    pub fn service(&self) -> &AppState {
        &self.service
    }

    /// Run the node (HTTP server).
    pub async fn run(&self) -> Result<()> {
        let router = create_router(self.service.clone());

        tracing::info!(
            "Starting state node {} on {}",
            self.node_id(),
            self.config.http_addr
        );

        let listener = tokio::net::TcpListener::bind(&self.config.http_addr)
            .await
            .context("Failed to bind HTTP listener")?;

        axum::serve(listener, router)
            .await
            .context("HTTP server error")?;

        Ok(())
    }
}

