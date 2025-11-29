//! State Node binary entry point.
//!
//! This binary starts a state node with HTTP API and P2P networking.

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::Multiaddr;
use monas_state_node::{StateNode, StateNodeConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tracing_subscriber::EnvFilter;

/// State Node CLI arguments.
#[derive(Parser, Debug)]
#[command(name = "state-node")]
#[command(about = "Monas State Node - Distributed content management")]
struct Args {
    /// Data directory for persistence.
    #[arg(short, long, default_value = "data")]
    data_dir: PathBuf,

    /// HTTP API listen address.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Node ID (optional, auto-generated if not provided).
    #[arg(short, long)]
    node_id: Option<String>,

    /// Bootstrap node addresses (multiaddr format).
    #[arg(short, long)]
    bootstrap: Vec<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    tracing::info!("Starting Monas State Node");
    tracing::info!("Data directory: {:?}", args.data_dir);
    tracing::info!("HTTP listen address: {}", args.listen);

    // Build configuration
    let mut network_config = monas_state_node::infrastructure::network::Libp2pNetworkConfig::default();
    
    // Parse and add bootstrap addresses
    for addr_str in &args.bootstrap {
        tracing::info!("Bootstrap address: {}", addr_str);
        
        // Parse multiaddr and extract peer ID
        if let Ok(addr) = Multiaddr::from_str(addr_str) {
            // Extract peer ID from the multiaddr (last component should be /p2p/<peer_id>)
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                // Create address without the /p2p/ suffix for Kademlia
                let addr_without_p2p: Multiaddr = addr
                    .iter()
                    .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                    .collect();
                network_config.bootstrap_nodes.push((peer_id, addr_without_p2p));
                tracing::info!("Added bootstrap peer: {}", peer_id);
            } else {
                tracing::warn!("Bootstrap address missing peer ID: {}", addr_str);
            }
        } else {
            tracing::warn!("Failed to parse bootstrap address: {}", addr_str);
        }
    }

    let config = StateNodeConfig {
        data_dir: args.data_dir,
        http_addr: args.listen,
        network_config,
        node_id: args.node_id,
    };

    // Create and run the node
    let node = StateNode::new(config)
        .await
        .context("Failed to create state node")?;

    tracing::info!("Node ID: {}", node.node_id());

    // Run the node (this blocks until shutdown)
    node.run().await?;

    Ok(())
}

