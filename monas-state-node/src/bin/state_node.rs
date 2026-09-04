//! State Node binary entry point.
//!
//! This binary starts a state node with HTTP API and P2P networking.

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::Multiaddr;
use monas_state_node::infrastructure::network::bootstrap::{
    is_dns_addr, parse_bootstrap_addr, BootstrapParseError,
};
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

    /// Externally reachable addresses to advertise to peers (multiaddr format).
    /// Use in production to announce a public IP/hostname so remote nodes can
    /// dial this node, e.g. `/ip4/203.0.113.5/tcp/9090`. May be repeated.
    #[arg(long)]
    external_address: Vec<String>,

    /// P2P listen port. Defaults to a fixed port so the advertised address is
    /// stable across restarts (important for production). Pass `0` for a random
    /// port (e.g. when running multiple nodes on one host).
    #[arg(long, default_value = "9090")]
    p2p_port: u16,

    /// Disable mDNS local-network peer discovery.
    ///
    /// mDNS only reaches peers in the same broadcast domain, so it does
    /// nothing in a real deployment (VPC, cross-internet) but works locally.
    /// Pass this when a local cluster should behave like a deployed one —
    /// otherwise mDNS can quietly paper over failures in the discovery paths
    /// production actually depends on.
    #[arg(long)]
    disable_mdns: bool,

    /// Disable NAT traversal (AutoNAT v2, circuit relay v2, DCUtR).
    ///
    /// NAT traversal is what lets a node behind a home router or a NAT gateway
    /// join at all. A deployment where every node is publicly reachable does
    /// not need it and can turn the machinery off.
    #[arg(long)]
    disable_nat_traversal: bool,

    /// Offer circuit relay service to other nodes.
    ///
    /// A relay carries traffic for peers it knows nothing about, so this is
    /// opt-in and separate from `--disable-nat-traversal`: needing a relay
    /// oneself is not the same as being willing to be one. Only a node that
    /// is actually reachable from outside can serve, so this requires
    /// `--external-address`.
    #[arg(long)]
    relay_service: bool,

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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    tracing::info!("Starting Monas State Node");
    tracing::info!("Data directory: {:?}", args.data_dir);
    tracing::info!("HTTP listen address: {}", args.listen);

    // Build configuration
    let mut network_config = monas_state_node::infrastructure::network::Libp2pNetworkConfig {
        listen_addrs: vec![format!("/ip4/0.0.0.0/tcp/{}", args.p2p_port)
            .parse::<Multiaddr>()
            .context("Failed to parse P2P listen address")?],
        enable_mdns: !args.disable_mdns,
        enable_nat_traversal: !args.disable_nat_traversal,
        ..Default::default()
    };
    if args.disable_nat_traversal {
        tracing::info!("NAT traversal disabled; this node can only reach directly-dialable peers");
    }
    if args.disable_mdns {
        tracing::info!(
            "mDNS disabled; discovery relies on bootstrap peers, Kademlia and the peer store"
        );
    }

    // Parse and add bootstrap addresses
    for addr_str in &args.bootstrap {
        match parse_bootstrap_addr(addr_str) {
            Ok((peer_id, addr)) => {
                if !is_dns_addr(&addr) {
                    // Not fatal, but worth saying out loud: a literal IP is
                    // frozen for the lifetime of the process, so if this peer
                    // is ever recreated on a different address we will dial
                    // the old one forever.
                    tracing::warn!(
                        "Bootstrap address {} uses a literal IP; it will not be \
                         re-resolved if that peer moves. Prefer /dns4/<host>/…",
                        addr_str
                    );
                }
                tracing::info!("Added bootstrap peer {} at {}", peer_id, addr);
                network_config.bootstrap_nodes.push((peer_id, addr));
            }
            Err(BootstrapParseError::MissingPeerId) => {
                tracing::warn!("Bootstrap address missing peer ID: {}", addr_str);
            }
            Err(BootstrapParseError::Malformed) => {
                tracing::warn!("Failed to parse bootstrap address: {}", addr_str);
            }
        }
    }

    // Parse and add externally reachable addresses to advertise.
    for addr_str in &args.external_address {
        match Multiaddr::from_str(addr_str) {
            Ok(addr) => {
                tracing::info!("External address: {}", addr);
                network_config.external_addrs.push(addr);
            }
            Err(e) => tracing::warn!("Failed to parse external address {}: {}", addr_str, e),
        }
    }

    // Relay service is only meaningful on a node that is actually reachable
    // from outside. Refusing here rather than starting a relay nobody can
    // reach keeps the "advertise only what you can provide" rule honest.
    if args.relay_service {
        if network_config.external_addrs.is_empty() {
            anyhow::bail!(
                "--relay-service requires at least one --external-address: a node that \
                 cannot be reached from outside cannot relay for anyone"
            );
        }
        if args.disable_nat_traversal {
            anyhow::bail!("--relay-service cannot be used with --disable-nat-traversal");
        }
        network_config.enable_relay_service = true;
        tracing::info!(
            "Relay service enabled; this node will carry circuits for other peers \
             (up to 128 reservations / 32 circuits)"
        );
    }

    let config = StateNodeConfig {
        data_dir: args.data_dir,
        http_addr: args.listen,
        network_config,
        node_id: args.node_id,
        sync_interval_secs: 30,
        outbox_retry_interval_secs: 10,
        ..StateNodeConfig::default()
    };

    // Create and run the node
    let node = StateNode::new(config)
        .await
        .context("Failed to create state node")?;

    tracing::info!("Node ID: {}", node.node_id());

    // Wait briefly for network to start listening, then log addresses
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let addrs = node.listen_addrs().await;
    for addr in &addrs {
        tracing::info!("P2P listen address: {}", addr);
    }

    // Run the node (this blocks until shutdown)
    node.run().await?;

    Ok(())
}
