//! libp2p-based network implementation.
//!
//! Provides a full P2P networking stack using libp2p 0.56 with:
//! - Kademlia DHT for peer discovery
//! - Gossipsub for event propagation
//! - RequestResponse for direct peer communication
//! - mDNS for local peer discovery
//! - WebRTC and TCP transports

use super::behaviour::{BehaviourConfig, NodeBehaviour, NodeBehaviourEvent};
use super::peer_store::PeerStore;
use super::protocol::{ContentRequest, ContentResponse, PushBootstrap};
use super::public_key_protocol::{NodePublicKey, PublicKeyRequest, PublicKeyResponse};
use super::transport;
use crate::domain::events::Event;
use crate::infrastructure::disk_capacity;
use crate::port::content_repository::{ContentRepository, SerializedOperation};
use crate::port::peer_network::PeerNetwork;
use crate::port::peer_network::{RelayReadError, RelayReadErrorKind};

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    core::ConnectedPoint,
    gossipsub::{self, IdentTopic},
    identify, kad,
    request_response::{self, OutboundRequestId, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

/// Default timeout for PeerNetwork operations (30 seconds).
const PEER_NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// How often to check connectivity and re-dial bootstrap peers.
///
/// Short enough that a node which lost its peers rejoins within a minute,
/// long enough that a genuinely unreachable bootstrap is not hammered. Dials
/// are skipped entirely while the node is healthy, so the steady-state cost is
/// one comparison per tick.
const PEER_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

/// Connected-peer count at or above which no maintenance dialling happens.
///
/// This is about *connectivity*, not replication: it only decides when to
/// re-dial, and is deliberately independent of `min_replication_factor`.
const HEALTHY_PEER_COUNT: usize = 3;

/// The address of a freshly established connection, if it is one we could dial
/// again later.
///
/// Only outbound connections qualify. On an inbound connection the remote
/// address is `send_back_addr`, which carries the peer's *ephemeral source
/// port* rather than the port it listens on: dialling it from a later process
/// can never succeed. Storing those is worse than storing nothing, because
/// addresses are capped FIFO per peer (`MAX_ADDRS_PER_PEER`), so a handful of
/// inbound reconnects would push out the one address that actually works.
fn reusable_addr(endpoint: &ConnectedPoint) -> Option<&Multiaddr> {
    match endpoint {
        ConnectedPoint::Dialer { address, .. } => Some(address),
        ConnectedPoint::Listener { .. } => None,
    }
}

/// How many relays a private node keeps reservations with.
///
/// More than one because a relay can vanish, and a private node with no
/// reservation is unreachable; not many more because each reservation costs
/// the relay a slot.
const TARGET_RELAY_RESERVATIONS: usize = 2;

/// What AutoNAT has told us about our own reachability.
///
/// Deliberately three-valued. "We have not been told yet" is not the same as
/// "we are private": acting on the former would have every node briefly
/// announce itself as needing a relay at startup, and a node that never gets
/// an answer (no AutoNAT server around) should not silently behave as if it
/// were behind NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Reachability {
    #[default]
    Unknown,
    Public,
    Private,
}

/// Tracks reachability and the relay reservations that follow from it.
#[derive(Default)]
struct NatState {
    reachability: Reachability,
    /// Relays we currently listen through, with the listener that holds each
    /// reservation. The `ListenerId` is kept because releasing a reservation
    /// means removing its listener, and `Swarm::listeners()` only yields
    /// addresses — there is no way back to the id from those.
    reserved_with: HashMap<PeerId, libp2p::core::transport::ListenerId>,
}

/// A relay request received from a remote peer via P2P protocol.
/// The swarm loop sends these through a channel to the application layer (node.rs),
/// which processes them using StateNodeService.
pub struct RelayRequest {
    pub kind: RelayRequestKind,
    pub reply:
        oneshot::Sender<std::result::Result<RelayOutcome, crate::domain::errors::StateNodeError>>,
}

/// Result payload of a processed relay request.
pub enum RelayOutcome {
    /// Write relays (update/delete/invalidate) complete without a payload.
    Done,
    /// Relayed data read: raw bytes plus the version that was served.
    Data { data: Vec<u8>, version: String },
    /// Relayed history read.
    History { versions: Vec<String> },
}

/// The kind of relay request.
pub enum RelayRequestKind {
    UpdateContent {
        content_id: String,
        data: Vec<u8>,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
    },
    DeleteContent {
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
    },
    InvalidateTokens {
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
    },
    ReadContent {
        content_id: String,
        /// `None` reads the latest version; `Some(v)` a specific version CID.
        version: Option<String>,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
    },
    ReadHistory {
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
    },
}

/// Gossipsub message received from the network.
#[derive(Debug, Clone)]
pub struct GossipsubMessage {
    /// The topic the message was received on.
    pub topic: String,
    /// The peer that propagated the message.
    pub source: String,
    /// The raw message data.
    pub data: Vec<u8>,
}

/// Parsed domain event received from Gossipsub.
#[derive(Debug, Clone)]
pub struct ReceivedEvent {
    /// The peer that **published** the message, as authenticated by gossipsub.
    ///
    /// This is `Message::source`, not `propagation_source`: the mesh forwards
    /// messages, so the peer that handed us the bytes is generally not the one
    /// that produced them. Under `MessageAuthenticity::Signed` +
    /// `ValidationMode::Strict` the author field is required and the message
    /// signature is verified against it before delivery, so a forwarder cannot
    /// alter it. Authorization checks must use this field — using the
    /// forwarder would both accept forged origins and reject honest multi-hop
    /// delivery.
    ///
    /// `None` only if a message somehow arrives without an author, which
    /// Strict mode rejects; callers treat it as "unverifiable" and skip
    /// origin-bound checks rather than trusting it.
    pub source: Option<String>,
    /// The parsed domain event.
    pub event: Event,
}

/// Configuration for the libp2p network.
#[derive(Debug, Clone)]
pub struct Libp2pNetworkConfig {
    /// Listen addresses for the node.
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap nodes to connect to.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// Enable mDNS for local peer discovery.
    pub enable_mdns: bool,
    /// Enable NAT traversal (AutoNAT v2 + circuit relay v2 + DCUtR), which is
    /// what lets a node behind NAT participate at all.
    pub enable_nat_traversal: bool,
    /// Gossipsub topics to subscribe to.
    pub gossipsub_topics: Vec<String>,
    /// Externally reachable addresses to advertise to peers (e.g. a public
    /// IP/hostname for production deployments). These are passed to
    /// `Swarm::add_external_address` and announced via identify so remote nodes
    /// learn how to dial this node. Empty by default (local/mDNS setups don't
    /// need it).
    pub external_addrs: Vec<Multiaddr>,
}

impl Default for Libp2pNetworkConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec![
                // TCP for traditional connections (primary transport for server-to-server)
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                // Note: QUIC and WebRTC are available but disabled by default
                // due to compatibility issues. Enable when needed:
                // "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
                // "/ip4/0.0.0.0/udp/0/webrtc-direct".parse().unwrap(),
            ],
            bootstrap_nodes: vec![],
            enable_mdns: true,
            enable_nat_traversal: true,
            gossipsub_topics: vec!["monas-events".to_string()],
            external_addrs: vec![],
        }
    }
}

/// Commands sent to the swarm event loop.
enum SwarmCommand {
    FindClosestPeers {
        key: Vec<u8>,
        /// Number of closest peers to find.
        /// Currently not used as libp2p Kademlia uses default value (20 peers).
        /// TODO: Use this parameter when libp2p supports custom k-value in get_closest_peers.
        #[allow(dead_code)]
        k: usize,
        reply: oneshot::Sender<Result<Vec<PeerId>>>,
    },
    QueryCapacity {
        peer_id: PeerId,
        reply: oneshot::Sender<Result<(u64, u64)>>,
    },
    PublishEvent {
        topic: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    FetchContent {
        peer_id: PeerId,
        content_id: String,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    PublishProvider {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<()>>,
    },
    GetListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    // ========== CRDT Sync Commands ==========
    FetchOperations {
        peer_id: PeerId,
        genesis_cid: String,
        since_version: Option<String>,
        reply: oneshot::Sender<Result<Vec<SerializedOperation>>>,
    },
    PushOperations {
        peer_id: PeerId,
        genesis_cid: String,
        operations: Vec<SerializedOperation>,
        bootstrap: Option<PushBootstrap>,
        reply: oneshot::Sender<Result<usize>>,
    },
    GetProviders {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<PeerId>>>,
    },
    QueryPublicKeys {
        peer_id: PeerId,
        node_ids: Vec<String>,
        reply: oneshot::Sender<Result<Vec<NodePublicKey>>>,
    },
    RelayUpdateContent {
        peer_id: PeerId,
        content_id: String,
        data: Vec<u8>,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
        reply: oneshot::Sender<Result<bool>>,
    },
    RelayDeleteContent {
        peer_id: PeerId,
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
        reply: oneshot::Sender<Result<bool>>,
    },
    RelayInvalidateTokens {
        peer_id: PeerId,
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
        reply: oneshot::Sender<Result<bool>>,
    },
    RelayReadContent {
        peer_id: PeerId,
        content_id: String,
        version: Option<String>,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
        reply: RelayReadReply,
    },
    RelayReadHistory {
        peer_id: PeerId,
        content_id: String,
        auth_token: String,
        request_signature: Vec<u8>,
        timestamp: Option<u64>,
        reply: RelayHistoryReply,
    },
    /// Send a response back through a ResponseChannel.
    /// Used by spawned relay tasks to send responses without blocking the swarm loop.
    SendRelayResponse {
        channel: ResponseChannel<ContentResponse>,
        response: ContentResponse,
    },
}

/// TTL for pending requests. Entries older than this are cleaned up to prevent memory leaks.
const PENDING_REQUEST_TTL: Duration = Duration::from_secs(120);

/// Reply payload of a relayed data read: `(data, served_version)`.
type RelayReadReply = oneshot::Sender<std::result::Result<(Vec<u8>, String), RelayReadError>>;
/// Reply payload of a relayed history read.
type RelayHistoryReply = oneshot::Sender<std::result::Result<Vec<String>, RelayReadError>>;

/// Map a member-side service error to the wire verdict for relayed reads.
fn relay_read_error_kind(e: &crate::domain::errors::StateNodeError) -> RelayReadErrorKind {
    use crate::domain::errors::StateNodeError as E;
    match e {
        E::ContentNotFound(_) => RelayReadErrorKind::NotFound,
        E::AuthenticationFailed(_) | E::InvalidUcanToken(_) => {
            RelayReadErrorKind::AuthenticationFailed
        }
        E::AuthorizationFailed(_) | E::PermissionDenied(_) => {
            RelayReadErrorKind::AuthorizationFailed
        }
        _ => RelayReadErrorKind::Other,
    }
}

/// Pending requests tracking with TTL support.
///
/// Each request tracks its creation time. A periodic sweep removes entries
/// whose oneshot::Sender is closed (receiver timed out) or exceeded the TTL.
#[derive(Default)]
struct PendingRequests {
    capacity_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<(u64, u64)>>>,
    content_fetches: HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<u8>>>>,
    kad_queries: HashMap<kad::QueryId, oneshot::Sender<Result<Vec<PeerId>>>>,
    kad_provider_queries: HashMap<kad::QueryId, oneshot::Sender<Result<Vec<PeerId>>>>,
    operation_fetches:
        HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<SerializedOperation>>>>,
    operation_pushes: HashMap<OutboundRequestId, oneshot::Sender<Result<usize>>>,
    public_key_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<NodePublicKey>>>>,
    relay_update_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<bool>>>,
    relay_delete_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<bool>>>,
    relay_invalidate_tokens_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<bool>>>,
    relay_read_queries: HashMap<OutboundRequestId, RelayReadReply>,
    relay_history_queries: HashMap<OutboundRequestId, RelayHistoryReply>,
    /// Timestamps for all pending request IDs, used for TTL-based cleanup.
    timestamps: HashMap<u64, tokio::time::Instant>,
}

impl PendingRequests {
    /// Remove pending entries whose oneshot::Sender is closed (receiver dropped)
    /// or that have exceeded the TTL. This prevents unbounded memory growth.
    fn cleanup_stale(&mut self) {
        let now = tokio::time::Instant::now();
        let ttl = PENDING_REQUEST_TTL;

        // Clean up closed senders from each map
        self.capacity_queries.retain(|_, s| !s.is_closed());
        self.content_fetches.retain(|_, s| !s.is_closed());
        self.kad_queries.retain(|_, s| !s.is_closed());
        self.kad_provider_queries.retain(|_, s| !s.is_closed());
        self.operation_fetches.retain(|_, s| !s.is_closed());
        self.operation_pushes.retain(|_, s| !s.is_closed());
        self.public_key_queries.retain(|_, s| !s.is_closed());
        self.relay_update_queries.retain(|_, s| !s.is_closed());
        self.relay_delete_queries.retain(|_, s| !s.is_closed());
        self.relay_invalidate_tokens_queries
            .retain(|_, s| !s.is_closed());
        self.relay_read_queries.retain(|_, s| !s.is_closed());
        self.relay_history_queries.retain(|_, s| !s.is_closed());

        // Clean up expired timestamps
        self.timestamps
            .retain(|_, ts| now.duration_since(*ts) < ttl);
    }
}

/// Channels for dispatching relay requests and sending responses back to the swarm.
///
/// Relay requests (UpdateContent, DeleteContent, InvalidateTokens) are processed in
/// spawned tasks to avoid blocking the swarm loop. `relay_tx` dispatches the
/// request to the relay handler, and `command_tx` sends the response back to the
/// swarm via `SwarmCommand::SendRelayResponse`.
#[derive(Clone)]
struct RelayChannels {
    relay_tx: mpsc::Sender<RelayRequest>,
    command_tx: mpsc::Sender<SwarmCommand>,
}

/// libp2p-based network implementation.
pub struct Libp2pNetwork {
    local_peer_id: PeerId,
    command_tx: mpsc::Sender<SwarmCommand>,
    /// Connected peers and their addresses.
    ///
    /// Updated by the swarm event loop when connections are established/closed.
    /// Used for monitoring (health check) and peer management.
    connected_peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
    /// Broadcast channel for received Gossipsub events.
    event_rx: broadcast::Sender<ReceivedEvent>,
    /// Content repository for content storage.
    ///
    /// Passed to swarm event loop for handling incoming requests.
    /// Not directly accessed by PeerNetwork trait methods as they delegate to the swarm.
    #[allow(dead_code)]
    crdt_repo: Arc<dyn ContentRepository>,
    /// Data directory for disk capacity queries.
    ///
    /// Passed to swarm event loop for responding to CapacityQuery requests.
    /// Not directly accessed by PeerNetwork trait methods as they delegate to the swarm.
    #[allow(dead_code)]
    data_dir: PathBuf,
    /// P-256 public key for this node.
    /// Reserved for future use in public key exchange APIs.
    #[allow(dead_code)]
    p256_public_key: Vec<u8>,
    /// Channel receiver for relay requests from remote peers.
    /// Taken by node.rs run() to process relay requests via StateNodeService.
    relay_request_rx: tokio::sync::Mutex<Option<mpsc::Receiver<RelayRequest>>>,
    /// Content network repository for member verification on incoming requests.
    #[allow(dead_code)]
    content_network_repo: Option<
        Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
    >,
}

impl Libp2pNetwork {
    /// Create a new libp2p network with the given configuration.
    /// Load an Ed25519 keypair from disk, or generate a new one and save it.
    fn load_or_generate_peer_keypair(
        data_dir: &std::path::Path,
    ) -> Result<libp2p::identity::Keypair> {
        let key_path = data_dir.join("peer_key.ed25519");

        if key_path.exists() {
            let key_bytes =
                std::fs::read(&key_path).context("Failed to read peer keypair from disk")?;
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes(key_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to decode peer keypair: {:?}", e))?;
            info!("Loaded peer keypair from {}", key_path.display());
            Ok(keypair)
        } else {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            // Extract the raw Ed25519 secret key bytes for persistence
            if let Ok(ed25519_kp) = keypair.clone().try_into_ed25519() {
                let secret_bytes = ed25519_kp.secret().as_ref().to_vec();
                if let Some(parent) = key_path.parent() {
                    std::fs::create_dir_all(parent)
                        .context("Failed to create data directory for peer key")?;
                }
                std::fs::write(&key_path, &secret_bytes)
                    .context("Failed to write peer keypair to disk")?;
                info!(
                    "Generated and saved new peer keypair to {}",
                    key_path.display()
                );
            }
            Ok(keypair)
        }
    }

    /// Create a new libp2p network with the given configuration.
    pub async fn new(
        config: Libp2pNetworkConfig,
        crdt_repo: Arc<dyn ContentRepository>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        Self::with_content_network_repo(config, crdt_repo, data_dir, None).await
    }

    /// Create a new libp2p network with an optional content network repository
    /// for member verification on incoming PushOperations/FetchOperations requests.
    pub async fn with_content_network_repo(
        config: Libp2pNetworkConfig,
        crdt_repo: Arc<dyn ContentRepository>,
        data_dir: PathBuf,
        content_network_repo: Option<
            Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        >,
    ) -> Result<Self> {
        let keypair = Self::load_or_generate_peer_keypair(&data_dir)?;
        let local_peer_id = PeerId::from(keypair.public());

        // Load or generate P-256 key for node authentication
        use crate::infrastructure::key_management::NodeKeyPair;
        let p256_keypair = NodeKeyPair::load_or_generate(&data_dir.join("node_key.pem"))?;
        let p256_public_key = p256_keypair.public_key_bytes();
        let p256_signing_key = Arc::new(p256_keypair);

        info!("Local peer ID: {}", local_peer_id);

        // Build transport, and the relay client if NAT traversal is on.
        //
        // `relay::client::new` hands back a transport half and a behaviour
        // half that only work together: the transport is what actually dials
        // `/…/p2p-circuit/…`, the behaviour is what negotiates the reservation.
        // They are created here so both can be handed to their respective
        // owners.
        let (transport, relay_client) = if config.enable_nat_traversal {
            let (relay_transport, relay_behaviour) = libp2p::relay::client::new(local_peer_id);
            (
                transport::build_transport_with_relay(&keypair, relay_transport)
                    .context("Failed to build transport with relay client")?,
                Some(relay_behaviour),
            )
        } else {
            (
                transport::build_transport(&keypair).context("Failed to build transport")?,
                None,
            )
        };

        // Build behaviour
        // `enable_mdns` used to be ignored here: mDNS was always on, so a local
        // cluster could rediscover a moved peer by broadcast even when the
        // paths production relies on were broken. Honour the flag so local
        // runs can reproduce a deployment where mDNS does not exist.
        let behaviour = NodeBehaviour::new(
            local_peer_id,
            &keypair,
            BehaviourConfig {
                enable_mdns: config.enable_mdns,
                enable_nat_traversal: config.enable_nat_traversal,
                ..BehaviourConfig::default()
            },
            relay_client,
        )?;

        // Create swarm with connection limits to prevent FD/memory exhaustion (M-3).
        // idle_connection_timeout is set higher than the default sync_interval (30s)
        // to avoid excessive reconnection overhead (L-12).
        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(120));

        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, swarm_config);

        // Start listening on configured addresses
        for addr in &config.listen_addrs {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => info!("Listening on {}", addr),
                Err(e) => warn!("Failed to listen on {}: {}", addr, e),
            }
        }

        // Advertise externally reachable addresses (e.g. a public IP in
        // production). identify announces these to peers so remote nodes can
        // dial us even when our listen addresses are bound to 0.0.0.0 or sit
        // behind NAT. No-op for local/mDNS setups where this is empty.
        for addr in &config.external_addrs {
            swarm.add_external_address(addr.clone());
            info!("Advertising external address: {}", addr);
        }

        // Subscribe to gossipsub topics
        for topic_name in &config.gossipsub_topics {
            let topic = IdentTopic::new(topic_name);
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!("Failed to subscribe to topic {}: {:?}", topic_name, e);
            } else {
                info!("Subscribed to topic: {}", topic_name);
            }
        }

        // Add bootstrap nodes
        for (peer_id, addr) in &config.bootstrap_nodes {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
            // Kademlia alone does not reliably supply addresses to the
            // request-response behaviours (it only does so while the peer is
            // `Entry::Present` in a routing bucket). Make the address available
            // to every behaviour so request-response dials don't fail with
            // `DialError::NoAddresses`.
            swarm.add_peer_address(*peer_id, addr.clone());
            info!("Added bootstrap node: {} at {}", peer_id, addr);
        }

        // Bootstrap Kademlia if we have bootstrap nodes
        if !config.bootstrap_nodes.is_empty() {
            if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                warn!("Failed to bootstrap Kademlia: {:?}", e);
            }
        }

        let connected_peers = Arc::new(RwLock::new(HashMap::new()));
        let connected_peers_clone = connected_peers.clone();

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(256);

        // Create broadcast channel for received events
        let (event_tx, _) = broadcast::channel(256);
        let event_tx_clone = event_tx.clone();

        // Clone for swarm loop
        let crdt_repo_clone = crdt_repo.clone();
        let data_dir_clone = data_dir.clone();
        let p256_signing_key_clone = p256_signing_key.clone();

        // Create relay request channel
        let (relay_tx, relay_rx) = mpsc::channel::<RelayRequest>(64);

        // Spawn swarm event loop
        let relay_channels = RelayChannels {
            relay_tx,
            command_tx: command_tx.clone(),
        };
        let content_network_repo_clone = content_network_repo.clone();
        let bootstrap_nodes_clone = config.bootstrap_nodes.clone();
        tokio::spawn(Self::run_swarm_loop(
            swarm,
            command_rx,
            connected_peers_clone,
            event_tx_clone,
            crdt_repo_clone,
            data_dir_clone,
            p256_signing_key_clone,
            relay_channels,
            content_network_repo_clone,
            bootstrap_nodes_clone,
        ));

        Ok(Self {
            local_peer_id,
            command_tx,
            connected_peers,
            event_rx: event_tx,
            crdt_repo,
            data_dir,
            p256_public_key,
            relay_request_rx: tokio::sync::Mutex::new(Some(relay_rx)),
            content_network_repo,
        })
    }

    /// Subscribe to received Gossipsub events.
    ///
    /// Returns a receiver that will receive all domain events from other nodes.
    pub fn subscribe_events(&self) -> broadcast::Receiver<ReceivedEvent> {
        self.event_rx.subscribe()
    }

    /// Dial a peer at the given multiaddr.
    ///
    /// This initiates a connection to the peer.
    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::Dial {
                addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send dial command"))?;
        tokio::time::timeout(PEER_NETWORK_TIMEOUT, reply_rx)
            .await
            .map_err(|_| anyhow::anyhow!("dial timed out"))?
            .map_err(|_| anyhow::anyhow!("Dial response channel closed"))?
    }

    /// Take the relay request receiver.
    ///
    /// This can only be called once. Returns None on subsequent calls.
    /// Used by node.rs run() to process incoming relay requests.
    pub async fn take_relay_receiver(&self) -> Option<mpsc::Receiver<RelayRequest>> {
        self.relay_request_rx.lock().await.take()
    }

    /// Get the addresses this node is listening on (raw Multiaddr).
    pub async fn listen_addrs_raw(&self) -> Vec<Multiaddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .command_tx
            .send(SwarmCommand::GetListenAddrs { reply: reply_tx })
            .await
            .is_err()
        {
            return vec![];
        }
        reply_rx.await.unwrap_or_default()
    }

    /// Run the swarm event loop.
    #[allow(clippy::too_many_arguments)]
    async fn run_swarm_loop(
        mut swarm: Swarm<NodeBehaviour>,
        mut command_rx: mpsc::Receiver<SwarmCommand>,
        connected_peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        event_tx: broadcast::Sender<ReceivedEvent>,
        crdt_repo: Arc<dyn ContentRepository>,
        data_dir: PathBuf,
        p256_signing_key: Arc<crate::infrastructure::key_management::NodeKeyPair>,
        relay_channels: RelayChannels,
        content_network_repo: Option<
            Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        >,
        bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    ) {
        let mut pending = PendingRequests::default();
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Peers we have previously reached. Dialling these alongside the
        // configured bootstrap peers means the node can rejoin even when every
        // bootstrap address is down or has moved — the bootstrap list is an
        // entry point, not a dependency.
        let mut peer_store = PeerStore::load(&data_dir);
        if !peer_store.is_empty() {
            info!("Loaded {} known peer(s) from disk", peer_store.len());
            for (peer_id, addrs) in peer_store.iter() {
                for addr in addrs {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(peer_id, addr.clone());
                    swarm.add_peer_address(*peer_id, addr.clone());
                }
            }
        }
        let mut peer_store_dirty = false;
        let mut nat_state = NatState::default();

        // Periodically re-establish connectivity. Without this a node that
        // loses every connection stays isolated forever: `ConnectionClosed`
        // only forgets the peer, nothing ever dials again, and Kademlia is
        // only bootstrapped at startup and on identify. Combined with a
        // bootstrap address that had been frozen to a stale IP, that is what
        // left a whole deployment unable to reconverge.
        let mut peer_maintenance = tokio::time::interval(PEER_MAINTENANCE_INTERVAL);
        peer_maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick fires immediately; the startup dial already happened.
        peer_maintenance.tick().await;

        loop {
            tokio::select! {
                // Handle incoming commands
                Some(cmd) = command_rx.recv() => {
                    Self::handle_command(&mut swarm, &mut pending, cmd).await;
                }
                // Handle swarm events
                event = swarm.select_next_some() => {
                    // Remember peers we actually reached, before the event is
                    // consumed by the handler below.
                    if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } = &event {
                        if let Some(addr) = reusable_addr(endpoint) {
                            if peer_store.record(*peer_id, addr.clone()) {
                                peer_store_dirty = true;
                            }
                        }
                    }
                    Self::handle_swarm_event(&mut swarm, &mut pending, &connected_peers, &event_tx, &crdt_repo, &data_dir, &p256_signing_key, &relay_channels, &content_network_repo, &mut nat_state, event).await;
                }
                // Periodic cleanup of stale pending requests
                _ = cleanup_interval.tick() => {
                    pending.cleanup_stale();
                }
                // Periodic reconnection / re-bootstrap
                _ = peer_maintenance.tick() => {
                    Self::maintain_connectivity(&mut swarm, &connected_peers, &bootstrap_nodes, &peer_store).await;
                    // Flush at most once per tick rather than on every new
                    // address, so a busy node does not rewrite the file
                    // constantly.
                    if peer_store_dirty {
                        if let Err(e) = peer_store.save(&data_dir) {
                            warn!("Failed to persist peer store: {}", e);
                        } else {
                            peer_store_dirty = false;
                        }
                    }
                }
            }
        }
    }

    /// Record what AutoNAT concluded about our own reachability.
    ///
    /// This is the one place the public/private decision is made, and it is
    /// made from *measurement*: AutoNAT v2 asks other nodes to dial a specific
    /// address of ours back, and they answer only for addresses they actually
    /// reached. A node cannot talk itself into being considered reachable,
    /// which matters because the alternative — self-reported reachability —
    /// lets a node advertise relay service it cannot provide.
    async fn handle_autonat_client_event(
        swarm: &mut Swarm<NodeBehaviour>,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        nat_state: &mut NatState,
        event: libp2p::autonat::v2::client::Event,
    ) {
        let observed = if event.result.is_ok() {
            Reachability::Public
        } else {
            Reachability::Private
        };

        if nat_state.reachability == observed {
            return;
        }

        info!(
            "AutoNAT: reachability {:?} -> {:?} (tested {})",
            nat_state.reachability, observed, event.tested_addr
        );
        nat_state.reachability = observed;

        match observed {
            Reachability::Public => {
                // We can be dialled, so the address is worth announcing and
                // there is no reason to occupy someone else's relay slot.
                swarm.add_external_address(event.tested_addr.clone());
                Self::release_relay_reservations(swarm, nat_state);
            }
            Reachability::Private => {
                Self::ensure_relay_reservations(swarm, connected_peers, nat_state).await
            }
            Reachability::Unknown => {}
        }
    }

    /// Reserve a slot on connected relays so other nodes can reach us.
    ///
    /// Any connected peer may be asked: a relay is not a special kind of node,
    /// just one that happens to be reachable. Reservations are attempted with
    /// peers we are already connected to, since a peer we cannot dial cannot
    /// relay for us either.
    async fn ensure_relay_reservations(
        swarm: &mut Swarm<NodeBehaviour>,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        nat_state: &mut NatState,
    ) {
        if swarm.behaviour().relay_client.as_ref().is_none() {
            return;
        }

        // A circuit address must carry the relay's *dialable* address, not
        // just its peer id: the client transport rejects `/p2p/<id>/p2p-circuit`
        // with `MissingRelayAddr`, because it has to know where to open the
        // circuit. So candidates come from the connection table, which is
        // where the addresses we actually reached them on are recorded.
        let candidates: Vec<(PeerId, Multiaddr)> = connected_peers
            .read()
            .await
            .iter()
            .filter(|(p, _)| !nat_state.reserved_with.contains_key(p))
            .filter_map(|(p, addrs)| {
                addrs
                    .iter()
                    .find(|a| Self::is_relayable_addr(a))
                    .map(|a| (*p, a.clone()))
            })
            .collect();

        for (peer, addr) in candidates {
            if nat_state.reserved_with.len() >= TARGET_RELAY_RESERVATIONS {
                break;
            }
            // Listening on a circuit address is what actually requests the
            // reservation; the relay accepts or refuses, and a refusal simply
            // means this peer will not be one of our relays.
            let circuit = addr
                .with(libp2p::multiaddr::Protocol::P2p(peer))
                .with(libp2p::multiaddr::Protocol::P2pCircuit);
            match swarm.listen_on(circuit.clone()) {
                Ok(listener_id) => {
                    info!("Requesting relay reservation via {}", circuit);
                    nat_state.reserved_with.insert(peer, listener_id);
                }
                Err(e) => debug!("Cannot listen via relay {}: {}", peer, e),
            }
        }
    }

    /// Whether an address can serve as the relay hop of a circuit address.
    ///
    /// Excludes addresses that are already relayed (no circuits through
    /// circuits) and ones that only work from where we are standing — a relay
    /// has to be reachable by the *third* party we want to be reached by.
    fn is_relayable_addr(addr: &Multiaddr) -> bool {
        use libp2p::multiaddr::Protocol;
        let mut routable = true;
        for p in addr.iter() {
            match p {
                Protocol::P2pCircuit => return false,
                Protocol::Ip4(ip)
                    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() =>
                {
                    routable = false;
                }
                Protocol::Ip6(ip) if ip.is_loopback() || ip.is_unspecified() => {
                    routable = false;
                }
                _ => {}
            }
        }
        routable
    }

    /// Stop using relays once we know we are directly reachable.
    fn release_relay_reservations(swarm: &mut Swarm<NodeBehaviour>, nat_state: &mut NatState) {
        if nat_state.reserved_with.is_empty() {
            return;
        }
        info!(
            "Reachable directly; releasing {} relay reservation(s)",
            nat_state.reserved_with.len()
        );
        // Removing the circuit listener is what actually drops the
        // reservation, freeing the slot on a relay for a node that needs it.
        for (peer, listener_id) in nat_state.reserved_with.drain() {
            if swarm.remove_listener(listener_id) {
                debug!("Released relay reservation with {}", peer);
            }
        }
    }

    /// Re-dial bootstrap peers and re-run the Kademlia bootstrap when we are
    /// short on connections.
    ///
    /// Dialling a `/dns4/` bootstrap address re-resolves it, so a peer that
    /// came back at a different IP is picked up here. Dial errors are expected
    /// and harmless — the peer may simply still be down — so they are logged
    /// at debug level and retried on the next tick.
    async fn maintain_connectivity(
        swarm: &mut Swarm<NodeBehaviour>,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        bootstrap_nodes: &[(PeerId, Multiaddr)],
        peer_store: &PeerStore,
    ) {
        let connected: HashSet<PeerId> = connected_peers.read().await.keys().copied().collect();

        if connected.len() >= HEALTHY_PEER_COUNT {
            return;
        }

        debug!(
            "Connectivity maintenance: {} peer(s) connected, below {}",
            connected.len(),
            HEALTHY_PEER_COUNT
        );

        // Configured entry points first, then peers we have met before. The
        // latter is what lets a node recover when every bootstrap is down.
        let candidates = bootstrap_nodes.iter().map(|(p, a)| (p, a)).chain(
            peer_store
                .iter()
                .flat_map(|(p, addrs)| addrs.iter().map(move |a| (p, a))),
        );

        let mut dialled: HashSet<PeerId> = HashSet::new();
        for (peer_id, addr) in candidates {
            if swarm.local_peer_id() == peer_id
                || connected.contains(peer_id)
                || !dialled.insert(*peer_id)
            {
                continue;
            }
            // Refresh the address book first: for a DNS address this is what
            // lets a later dial pick up a changed IP.
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
            swarm.add_peer_address(*peer_id, addr.clone());

            match swarm.dial(addr.clone()) {
                Ok(()) => info!("Re-dialling peer {} at {}", peer_id, addr),
                Err(e) => debug!("Re-dial of {} at {} failed: {:?}", peer_id, addr, e),
            }
        }

        // Re-run the DHT bootstrap so routing buckets refill once a dial lands.
        // Errors here mean "no known peers to bootstrap from", which the dials
        // above are in the process of fixing.
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            debug!("Kademlia bootstrap during maintenance: {:?}", e);
        }
    }

    /// Handle a command from the main thread.
    async fn handle_command(
        swarm: &mut Swarm<NodeBehaviour>,
        pending: &mut PendingRequests,
        cmd: SwarmCommand,
    ) {
        match cmd {
            SwarmCommand::FindClosestPeers { key, k: _, reply } => {
                let query_id = swarm.behaviour_mut().kademlia.get_closest_peers(key);
                pending.kad_queries.insert(query_id, reply);
            }
            SwarmCommand::QueryCapacity { peer_id, reply } => {
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, ContentRequest::CapacityQuery);
                pending.capacity_queries.insert(request_id, reply);
            }
            SwarmCommand::PublishEvent { topic, data, reply } => {
                let topic = IdentTopic::new(&topic);
                let result = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, data)
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("Failed to publish: {:?}", e));
                let _ = reply.send(result);
            }
            SwarmCommand::FetchContent {
                peer_id,
                content_id,
                reply,
            } => {
                let request_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, ContentRequest::FetchContent { content_id });
                pending.content_fetches.insert(request_id, reply);
            }
            SwarmCommand::PublishProvider { key, reply } => {
                let key = kad::RecordKey::new(&key);
                let result = swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(key)
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("Failed to start providing: {:?}", e));
                let _ = reply.send(result);
            }
            SwarmCommand::Dial { addr, reply } => {
                let result = swarm
                    .dial(addr.clone())
                    .map_err(|e| anyhow::anyhow!("Failed to dial {}: {:?}", addr, e));
                let _ = reply.send(result);
            }
            SwarmCommand::GetListenAddrs { reply } => {
                let addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
                let _ = reply.send(addrs);
            }
            SwarmCommand::FetchOperations {
                peer_id,
                genesis_cid,
                since_version,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::FetchOperations {
                        genesis_cid,
                        since_version,
                    },
                );
                pending.operation_fetches.insert(request_id, reply);
            }
            SwarmCommand::PushOperations {
                peer_id,
                genesis_cid,
                operations,
                bootstrap,
                reply,
            } => {
                // Convert SerializedOperation to Vec<u8> for wire format
                let wire_ops: Vec<Vec<u8>> = operations
                    .iter()
                    .filter_map(|op| serde_json::to_vec(op).ok())
                    .collect();
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::PushOperations {
                        genesis_cid,
                        operations: wire_ops,
                        bootstrap,
                    },
                );
                pending.operation_pushes.insert(request_id, reply);
            }
            SwarmCommand::GetProviders { key, reply } => {
                let key = kad::RecordKey::new(&key);
                let query_id = swarm.behaviour_mut().kademlia.get_providers(key);
                pending.kad_provider_queries.insert(query_id, reply);
            }
            SwarmCommand::QueryPublicKeys {
                peer_id,
                node_ids,
                reply,
            } => {
                let request = PublicKeyRequest {
                    requesting_node: swarm.local_peer_id().to_string(),
                    requested_nodes: node_ids,
                };
                let request_id = swarm
                    .behaviour_mut()
                    .public_key_protocol
                    .send_request(&peer_id, request);
                pending.public_key_queries.insert(request_id, reply);
            }
            SwarmCommand::RelayUpdateContent {
                peer_id,
                content_id,
                data,
                auth_token,
                request_signature,
                timestamp,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::UpdateContent {
                        content_id,
                        data,
                        auth_token,
                        request_signature,
                        timestamp,
                    },
                );
                pending.relay_update_queries.insert(request_id, reply);
            }
            SwarmCommand::RelayDeleteContent {
                peer_id,
                content_id,
                auth_token,
                request_signature,
                timestamp,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::DeleteContent {
                        content_id,
                        auth_token,
                        request_signature,
                        timestamp,
                    },
                );
                pending.relay_delete_queries.insert(request_id, reply);
            }
            SwarmCommand::RelayInvalidateTokens {
                peer_id,
                content_id,
                auth_token,
                request_signature,
                timestamp,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::InvalidateTokens {
                        content_id,
                        auth_token,
                        request_signature,
                        timestamp,
                    },
                );
                pending
                    .relay_invalidate_tokens_queries
                    .insert(request_id, reply);
            }
            SwarmCommand::RelayReadContent {
                peer_id,
                content_id,
                version,
                auth_token,
                request_signature,
                timestamp,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::ReadContent {
                        content_id,
                        version,
                        auth_token,
                        request_signature,
                        timestamp,
                    },
                );
                pending.relay_read_queries.insert(request_id, reply);
            }
            SwarmCommand::RelayReadHistory {
                peer_id,
                content_id,
                auth_token,
                request_signature,
                timestamp,
                reply,
            } => {
                let request_id = swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    ContentRequest::ReadHistory {
                        content_id,
                        auth_token,
                        request_signature,
                        timestamp,
                    },
                );
                pending.relay_history_queries.insert(request_id, reply);
            }
            SwarmCommand::SendRelayResponse { channel, response } => {
                if let Err(e) = swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                {
                    error!("Failed to send relay response: {:?}", e);
                }
            }
        }
    }

    /// Handle a swarm event.
    #[allow(clippy::too_many_arguments)]
    async fn handle_swarm_event(
        swarm: &mut Swarm<NodeBehaviour>,
        pending: &mut PendingRequests,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        event_tx: &broadcast::Sender<ReceivedEvent>,
        crdt_repo: &Arc<dyn ContentRepository>,
        data_dir: &std::path::Path,
        p256_signing_key: &Arc<crate::infrastructure::key_management::NodeKeyPair>,
        relay_channels: &RelayChannels,
        content_network_repo: &Option<
            Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        >,
        nat_state: &mut NatState,
        event: SwarmEvent<NodeBehaviourEvent>,
    ) {
        match event {
            SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(kad_event)) => {
                Self::handle_kademlia_event(pending, kad_event).await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossip_event)) => {
                Self::handle_gossipsub_event(event_tx, *gossip_event).await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(rr_event)) => {
                Self::handle_request_response_event(
                    swarm,
                    pending,
                    crdt_repo,
                    data_dir,
                    relay_channels,
                    content_network_repo,
                    rr_event,
                )
                .await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::PublicKeyProtocol(pk_event)) => {
                Self::handle_public_key_protocol_event(swarm, pending, p256_signing_key, pk_event)
                    .await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify_event)) => {
                Self::handle_identify_event(swarm, *identify_event).await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::AutonatClient(ev)) => {
                Self::handle_autonat_client_event(swarm, connected_peers, nat_state, ev).await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Dcutr(ev)) => {
                // A successful upgrade means the pair is now talking directly
                // and the relay is out of the path — the outcome the whole
                // relay machinery exists to reach.
                match ev.result {
                    Ok(_) => info!("Hole punch to {} succeeded; now direct", ev.remote_peer_id),
                    Err(e) => debug!("Hole punch to {} failed: {}", ev.remote_peer_id, e),
                }
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::RelayClient(
                libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) => {
                info!(
                    "Relay reservation accepted by {}; reachable through it now",
                    relay_peer_id
                );
            }
            #[cfg(not(target_arch = "wasm32"))]
            SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns_event)) => {
                Self::handle_mdns_event(swarm, connected_peers, mdns_event).await;
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                connection_id,
                ..
            } => {
                let addr = endpoint.get_remote_address().clone();
                info!("Connection established with {} at {}", peer_id, addr);

                // Enforce connection limit (M-3): close excess connections to prevent
                // FD/memory exhaustion. Limit total unique peers to 256.
                const MAX_CONNECTED_PEERS: usize = 256;
                let mut peers = connected_peers.write().await;
                let peer_count = peers.len();
                if !peers.contains_key(&peer_id) && peer_count >= MAX_CONNECTED_PEERS {
                    warn!(
                        "Connection limit reached ({}/{}), closing connection to {}",
                        peer_count, MAX_CONNECTED_PEERS, peer_id
                    );
                    let _ = swarm.close_connection(connection_id);
                } else {
                    peers.entry(peer_id).or_insert_with(Vec::new).push(addr);
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Connection closed with {}", peer_id);
                connected_peers.write().await.remove(&peer_id);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }
            _ => {}
        }
    }

    async fn handle_kademlia_event(pending: &mut PendingRequests, event: kad::Event) {
        match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => {
                match result {
                    kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                        if let Some(reply) = pending.kad_queries.remove(&id) {
                            let _ =
                                reply.send(Ok(ok.peers.into_iter().map(|p| p.peer_id).collect()));
                        }
                    }
                    kad::QueryResult::GetClosestPeers(Err(e)) => {
                        if let Some(reply) = pending.kad_queries.remove(&id) {
                            let _ =
                                reply.send(Err(anyhow::anyhow!("Kademlia query failed: {:?}", e)));
                        }
                    }
                    kad::QueryResult::GetProviders(Ok(ok)) => {
                        match ok {
                            kad::GetProvidersOk::FoundProviders { providers, .. } => {
                                if let Some(reply) = pending.kad_provider_queries.remove(&id) {
                                    let providers: Vec<PeerId> = providers.into_iter().collect();
                                    let _ = reply.send(Ok(providers));
                                }
                            }
                            kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
                                // Query finished, send empty result if still pending
                                if let Some(reply) = pending.kad_provider_queries.remove(&id) {
                                    let _ = reply.send(Ok(vec![]));
                                }
                            }
                        }
                    }
                    kad::QueryResult::GetProviders(Err(e)) => {
                        if let Some(reply) = pending.kad_provider_queries.remove(&id) {
                            let _ =
                                reply.send(Err(anyhow::anyhow!("Provider query failed: {:?}", e)));
                        }
                    }
                    _ => {}
                }
            }
            kad::Event::RoutingUpdated { peer, .. } => {
                debug!("Kademlia routing updated for peer: {}", peer);
            }
            _ => {}
        }
    }

    async fn handle_gossipsub_event(
        event_tx: &broadcast::Sender<ReceivedEvent>,
        event: gossipsub::Event,
    ) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            } => {
                debug!(
                    "Received gossipsub message from {}: {} bytes",
                    propagation_source,
                    message.data.len()
                );

                // Try to deserialize as a domain Event
                match serde_json::from_slice::<Event>(&message.data) {
                    Ok(domain_event) => {
                        info!(
                            "Received domain event from {}: {:?}",
                            propagation_source,
                            domain_event.event_type()
                        );

                        // Bind to the authenticated publisher, not the peer
                        // that forwarded it to us — see `ReceivedEvent::source`.
                        let received = ReceivedEvent {
                            source: message.source.map(|p| p.to_string()),
                            event: domain_event,
                        };

                        // Broadcast to all subscribers
                        if let Err(e) = event_tx.send(received) {
                            debug!("No subscribers for received event: {}", e);
                        }
                    }
                    Err(e) => {
                        // Not a domain event, might be a CRDT operation or other message
                        debug!("Failed to deserialize gossipsub message as Event: {}", e);
                    }
                }
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                debug!("Peer {} subscribed to {}", peer_id, topic);
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                debug!("Peer {} unsubscribed from {}", peer_id, topic);
            }
            _ => {}
        }
    }

    async fn handle_request_response_event(
        swarm: &mut Swarm<NodeBehaviour>,
        pending: &mut PendingRequests,
        crdt_repo: &Arc<dyn ContentRepository>,
        data_dir: &std::path::Path,
        relay_channels: &RelayChannels,
        content_network_repo: &Option<
            Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        >,
        event: request_response::Event<ContentRequest, ContentResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    Self::handle_incoming_request(
                        swarm,
                        peer,
                        request,
                        channel,
                        crdt_repo,
                        data_dir,
                        relay_channels,
                        content_network_repo,
                    )
                    .await;
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    Self::handle_response(pending, request_id, response).await;
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                error!("Outbound request failed: {:?}", error);
                let err_msg = format!("Request failed: {:?}", error);
                // Clean up all pending request types to prevent resource leaks
                if let Some(reply) = pending.capacity_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.content_fetches.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.operation_fetches.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.operation_pushes.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.public_key_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.relay_update_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.relay_delete_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.relay_invalidate_tokens_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("{}", err_msg)));
                }
                if let Some(reply) = pending.relay_read_queries.remove(&request_id) {
                    let _ = reply.send(Err(RelayReadError::other(&err_msg)));
                }
                if let Some(reply) = pending.relay_history_queries.remove(&request_id) {
                    let _ = reply.send(Err(RelayReadError::other(&err_msg)));
                }
            }
            _ => {}
        }
    }

    /// Decide whether an incoming `PushOperations` request should be accepted,
    /// given the receiver's local state and the optional bootstrap payload.
    ///
    /// Returns `Ok(())` if the push should be accepted (may have persisted a
    /// new `ContentNetwork` as a side effect when bootstrapping) or `Err(msg)`
    /// with a human-readable rejection reason the caller can forward as a
    /// `ContentResponse::Error`.
    async fn validate_push_eligibility(
        repo: &Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        genesis_cid: &str,
        sender_peer: &str,
        local_peer: &str,
        bootstrap: Option<&PushBootstrap>,
    ) -> std::result::Result<(), String> {
        let existing = repo
            .read()
            .await
            .get_content_network(genesis_cid)
            .await
            .ok()
            .flatten();

        match (existing, bootstrap) {
            (Some(net), _) => {
                if net.has_member_str(sender_peer) {
                    Ok(())
                } else {
                    Err(format!(
                        "Peer {} is not a member of content network {}",
                        sender_peer, genesis_cid
                    ))
                }
            }
            (None, Some(bs)) => {
                // SECURITY: libp2p transport authenticates `sender_peer`, so
                // binding `sender_peer == bs.creator_node_id` stops creator
                // impersonation. Requiring that `local_peer` appear in
                // `member_nodes` stops a malicious peer from fabricating a
                // network on an unrelated victim node. This mirrors the
                // Gossipsub `ContentCreated` path, which binds the
                // authenticated publisher to the creator it claims; the
                // residual risk is the same — an authenticated creator can
                // still declare a member set of its choosing.
                if bs.creator_node_id != sender_peer {
                    return Err(format!(
                        "bootstrap creator_node_id {} does not match sender {}",
                        bs.creator_node_id, sender_peer
                    ));
                }
                if !bs.member_nodes.contains(&local_peer.to_string()) {
                    return Err(format!(
                        "local node {} is not in declared member set for {}",
                        local_peer, genesis_cid
                    ));
                }
                if bs.member_nodes.is_empty() {
                    return Err("bootstrap member_nodes is empty".to_string());
                }

                use crate::domain::content_network::ContentNetwork;
                use crate::domain::value_objects::{ContentId, NodeId};

                let content_id_vo = ContentId::new(genesis_cid.to_string())
                    .map_err(|e| format!("invalid genesis_cid: {}", e))?;
                let first_node = NodeId::from_string(bs.member_nodes[0].clone())
                    .map_err(|e| format!("invalid node_id in bootstrap: {}", e))?;
                let mut net = ContentNetwork::new(content_id_vo, first_node)
                    .map_err(|e| format!("failed to build ContentNetwork: {}", e))?;
                for extra in bs.member_nodes.iter().skip(1) {
                    let n = NodeId::from_string(extra.clone())
                        .map_err(|e| format!("invalid node_id in bootstrap: {}", e))?;
                    net.add_member(n);
                }
                repo.write()
                    .await
                    .save_content_network(net)
                    .await
                    .map_err(|e| format!("failed to persist bootstrapped network: {}", e))?;
                Ok(())
            }
            (None, None) => Err(format!(
                "unknown content network {} and no bootstrap provided",
                genesis_cid
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_incoming_request(
        swarm: &mut Swarm<NodeBehaviour>,
        peer: PeerId,
        request: ContentRequest,
        channel: ResponseChannel<ContentResponse>,
        crdt_repo: &Arc<dyn ContentRepository>,
        data_dir: &std::path::Path,
        relay_channels: &RelayChannels,
        content_network_repo: &Option<
            Arc<RwLock<dyn crate::port::persistence::PersistentContentRepository + Send + Sync>>,
        >,
    ) {
        debug!("Received request from {}: {:?}", peer, request);

        // For relay requests (UpdateContent, DeleteContent, InvalidateTokens), we spawn a
        // background task to avoid blocking the swarm loop. The relay handler may need
        // to send SwarmCommands (e.g. publish_event, query_capacity) which would deadlock
        // if the swarm loop is blocked waiting for the relay response.
        match request {
            ContentRequest::UpdateContent {
                content_id,
                data,
                auth_token,
                request_signature,
                timestamp,
            } => {
                info!(
                    "Received relayed UpdateContent for {} from {}",
                    content_id, peer
                );
                let channels = relay_channels.clone();
                tokio::spawn(async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let relay_req = RelayRequest {
                        kind: RelayRequestKind::UpdateContent {
                            content_id: content_id.clone(),
                            data,
                            auth_token,
                            request_signature,
                            timestamp,
                        },
                        reply: reply_tx,
                    };
                    let response = if channels.relay_tx.send(relay_req).await.is_ok() {
                        match reply_rx.await {
                            Ok(Ok(_)) => ContentResponse::UpdateResult {
                                content_id,
                                success: true,
                            },
                            Ok(Err(e)) => ContentResponse::Error {
                                message: format!("Relay update failed: {}", e),
                            },
                            Err(_) => ContentResponse::Error {
                                message: "Relay handler dropped".to_string(),
                            },
                        }
                    } else {
                        ContentResponse::Error {
                            message: "Relay channel closed".to_string(),
                        }
                    };
                    let _ = channels
                        .command_tx
                        .send(SwarmCommand::SendRelayResponse { channel, response })
                        .await;
                });
                return;
            }
            ContentRequest::DeleteContent {
                content_id,
                auth_token,
                request_signature,
                timestamp,
            } => {
                info!(
                    "Received relayed DeleteContent for {} from {}",
                    content_id, peer
                );
                let channels = relay_channels.clone();
                tokio::spawn(async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let relay_req = RelayRequest {
                        kind: RelayRequestKind::DeleteContent {
                            content_id: content_id.clone(),
                            auth_token,
                            request_signature,
                            timestamp,
                        },
                        reply: reply_tx,
                    };
                    let response = if channels.relay_tx.send(relay_req).await.is_ok() {
                        match reply_rx.await {
                            Ok(Ok(_)) => ContentResponse::DeleteResult {
                                content_id,
                                success: true,
                            },
                            Ok(Err(e)) => ContentResponse::Error {
                                message: format!("Relay delete failed: {}", e),
                            },
                            Err(_) => ContentResponse::Error {
                                message: "Relay handler dropped".to_string(),
                            },
                        }
                    } else {
                        ContentResponse::Error {
                            message: "Relay channel closed".to_string(),
                        }
                    };
                    let _ = channels
                        .command_tx
                        .send(SwarmCommand::SendRelayResponse { channel, response })
                        .await;
                });
                return;
            }
            ContentRequest::InvalidateTokens {
                content_id,
                auth_token,
                request_signature,
                timestamp,
            } => {
                info!(
                    "Received relayed InvalidateTokens for {} from {}",
                    content_id, peer
                );
                let channels = relay_channels.clone();
                tokio::spawn(async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let relay_req = RelayRequest {
                        kind: RelayRequestKind::InvalidateTokens {
                            content_id: content_id.clone(),
                            auth_token,
                            request_signature,
                            timestamp,
                        },
                        reply: reply_tx,
                    };
                    let response = if channels.relay_tx.send(relay_req).await.is_ok() {
                        match reply_rx.await {
                            Ok(Ok(_)) => ContentResponse::InvalidateTokensResult {
                                content_id,
                                success: true,
                            },
                            Ok(Err(e)) => ContentResponse::Error {
                                message: format!("Relay invalidate_tokens failed: {}", e),
                            },
                            Err(_) => ContentResponse::Error {
                                message: "Relay handler dropped".to_string(),
                            },
                        }
                    } else {
                        ContentResponse::Error {
                            message: "Relay channel closed".to_string(),
                        }
                    };
                    let _ = channels
                        .command_tx
                        .send(SwarmCommand::SendRelayResponse { channel, response })
                        .await;
                });
                return;
            }
            ContentRequest::ReadContent {
                content_id,
                version,
                auth_token,
                request_signature,
                timestamp,
            } => {
                info!(
                    "Received relayed ReadContent for {} from {}",
                    content_id, peer
                );
                let channels = relay_channels.clone();
                tokio::spawn(async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let relay_req = RelayRequest {
                        kind: RelayRequestKind::ReadContent {
                            content_id: content_id.clone(),
                            version,
                            auth_token,
                            request_signature,
                            timestamp,
                        },
                        reply: reply_tx,
                    };
                    let response = if channels.relay_tx.send(relay_req).await.is_ok() {
                        match reply_rx.await {
                            Ok(Ok(RelayOutcome::Data { data, version })) => {
                                ContentResponse::ContentData {
                                    content_id,
                                    data,
                                    version,
                                }
                            }
                            Ok(Ok(_)) => ContentResponse::Error {
                                message: "Unexpected relay outcome for ReadContent".to_string(),
                            },
                            Ok(Err(e)) => ContentResponse::ReadFailed {
                                content_id,
                                kind: relay_read_error_kind(&e),
                                message: e.to_string(),
                            },
                            Err(_) => ContentResponse::Error {
                                message: "Relay handler dropped".to_string(),
                            },
                        }
                    } else {
                        ContentResponse::Error {
                            message: "Relay channel closed".to_string(),
                        }
                    };
                    let _ = channels
                        .command_tx
                        .send(SwarmCommand::SendRelayResponse { channel, response })
                        .await;
                });
                return;
            }
            ContentRequest::ReadHistory {
                content_id,
                auth_token,
                request_signature,
                timestamp,
            } => {
                info!(
                    "Received relayed ReadHistory for {} from {}",
                    content_id, peer
                );
                let channels = relay_channels.clone();
                tokio::spawn(async move {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let relay_req = RelayRequest {
                        kind: RelayRequestKind::ReadHistory {
                            content_id: content_id.clone(),
                            auth_token,
                            request_signature,
                            timestamp,
                        },
                        reply: reply_tx,
                    };
                    let response = if channels.relay_tx.send(relay_req).await.is_ok() {
                        match reply_rx.await {
                            Ok(Ok(RelayOutcome::History { versions })) => {
                                ContentResponse::HistoryData {
                                    content_id,
                                    versions,
                                }
                            }
                            Ok(Ok(_)) => ContentResponse::Error {
                                message: "Unexpected relay outcome for ReadHistory".to_string(),
                            },
                            Ok(Err(e)) => ContentResponse::ReadFailed {
                                content_id,
                                kind: relay_read_error_kind(&e),
                                message: e.to_string(),
                            },
                            Err(_) => ContentResponse::Error {
                                message: "Relay handler dropped".to_string(),
                            },
                        }
                    } else {
                        ContentResponse::Error {
                            message: "Relay channel closed".to_string(),
                        }
                    };
                    let _ = channels
                        .command_tx
                        .send(SwarmCommand::SendRelayResponse { channel, response })
                        .await;
                });
                return;
            }
            _ => {}
        }

        // Non-relay requests: handle synchronously in the swarm loop
        let response = match request {
            ContentRequest::CapacityQuery => match disk_capacity::get_disk_capacity(data_dir) {
                Ok((total, available)) => ContentResponse::CapacityResponse {
                    total_capacity: total,
                    available_capacity: available,
                },
                Err(e) => ContentResponse::Error {
                    message: format!("Failed to get disk capacity: {}", e),
                },
            },
            ContentRequest::FetchContent { content_id } => {
                match crdt_repo.get_latest_with_version(&content_id).await {
                    Ok(Some((data, version))) => ContentResponse::ContentData {
                        content_id,
                        data,
                        version,
                    },
                    Ok(None) => ContentResponse::NotFound { content_id },
                    Err(e) => ContentResponse::Error {
                        message: format!("Failed to fetch content: {}", e),
                    },
                }
            }
            ContentRequest::SyncContent { content_id, .. } => {
                // SyncContent returns the same as FetchContent (latest data)
                match crdt_repo.get_latest_with_version(&content_id).await {
                    Ok(Some((data, version))) => ContentResponse::ContentData {
                        content_id,
                        data,
                        version,
                    },
                    Ok(None) => ContentResponse::NotFound { content_id },
                    Err(e) => ContentResponse::Error {
                        message: format!("Failed to sync content: {}", e),
                    },
                }
            }
            ContentRequest::FetchOperations {
                genesis_cid,
                since_version,
            } => {
                // Verify peer is a member of the content network
                if let Some(repo) = content_network_repo {
                    let is_member = repo
                        .read()
                        .await
                        .get_content_network(&genesis_cid)
                        .await
                        .ok()
                        .flatten()
                        .map(|net| net.has_member_str(&peer.to_string()))
                        .unwrap_or(false);
                    if !is_member {
                        ContentResponse::Error {
                            message: format!(
                                "Peer {} is not a member of content network {}",
                                peer, genesis_cid
                            ),
                        }
                    } else {
                        match crdt_repo
                            .get_operations(&genesis_cid, since_version.as_deref())
                            .await
                        {
                            Ok(ops) => {
                                let operations: Vec<Vec<u8>> = ops
                                    .iter()
                                    .filter_map(|op| serde_json::to_vec(op).ok())
                                    .collect();
                                ContentResponse::OperationsData {
                                    genesis_cid,
                                    operations,
                                }
                            }
                            Err(e) => ContentResponse::Error {
                                message: format!("Failed to fetch operations: {}", e),
                            },
                        }
                    }
                } else {
                    match crdt_repo
                        .get_operations(&genesis_cid, since_version.as_deref())
                        .await
                    {
                        Ok(ops) => {
                            let operations: Vec<Vec<u8>> = ops
                                .iter()
                                .filter_map(|op| serde_json::to_vec(op).ok())
                                .collect();
                            ContentResponse::OperationsData {
                                genesis_cid,
                                operations,
                            }
                        }
                        Err(e) => ContentResponse::Error {
                            message: format!("Failed to fetch operations: {}", e),
                        },
                    }
                }
            }
            ContentRequest::PushOperations {
                genesis_cid,
                operations,
                bootstrap,
            } => {
                // The receiver decides whether to accept this push. Cases:
                //   1. Local ContentNetwork exists for this genesis: sender must
                //      be a known member. `bootstrap` is ignored to prevent a
                //      member from rewriting the member set.
                //   2. No local record AND bootstrap present: accept if the sender
                //      is the claimed creator and we're in the declared member
                //      set, then persist the ContentNetwork inline.
                //   3. No local record AND no bootstrap: reject (unknown network).
                //   4. `content_network_repo` is None (some test configurations):
                //      fall through to apply_operations — legacy behavior.
                if let Some(repo) = content_network_repo {
                    let local_id = swarm.local_peer_id().to_string();
                    let validation = Self::validate_push_eligibility(
                        repo,
                        &genesis_cid,
                        &peer.to_string(),
                        &local_id,
                        bootstrap.as_ref(),
                    )
                    .await;

                    if let Err(reason) = validation {
                        let response = ContentResponse::Error { message: reason };
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response)
                        {
                            error!("Failed to send response: {:?}", e);
                        }
                        return;
                    }
                }

                // Reject oversized payloads (max 16 MiB total)
                const MAX_PUSH_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
                let total_size: usize = operations.iter().map(|op| op.len()).sum();
                if total_size > MAX_PUSH_PAYLOAD_BYTES {
                    let response = ContentResponse::Error {
                        message: format!(
                            "Push payload too large: {} bytes (max {})",
                            total_size, MAX_PUSH_PAYLOAD_BYTES
                        ),
                    };
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response)
                    {
                        error!("Failed to send response: {:?}", e);
                    }
                    return;
                }

                // Deserialize operations from wire format
                let ops: Vec<SerializedOperation> = operations
                    .iter()
                    .filter_map(|bytes| serde_json::from_slice(bytes).ok())
                    .collect();

                match crdt_repo.apply_operations(&ops).await {
                    Ok(count) => ContentResponse::PushResult {
                        genesis_cid,
                        accepted_count: count,
                    },
                    Err(e) => ContentResponse::Error {
                        message: format!("Failed to apply operations: {}", e),
                    },
                }
            }
            // Relay variants already handled above and returned early
            ContentRequest::UpdateContent { .. }
            | ContentRequest::DeleteContent { .. }
            | ContentRequest::InvalidateTokens { .. }
            | ContentRequest::ReadContent { .. }
            | ContentRequest::ReadHistory { .. } => unreachable!(),
        };

        if let Err(e) = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, response)
        {
            error!("Failed to send response: {:?}", e);
        }
    }

    async fn handle_response(
        pending: &mut PendingRequests,
        request_id: OutboundRequestId,
        response: ContentResponse,
    ) {
        // Handle capacity query response
        if let Some(reply) = pending.capacity_queries.remove(&request_id) {
            match response {
                ContentResponse::CapacityResponse {
                    total_capacity,
                    available_capacity,
                } => {
                    let _ = reply.send(Ok((total_capacity, available_capacity)));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Capacity query error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle content fetch response
        if let Some(reply) = pending.content_fetches.remove(&request_id) {
            match response {
                ContentResponse::ContentData { data, .. } => {
                    let _ = reply.send(Ok(data));
                }
                ContentResponse::NotFound { content_id } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Content not found: {}", content_id)));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Fetch error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle operation fetch response
        if let Some(reply) = pending.operation_fetches.remove(&request_id) {
            match response {
                ContentResponse::OperationsData {
                    operations,
                    genesis_cid: _,
                } => {
                    // Deserialize operations from wire format
                    let ops: Vec<SerializedOperation> = operations
                        .iter()
                        .filter_map(|bytes| serde_json::from_slice(bytes).ok())
                        .collect();
                    let _ = reply.send(Ok(ops));
                }
                ContentResponse::NotFound { content_id } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Content not found: {}", content_id)));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Fetch operations error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle operation push response
        if let Some(reply) = pending.operation_pushes.remove(&request_id) {
            match response {
                ContentResponse::PushResult { accepted_count, .. } => {
                    let _ = reply.send(Ok(accepted_count));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Push operations error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle relay update response
        if let Some(reply) = pending.relay_update_queries.remove(&request_id) {
            match response {
                ContentResponse::UpdateResult { success, .. } => {
                    let _ = reply.send(Ok(success));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Relay update error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle relay delete response
        if let Some(reply) = pending.relay_delete_queries.remove(&request_id) {
            match response {
                ContentResponse::DeleteResult { success, .. } => {
                    let _ = reply.send(Ok(success));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!("Relay delete error: {}", message)));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle relay invalidate_tokens response
        if let Some(reply) = pending.relay_invalidate_tokens_queries.remove(&request_id) {
            match response {
                ContentResponse::InvalidateTokensResult { success, .. } => {
                    let _ = reply.send(Ok(success));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "Relay invalidate_tokens error: {}",
                        message
                    )));
                }
                _ => {
                    let _ = reply.send(Err(anyhow::anyhow!("Unexpected response type")));
                }
            }
            return;
        }

        // Handle relay read (data) response
        if let Some(reply) = pending.relay_read_queries.remove(&request_id) {
            match response {
                ContentResponse::ContentData { data, version, .. } => {
                    let _ = reply.send(Ok((data, version)));
                }
                ContentResponse::ReadFailed { kind, message, .. } => {
                    let _ = reply.send(Err(RelayReadError { kind, message }));
                }
                ContentResponse::NotFound { content_id } => {
                    let _ = reply.send(Err(RelayReadError {
                        kind: RelayReadErrorKind::NotFound,
                        message: format!("Content not found: {}", content_id),
                    }));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(RelayReadError::other(format!(
                        "Relay read error: {}",
                        message
                    ))));
                }
                _ => {
                    let _ = reply.send(Err(RelayReadError::other("Unexpected response type")));
                }
            }
            return;
        }

        // Handle relay read (history) response
        if let Some(reply) = pending.relay_history_queries.remove(&request_id) {
            match response {
                ContentResponse::HistoryData { versions, .. } => {
                    let _ = reply.send(Ok(versions));
                }
                ContentResponse::ReadFailed { kind, message, .. } => {
                    let _ = reply.send(Err(RelayReadError { kind, message }));
                }
                ContentResponse::NotFound { content_id } => {
                    let _ = reply.send(Err(RelayReadError {
                        kind: RelayReadErrorKind::NotFound,
                        message: format!("Content not found: {}", content_id),
                    }));
                }
                ContentResponse::Error { message } => {
                    let _ = reply.send(Err(RelayReadError::other(format!(
                        "Relay read error: {}",
                        message
                    ))));
                }
                _ => {
                    let _ = reply.send(Err(RelayReadError::other("Unexpected response type")));
                }
            }
        }
    }

    async fn handle_public_key_protocol_event(
        swarm: &mut Swarm<NodeBehaviour>,
        pending: &mut PendingRequests,
        p256_signing_key: &Arc<crate::infrastructure::key_management::NodeKeyPair>,
        event: request_response::Event<PublicKeyRequest, PublicKeyResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // Handle incoming public key request
                    debug!("Received public key request from {}: {:?}", peer, request);

                    // Create response with our public key
                    let mut public_keys = Vec::new();

                    // If no specific nodes requested, return our own key
                    if request.requested_nodes.is_empty() {
                        // Get our NodeId
                        let node_id = p256_signing_key
                            .node_id()
                            .map(|id| id.as_str().to_string())
                            .unwrap_or_else(|_| swarm.local_peer_id().to_string());

                        // Create signed public key proof
                        if let Ok(node_key) = NodePublicKey::new(
                            node_id,
                            p256_signing_key.public_key_bytes(),
                            p256_signing_key.signing_key(),
                        ) {
                            public_keys.push(node_key);
                        }
                    } else {
                        // If specific nodes requested, return our key if we're in the list
                        // Check both our NodeId and PeerId since tests may use either
                        let our_node_id = p256_signing_key
                            .node_id()
                            .map(|id| id.as_str().to_string())
                            .unwrap_or_else(|_| swarm.local_peer_id().to_string());

                        let our_peer_id = swarm.local_peer_id().to_string();

                        // Check if either our NodeId or PeerId is in the requested list
                        if request.requested_nodes.contains(&our_node_id)
                            || request.requested_nodes.contains(&our_peer_id)
                        {
                            // Return key with our NodeId (even if queried by PeerId)
                            if let Ok(node_key) = NodePublicKey::new(
                                our_node_id,
                                p256_signing_key.public_key_bytes(),
                                p256_signing_key.signing_key(),
                            ) {
                                public_keys.push(node_key);
                            }
                        }
                    }

                    let response = PublicKeyResponse { public_keys };

                    if let Err(e) = swarm
                        .behaviour_mut()
                        .public_key_protocol
                        .send_response(channel, response)
                    {
                        error!("Failed to send public key response: {:?}", e);
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    // Handle response to our public key request
                    if let Some(reply) = pending.public_key_queries.remove(&request_id) {
                        // Verify all received public keys
                        let mut verified_keys = Vec::new();
                        for key in response.public_keys {
                            match key.verify() {
                                Ok(_) => {
                                    info!("Verified public key for node {}", key.node_id);
                                    verified_keys.push(key);
                                }
                                Err(e) => {
                                    warn!("Failed to verify public key for {}: {}", key.node_id, e);
                                }
                            }
                        }
                        let _ = reply.send(Ok(verified_keys));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                error!("Public key request failed: {:?}", error);
                if let Some(reply) = pending.public_key_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "Public key request failed: {:?}",
                        error
                    )));
                }
            }
            _ => {}
        }
    }

    async fn handle_identify_event(swarm: &mut Swarm<NodeBehaviour>, event: identify::Event) {
        if let identify::Event::Received { peer_id, info, .. } = event {
            info!(
                "Identified peer {}: {} with {} addresses",
                peer_id,
                info.agent_version,
                info.listen_addrs.len()
            );
            // Add peer's addresses to Kademlia, and also make them available to
            // every behaviour (notably request-response) via the swarm's peer
            // address book. Without this, request-response dials can fail with
            // `DialError::NoAddresses` even though Kademlia knows the peer.
            for addr in &info.listen_addrs {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
                swarm.add_peer_address(peer_id, addr.clone());
            }

            // Try to bootstrap Kademlia now that we have a peer
            // This is important for the first node to populate its routing table
            if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                debug!("Kademlia bootstrap attempt: {:?}", e);
            } else {
                info!(
                    "Triggered Kademlia bootstrap after identifying peer {}",
                    peer_id
                );
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_mdns_event(
        swarm: &mut Swarm<NodeBehaviour>,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        event: libp2p::mdns::Event,
    ) {
        match event {
            libp2p::mdns::Event::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    info!("mDNS discovered peer {} at {}", peer_id, addr);
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    // Also publish to the swarm-wide peer address book so the
                    // request-response behaviours can dial this peer (Kademlia
                    // alone is not a reliable address source for them).
                    swarm.add_peer_address(peer_id, addr.clone());
                    connected_peers
                        .write()
                        .await
                        .entry(peer_id)
                        .or_insert_with(Vec::new)
                        .push(addr);
                }
            }
            libp2p::mdns::Event::Expired(peers) => {
                for (peer_id, addr) in peers {
                    debug!("mDNS peer expired: {} at {}", peer_id, addr);
                }
            }
        }
    }
}

impl Libp2pNetwork {
    async fn send_push_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
        bootstrap: Option<PushBootstrap>,
    ) -> Result<usize> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::PushOperations {
                peer_id,
                genesis_cid: genesis_cid.to_string(),
                operations: operations.to_vec(),
                bootstrap,
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("push_operations timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }
}

#[async_trait]
impl PeerNetwork for Libp2pNetwork {
    async fn find_closest_peers(&self, key: Vec<u8>, k: usize) -> Result<Vec<String>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::FindClosestPeers { key, k, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        let peers = tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("find_closest_peers timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))??;
        Ok(peers.into_iter().map(|p| p.to_string()).collect())
    }

    async fn query_node_capacity_batch(&self, peer_ids: &[String]) -> Result<HashMap<String, u64>> {
        let mut results = HashMap::new();

        for peer_id_str in peer_ids {
            let peer_id = match PeerId::from_str(peer_id_str) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let (tx, rx) = oneshot::channel();
            if self
                .command_tx
                .send(SwarmCommand::QueryCapacity { peer_id, reply: tx })
                .await
                .is_err()
            {
                continue;
            }

            if let Ok(Ok(Ok((_, available)))) = tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx).await
            {
                results.insert(peer_id_str.clone(), available);
            }
        }

        Ok(results)
    }

    async fn query_node_public_keys_batch(
        &self,
        peer_ids: &[String],
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut results = HashMap::new();

        // For each NodeId, we need to find which peer to query
        // This is a challenge because NodeId != PeerId
        // For now, we'll query our connected peers to ask about these NodeIds

        // First, get list of connected peers
        let (tx, _rx) = oneshot::channel();
        if self
            .command_tx
            .send(SwarmCommand::GetListenAddrs { reply: tx })
            .await
            .is_err()
        {
            return Ok(results);
        }

        // Query each connected peer for the public keys
        // In a real system, we'd have a DHT mapping NodeId -> PeerId
        // For now, we'll use a broadcast-like approach

        for node_id_str in peer_ids {
            // Try to parse as PeerId first (for testing)
            if let Ok(peer_id) = PeerId::from_str(node_id_str) {
                let (tx, rx) = oneshot::channel();
                if self
                    .command_tx
                    .send(SwarmCommand::QueryPublicKeys {
                        peer_id,
                        node_ids: vec![node_id_str.clone()],
                        reply: tx,
                    })
                    .await
                    .is_ok()
                {
                    if let Ok(Ok(Ok(keys))) = tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx).await {
                        // The returned key might have a different node_id (e.g., the actual NodeId)
                        // than what we requested (e.g., a PeerId), but we should still store it
                        // indexed by what was requested
                        if !keys.is_empty() {
                            // Take the first matching key (there should only be one for a specific peer)
                            results.insert(node_id_str.clone(), keys[0].public_key.clone());
                        }
                    }
                }
            }

            // If we didn't get a key, skip it
            if !results.contains_key(node_id_str) {
                warn!("Could not query public key for {}", node_id_str);
            }
        }

        Ok(results)
    }

    async fn publish_event(&self, topic: &str, event_data: &[u8]) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::PublishEvent {
                topic: topic.to_string(),
                data: event_data.to_vec(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("publish_event timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn fetch_content(&self, peer_id: &str, content_id: &str) -> Result<Vec<u8>> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::FetchContent {
                peer_id,
                content_id: content_id.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("fetch_content timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn publish_provider(&self, key: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::PublishProvider { key, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("publish_provider timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    fn local_peer_id(&self) -> String {
        self.local_peer_id.to_string()
    }

    async fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs_raw()
            .await
            .into_iter()
            .map(|a| a.to_string())
            .collect()
    }

    async fn fetch_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::FetchOperations {
                peer_id,
                genesis_cid: genesis_cid.to_string(),
                since_version: since_version.map(String::from),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("fetch_operations timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn push_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
    ) -> Result<usize> {
        self.send_push_operations(peer_id, genesis_cid, operations, None)
            .await
    }

    async fn push_operations_with_bootstrap(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
        bootstrap: PushBootstrap,
    ) -> Result<usize> {
        self.send_push_operations(peer_id, genesis_cid, operations, Some(bootstrap))
            .await
    }

    async fn broadcast_operation(
        &self,
        genesis_cid: &str,
        operation: &SerializedOperation,
    ) -> Result<()> {
        // Create a broadcast message containing the operation
        let broadcast_msg = serde_json::json!({
            "type": "crdt_operation",
            "genesis_cid": genesis_cid,
            "operation": operation,
        });
        let data = serde_json::to_vec(&broadcast_msg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize broadcast: {}", e))?;

        // Publish to the monas-events topic
        self.publish_event("monas-events", &data).await
    }

    async fn find_content_providers(&self, genesis_cid: &str) -> Result<Vec<String>> {
        let key = genesis_cid.as_bytes().to_vec();
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::GetProviders { key, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        let peers = tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("find_content_providers timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))??;
        Ok(peers.into_iter().map(|p| p.to_string()).collect())
    }

    async fn relay_update_content(
        &self,
        peer_id: &str,
        content_id: &str,
        data: &[u8],
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::RelayUpdateContent {
                peer_id,
                content_id: content_id.to_string(),
                data: data.to_vec(),
                auth_token: auth_token.to_string(),
                request_signature: request_signature.to_vec(),
                timestamp,
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("relay_update_content timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn relay_delete_content(
        &self,
        peer_id: &str,
        content_id: &str,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::RelayDeleteContent {
                peer_id,
                content_id: content_id.to_string(),
                auth_token: auth_token.to_string(),
                request_signature: request_signature.to_vec(),
                timestamp,
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("relay_delete_content timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn relay_invalidate_tokens(
        &self,
        peer_id: &str,
        content_id: &str,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> Result<bool> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::RelayInvalidateTokens {
                peer_id,
                content_id: content_id.to_string(),
                auth_token: auth_token.to_string(),
                request_signature: request_signature.to_vec(),
                timestamp,
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow::anyhow!("relay_invalidate_tokens timed out"))?
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn relay_read_content(
        &self,
        peer_id: &str,
        content_id: &str,
        version: Option<&str>,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> std::result::Result<(Vec<u8>, String), RelayReadError> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| RelayReadError::other(format!("Invalid peer ID: {}", peer_id)))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::RelayReadContent {
                peer_id,
                content_id: content_id.to_string(),
                version: version.map(ToOwned::to_owned),
                auth_token: auth_token.to_string(),
                request_signature: request_signature.to_vec(),
                timestamp,
                reply: tx,
            })
            .await
            .map_err(|_| RelayReadError::other("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| RelayReadError::other("relay_read_content timed out"))?
            .map_err(|_| RelayReadError::other("Failed to receive response"))?
    }

    async fn relay_read_history(
        &self,
        peer_id: &str,
        content_id: &str,
        auth_token: &str,
        request_signature: &[u8],
        timestamp: Option<u64>,
    ) -> std::result::Result<Vec<String>, RelayReadError> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| RelayReadError::other(format!("Invalid peer ID: {}", peer_id)))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::RelayReadHistory {
                peer_id,
                content_id: content_id.to_string(),
                auth_token: auth_token.to_string(),
                request_signature: request_signature.to_vec(),
                timestamp,
                reply: tx,
            })
            .await
            .map_err(|_| RelayReadError::other("Failed to send command"))?;

        tokio::time::timeout(PEER_NETWORK_TIMEOUT, rx)
            .await
            .map_err(|_| RelayReadError::other("relay_read_history timed out"))?
            .map_err(|_| RelayReadError::other("Failed to receive response"))?
    }

    async fn connected_peer_count(&self) -> usize {
        self.connected_peers.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crdt_repository::CrslCrdtRepository;
    use tempfile::tempdir;

    /// An inbound connection must never be remembered.
    ///
    /// `send_back_addr` is the peer's ephemeral source port, not its listen
    /// port — measured on a real pair of swarms, a node listening on
    /// `/tcp/62417` sees its peer as `/tcp/62418`. Recording that fills the
    /// store with addresses nothing can dial, and evicts the good one.
    #[test]
    fn only_outbound_connections_yield_a_reusable_address() {
        let listen: Multiaddr = "/ip4/10.0.1.60/tcp/9001".parse().unwrap();
        let ephemeral: Multiaddr = "/ip4/10.0.1.60/tcp/62418".parse().unwrap();

        let outbound = ConnectedPoint::Dialer {
            address: listen.clone(),
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::Reuse,
        };
        assert_eq!(reusable_addr(&outbound), Some(&listen));

        let inbound = ConnectedPoint::Listener {
            local_addr: "/ip4/10.0.1.61/tcp/9001".parse().unwrap(),
            send_back_addr: ephemeral,
        };
        assert_eq!(
            reusable_addr(&inbound),
            None,
            "inbound send_back_addr is an ephemeral port and must not be stored"
        );
    }

    /// Build a swarm with NAT traversal on, matching how the real one is
    /// assembled (relay transport and behaviour created as a pair).
    fn nat_swarm() -> Swarm<NodeBehaviour> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let (relay_transport, relay_client) = libp2p::relay::client::new(peer_id);
        let transport =
            super::super::transport::build_transport_with_relay(&keypair, relay_transport).unwrap();
        let behaviour = NodeBehaviour::new(
            peer_id,
            &keypair,
            BehaviourConfig {
                enable_mdns: false,
                ..BehaviourConfig::default()
            },
            Some(relay_client),
        )
        .unwrap();
        Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        )
    }

    /// Build the circuit address a reservation listens on.
    ///
    /// The relay's dialable address has to be in there, not just its peer id:
    /// `/p2p/<id>/p2p-circuit` is rejected by the client transport with
    /// `MissingRelayAddr`, since it would not know where to open the circuit.
    fn circuit_addr(relay: PeerId) -> Multiaddr {
        "/ip4/192.0.2.10/tcp/9001"
            .parse::<Multiaddr>()
            .unwrap()
            .with(libp2p::multiaddr::Protocol::P2p(relay))
            .with(libp2p::multiaddr::Protocol::P2pCircuit)
    }

    /// A circuit address must be accepted by the relay client transport.
    ///
    /// `listen_on` is where the shape of the address is validated, and it is
    /// the step the first implementation got wrong: it built
    /// `/p2p/<relay>/p2p-circuit` from the peer id alone, which every relay
    /// client rejects with `MissingRelayAddr` because it does not say where to
    /// open the circuit. Reservations would have failed on every attempt.
    #[tokio::test]
    async fn a_circuit_address_needs_the_relay_address_not_just_its_peer_id() {
        let mut swarm = nat_swarm();
        let relay_peer = PeerId::random();

        // What the implementation builds now: relay address + peer id.
        assert!(
            swarm.listen_on(circuit_addr(relay_peer)).is_ok(),
            "a circuit address carrying the relay's address must be accepted"
        );

        // What it built before — rejected, so no reservation was ever made.
        let peer_id_only = Multiaddr::empty()
            .with(libp2p::multiaddr::Protocol::P2p(relay_peer))
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        assert!(
            swarm.listen_on(peer_id_only).is_err(),
            "a circuit address without the relay's address must be rejected"
        );
    }

    /// `ensure_relay_reservations` must produce a circuit address the relay
    /// client accepts, and must skip peers whose only known address is one a
    /// third party could not dial.
    ///
    /// This exercises the implementation, unlike the address-shape test above:
    /// building the circuit from the peer id alone made every `listen_on` fail
    /// with `MissingRelayAddr`, so no reservation was ever taken and the whole
    /// private-node path was dead. That failure was silent — the error was
    /// logged at debug and the loop moved on.
    #[tokio::test]
    async fn reservations_are_only_taken_via_dialable_relay_addresses() {
        let mut swarm = nat_swarm();
        let mut nat_state = NatState::default();

        let routable_peer = PeerId::random();
        let loopback_peer = PeerId::random();
        let connected: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>> = Arc::new(RwLock::new(
            [
                (
                    routable_peer,
                    vec!["/ip4/198.51.100.7/tcp/9001".parse().unwrap()],
                ),
                (
                    loopback_peer,
                    vec!["/ip4/127.0.0.1/tcp/9001".parse().unwrap()],
                ),
            ]
            .into_iter()
            .collect(),
        ));

        Libp2pNetwork::ensure_relay_reservations(&mut swarm, &connected, &mut nat_state).await;

        assert!(
            nat_state.reserved_with.contains_key(&routable_peer),
            "a reservation must be taken via the routable peer"
        );
        assert!(
            !nat_state.reserved_with.contains_key(&loopback_peer),
            "a loopback-only peer cannot relay for us"
        );
    }

    /// Reservations stop at the target so we do not occupy every relay slot
    /// in sight.
    #[tokio::test]
    async fn reservations_stop_at_the_target_count() {
        let mut swarm = nat_swarm();
        let mut nat_state = NatState::default();

        let peers: HashMap<PeerId, Vec<Multiaddr>> = (0..TARGET_RELAY_RESERVATIONS + 3)
            .map(|i| {
                (
                    PeerId::random(),
                    vec![format!("/ip4/198.51.100.{}/tcp/9001", i + 1)
                        .parse()
                        .unwrap()],
                )
            })
            .collect();
        let connected = Arc::new(RwLock::new(peers));

        Libp2pNetwork::ensure_relay_reservations(&mut swarm, &connected, &mut nat_state).await;

        assert_eq!(nat_state.reserved_with.len(), TARGET_RELAY_RESERVATIONS);
    }

    /// Releasing clears the bookkeeping and leaves unrelated listeners alone.
    ///
    /// Note this asserts the bookkeeping, not the listener teardown itself:
    /// the relay client's `remove_listener` marks a listener closed but keeps
    /// the entry, so a second call still reports `true` and cannot distinguish
    /// "removed" from "never removed". Confirming the teardown needs a live
    /// relay, which is part of the manual NAT verification in the README
    /// rather than something this unit test can honestly claim.
    #[tokio::test]
    async fn releasing_clears_reservations_without_touching_other_listeners() {
        let mut swarm = nat_swarm();
        let mut nat_state = NatState::default();
        let relay_peer = PeerId::random();

        let plain = swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let circuit = swarm.listen_on(circuit_addr(relay_peer)).unwrap();
        nat_state.reserved_with.insert(relay_peer, circuit);
        nat_state.reachability = Reachability::Private;

        Libp2pNetwork::release_relay_reservations(&mut swarm, &mut nat_state);

        assert!(
            nat_state.reserved_with.is_empty(),
            "released reservations must be forgotten, or we never retry them"
        );
        assert!(
            swarm.remove_listener(plain),
            "a non-circuit listener must survive the release"
        );
    }

    /// A circuit address is only built from an address a third party could
    /// dial — a relay reachable only from where we stand relays nothing.
    #[test]
    fn only_routable_non_circuit_addresses_can_host_a_reservation() {
        let routable: Multiaddr = "/ip4/198.51.100.7/tcp/9001".parse().unwrap();
        assert!(Libp2pNetwork::is_relayable_addr(&routable));

        for bad in [
            "/ip4/127.0.0.1/tcp/9001",
            "/ip4/0.0.0.0/tcp/9001",
            "/ip6/::1/tcp/9001",
        ] {
            assert!(
                !Libp2pNetwork::is_relayable_addr(&bad.parse().unwrap()),
                "{bad} is not reachable by a third party"
            );
        }

        // No circuits through circuits.
        assert!(!Libp2pNetwork::is_relayable_addr(&circuit_addr(
            PeerId::random()
        )));
    }

    #[tokio::test]
    async fn test_network_creation() {
        let config = Libp2pNetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false,
            enable_nat_traversal: false,
            gossipsub_topics: vec!["test".to_string()],
            external_addrs: vec![],
        };

        // Create a temporary directory for the CRDT repository
        let tmp_dir = tempdir().unwrap();
        let crdt_repo: Arc<dyn ContentRepository> =
            Arc::new(CrslCrdtRepository::open(tmp_dir.path().join("crdt")).unwrap());
        let data_dir = tmp_dir.path().to_path_buf();

        let network = Libp2pNetwork::new(config, crdt_repo, data_dir).await;
        assert!(network.is_ok());

        let network = network.unwrap();
        assert!(!network.local_peer_id().is_empty());
    }
}
