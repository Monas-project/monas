//! libp2p-based network implementation.
//!
//! Provides a full P2P networking stack using libp2p 0.56 with:
//! - Kademlia DHT for peer discovery
//! - Gossipsub for event propagation
//! - RequestResponse for direct peer communication
//! - mDNS for local peer discovery
//! - WebRTC and TCP transports

use super::behaviour::{BehaviourConfig, NodeBehaviour, NodeBehaviourEvent};
use super::protocol::{ContentRequest, ContentResponse};
use super::transport;
use crate::domain::events::Event;
use crate::infrastructure::disk_capacity;
use crate::port::content_repository::{ContentRepository, SerializedOperation};
use crate::port::peer_network::PeerNetwork;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic},
    identify, kad,
    request_response::{self, OutboundRequestId, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

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
    /// The source peer ID.
    pub source: String,
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
    /// Gossipsub topics to subscribe to.
    pub gossipsub_topics: Vec<String>,
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
            gossipsub_topics: vec!["monas-events".to_string()],
        }
    }
}

/// Commands sent to the swarm event loop.
enum SwarmCommand {
    FindClosestPeers {
        key: Vec<u8>,
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
        reply: oneshot::Sender<Result<usize>>,
    },
    GetProviders {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<PeerId>>>,
    },
}

/// Pending requests tracking.
#[derive(Default)]
struct PendingRequests {
    capacity_queries: HashMap<OutboundRequestId, oneshot::Sender<Result<(u64, u64)>>>,
    content_fetches: HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<u8>>>>,
    kad_queries: HashMap<kad::QueryId, oneshot::Sender<Result<Vec<PeerId>>>>,
    kad_provider_queries: HashMap<kad::QueryId, oneshot::Sender<Result<Vec<PeerId>>>>,
    operation_fetches:
        HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<SerializedOperation>>>>,
    operation_pushes: HashMap<OutboundRequestId, oneshot::Sender<Result<usize>>>,
}

/// libp2p-based network implementation.
pub struct Libp2pNetwork {
    local_peer_id: PeerId,
    command_tx: mpsc::Sender<SwarmCommand>,
    /// Connected peers and their addresses.
    #[allow(dead_code)]
    connected_peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
    /// Broadcast channel for received Gossipsub events.
    event_rx: broadcast::Sender<ReceivedEvent>,
    /// Content repository for content storage.
    #[allow(dead_code)]
    crdt_repo: Arc<dyn ContentRepository>,
    /// Data directory for disk capacity queries.
    #[allow(dead_code)]
    data_dir: PathBuf,
}

impl Libp2pNetwork {
    /// Create a new libp2p network with the given configuration.
    pub async fn new(
        config: Libp2pNetworkConfig,
        crdt_repo: Arc<dyn ContentRepository>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());

        info!("Local peer ID: {}", local_peer_id);

        // Build transport
        let transport =
            transport::build_transport(&keypair).context("Failed to build transport")?;

        // Build behaviour
        let behaviour = NodeBehaviour::new(local_peer_id, &keypair, BehaviourConfig::default())?;

        // Create swarm
        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60));

        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, swarm_config);

        // Start listening on configured addresses
        for addr in &config.listen_addrs {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => info!("Listening on {}", addr),
                Err(e) => warn!("Failed to listen on {}: {}", addr, e),
            }
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

        // Spawn swarm event loop
        tokio::spawn(Self::run_swarm_loop(
            swarm,
            command_rx,
            connected_peers_clone,
            event_tx_clone,
            crdt_repo_clone,
            data_dir_clone,
        ));

        Ok(Self {
            local_peer_id,
            command_tx,
            connected_peers,
            event_rx: event_tx,
            crdt_repo,
            data_dir,
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
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("Dial response channel closed"))?
    }

    /// Get the addresses this node is listening on.
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
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
    async fn run_swarm_loop(
        mut swarm: Swarm<NodeBehaviour>,
        mut command_rx: mpsc::Receiver<SwarmCommand>,
        connected_peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        event_tx: broadcast::Sender<ReceivedEvent>,
        crdt_repo: Arc<dyn ContentRepository>,
        data_dir: PathBuf,
    ) {
        let mut pending = PendingRequests::default();

        loop {
            tokio::select! {
                // Handle incoming commands
                Some(cmd) = command_rx.recv() => {
                    Self::handle_command(&mut swarm, &mut pending, cmd).await;
                }
                // Handle swarm events
                event = swarm.select_next_some() => {
                    Self::handle_swarm_event(&mut swarm, &mut pending, &connected_peers, &event_tx, &crdt_repo, &data_dir, event).await;
                }
            }
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
                    },
                );
                pending.operation_pushes.insert(request_id, reply);
            }
            SwarmCommand::GetProviders { key, reply } => {
                let key = kad::RecordKey::new(&key);
                let query_id = swarm.behaviour_mut().kademlia.get_providers(key);
                pending.kad_provider_queries.insert(query_id, reply);
            }
        }
    }

    /// Handle a swarm event.
    async fn handle_swarm_event(
        swarm: &mut Swarm<NodeBehaviour>,
        pending: &mut PendingRequests,
        connected_peers: &Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
        event_tx: &broadcast::Sender<ReceivedEvent>,
        crdt_repo: &Arc<dyn ContentRepository>,
        data_dir: &std::path::Path,
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
                Self::handle_request_response_event(swarm, pending, crdt_repo, data_dir, rr_event)
                    .await;
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify_event)) => {
                Self::handle_identify_event(swarm, *identify_event).await;
            }
            #[cfg(not(target_arch = "wasm32"))]
            SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns_event)) => {
                Self::handle_mdns_event(swarm, connected_peers, mdns_event).await;
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let addr = endpoint.get_remote_address().clone();
                info!("Connection established with {} at {}", peer_id, addr);
                connected_peers
                    .write()
                    .await
                    .entry(peer_id)
                    .or_insert_with(Vec::new)
                    .push(addr);
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

                        let received = ReceivedEvent {
                            source: propagation_source.to_string(),
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
        event: request_response::Event<ContentRequest, ContentResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    Self::handle_incoming_request(
                        swarm, peer, request, channel, crdt_repo, data_dir,
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
                // Clean up pending requests
                if let Some(reply) = pending.capacity_queries.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("Request failed: {:?}", error)));
                }
                if let Some(reply) = pending.content_fetches.remove(&request_id) {
                    let _ = reply.send(Err(anyhow::anyhow!("Request failed: {:?}", error)));
                }
            }
            _ => {}
        }
    }

    async fn handle_incoming_request(
        swarm: &mut Swarm<NodeBehaviour>,
        peer: PeerId,
        request: ContentRequest,
        channel: ResponseChannel<ContentResponse>,
        crdt_repo: &Arc<dyn ContentRepository>,
        data_dir: &std::path::Path,
    ) {
        debug!("Received request from {}: {:?}", peer, request);

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
                match crdt_repo
                    .get_operations(&genesis_cid, since_version.as_deref())
                    .await
                {
                    Ok(ops) => {
                        // Serialize operations for network transfer
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
            ContentRequest::PushOperations {
                genesis_cid,
                operations,
            } => {
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
            // Add peer's addresses to Kademlia
            for addr in &info.listen_addrs {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
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

#[async_trait]
impl PeerNetwork for Libp2pNetwork {
    async fn find_closest_peers(&self, key: Vec<u8>, k: usize) -> Result<Vec<String>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::FindClosestPeers { key, k, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        let peers = rx
            .await
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

            if let Ok(Ok((_, available))) = rx.await {
                results.insert(peer_id_str.clone(), available);
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

        rx.await
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

        rx.await
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn publish_provider(&self, key: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::PublishProvider { key, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        rx.await
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    fn local_peer_id(&self) -> String {
        self.local_peer_id.to_string()
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

        rx.await
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
    }

    async fn push_operations(
        &self,
        peer_id: &str,
        genesis_cid: &str,
        operations: &[SerializedOperation],
    ) -> Result<usize> {
        let peer_id = PeerId::from_str(peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid peer ID: {}", peer_id))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(SwarmCommand::PushOperations {
                peer_id,
                genesis_cid: genesis_cid.to_string(),
                operations: operations.to_vec(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send command"))?;

        rx.await
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))?
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

        let peers = rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive response"))??;
        Ok(peers.into_iter().map(|p| p.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crdt_repository::CrslCrdtRepository;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_network_creation() {
        let config = Libp2pNetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false,
            gossipsub_topics: vec!["test".to_string()],
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
