//! Network infrastructure using libp2p.
//!
//! This module provides P2P networking capabilities including:
//! - Kademlia DHT for peer discovery and content routing
//! - Gossipsub for event propagation
//! - RequestResponse for direct peer communication
//! - mDNS for local peer discovery
//! - WebRTC and TCP transports

pub mod behaviour;
pub mod libp2p_network;
pub mod protocol;
pub mod transport;

pub use behaviour::{BehaviourConfig, NodeBehaviour, NodeBehaviourEvent};
pub use libp2p_network::{GossipsubMessage, Libp2pNetwork, Libp2pNetworkConfig, ReceivedEvent};
pub use protocol::{ContentCodec, ContentRequest, ContentResponse};
