//! Port layer - Abstract interfaces for infrastructure dependencies
//!
//! This module defines traits that abstract away infrastructure concerns,
//! allowing the application layer to remain independent of specific implementations.

pub mod content_repository;
pub mod event_publisher;
pub mod peer_network;
pub mod persistence;

pub use content_repository::{CommitResult, ContentRepository, SerializedOperation};
pub use event_publisher::EventPublisher;
pub use peer_network::PeerNetwork;
pub use persistence::{PersistentContentRepository, PersistentNodeRegistry};
