//! Port layer - Abstract interfaces for infrastructure dependencies
//!
//! This module defines traits that abstract away infrastructure concerns,
//! allowing the application layer to remain independent of specific implementations.

pub mod auth_token;
pub mod authentication_service;
pub mod authorization_service;
pub mod content_repository;
pub mod event_publisher;
pub mod peer_network;
pub mod persistence;
pub mod public_key_registry;

pub use auth_token::AuthToken;
pub use authentication_service::AuthenticationService;
pub use authorization_service::{AuthorizationRequest, AuthorizationResult, AuthorizationService};
pub use content_repository::{CommitResult, ContentRepository, SerializedOperation};
pub use event_publisher::EventPublisher;
pub use peer_network::PeerNetwork;
pub use persistence::{
    PersistentAccessPolicyRepository, PersistentContentRepository, PersistentNodeRegistry,
};
pub use public_key_registry::{InMemoryPublicKeyRegistry, PublicKeyRegistry};
