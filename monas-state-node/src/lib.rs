pub mod application_service;
pub mod domain;
pub mod infrastructure;
pub mod port;
#[cfg(not(target_arch = "wasm32"))]
pub mod presentation;

#[cfg(test)]
pub mod test_utils;

// Domain layer exports
pub use domain::{
    AccessControlError, AccessControlEvent, AccessControlUpdate, AccessPolicy, AccessPolicyError,
    AuthCapability, AuthToken, AuthTokenParseError, AuthTokenVerifier, AuthTokenVerifyError,
    Capability, CapabilityAction, ContentAccessControl, ContentId, CrdtError, Identity,
    IdentityError, IdentityType, KeyId, NetworkError, NodeCandidate, NodeId, NonEmptySet,
    PlacementError, PlacementPolicy, StateNodeError, ValueError, VerifiedToken,
};

// Port layer exports (excluding AuthToken to avoid conflict with domain::AuthToken)
pub use port::{
    auth_token::AuthToken as PortAuthToken, AuthenticationService, AuthorizationRequest,
    AuthorizationResult, AuthorizationService, CommitResult, ContentRepository, EventPublisher,
    PeerNetwork, PersistentContentRepository, PersistentNodeRegistry, SerializedOperation,
};

#[cfg(not(target_arch = "wasm32"))]
pub use application_service::node::{StateNode, StateNodeConfig};
