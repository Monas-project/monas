//! Domain-specific error types for the state node system.

use axum::http::StatusCode;
use thiserror::Error;

use super::value_objects::{ContentId, NodeId};

/// Main error type for state node operations.
#[derive(Debug, Error)]
pub enum StateNodeError {
    // Content-related errors
    #[error("Content not found: {0}")]
    ContentNotFound(ContentId),

    #[error("Content already exists: {0}")]
    ContentAlreadyExists(ContentId),

    // Node-related errors
    #[error("Node not found: {0}")]
    NodeNotFound(NodeId),

    #[error("Insufficient capacity: required {required}, available {available}")]
    InsufficientCapacity { required: u64, available: u64 },

    #[error("No available member nodes found")]
    NoAvailableMembers,

    #[error("Node {node_id} is not a member of content network {content_id}")]
    NotAMember {
        node_id: String,
        content_id: ContentId,
    },

    // Permission-related errors
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid UCAN token: {0}")]
    InvalidUcanToken(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    // Network-related errors
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),

    #[error("Peer not reachable: {0}")]
    PeerNotReachable(String),

    // CRDT-related errors
    #[error("CRDT error: {0}")]
    CrdtError(#[from] CrdtError),

    #[error("Invalid CID: {0}")]
    InvalidCid(String),

    // Configuration errors
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),

    // Value object errors
    #[error("Value object error: {0}")]
    ValueError(#[from] super::value_objects::ValueError),

    // Other errors
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Network-related errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

/// CRDT-related errors.
#[derive(Debug, Error)]
pub enum CrdtError {
    #[error("Conflict resolution failed: {0}")]
    ConflictResolutionFailed(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

impl StateNodeError {
    /// Map the error to an HTTP status code.
    pub fn to_http_status(&self) -> StatusCode {
        match self {
            StateNodeError::ContentNotFound(_) => StatusCode::NOT_FOUND,
            StateNodeError::ContentAlreadyExists(_) => StatusCode::CONFLICT,
            StateNodeError::PermissionDenied(_) => StatusCode::FORBIDDEN,
            StateNodeError::InvalidUcanToken(_) => StatusCode::UNAUTHORIZED,
            StateNodeError::AuthenticationFailed(_) => StatusCode::UNAUTHORIZED,
            StateNodeError::AuthorizationFailed(_) => StatusCode::FORBIDDEN,
            StateNodeError::InsufficientCapacity { .. } => StatusCode::INSUFFICIENT_STORAGE,
            StateNodeError::NoAvailableMembers => StatusCode::SERVICE_UNAVAILABLE,
            StateNodeError::NotAMember { .. } => StatusCode::FORBIDDEN,
            StateNodeError::InvalidCid(_) => StatusCode::BAD_REQUEST,
            StateNodeError::InvalidConfiguration(_) => StatusCode::BAD_REQUEST,
            StateNodeError::NetworkError(_) => StatusCode::SERVICE_UNAVAILABLE,
            StateNodeError::PeerNotReachable(_) => StatusCode::SERVICE_UNAVAILABLE,
            StateNodeError::NodeNotFound(_) => StatusCode::NOT_FOUND,
            StateNodeError::CrdtError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StateNodeError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StateNodeError::ValueError(_) => StatusCode::BAD_REQUEST,
            StateNodeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Convert anyhow::Error to StateNodeError for backward compatibility.
impl From<anyhow::Error> for StateNodeError {
    fn from(err: anyhow::Error) -> Self {
        // Try to extract more specific error types from the error message
        let error_msg = err.to_string();

        if error_msg.contains("not a member") {
            StateNodeError::PermissionDenied(error_msg)
        } else if error_msg.contains("no available member nodes") {
            StateNodeError::NoAvailableMembers
        } else if error_msg.contains("capacity") {
            StateNodeError::InsufficientCapacity {
                required: 0,
                available: 0,
            }
        } else {
            // Default to Internal error for all other cases
            // (including "not found" errors, since we can't extract the ID)
            StateNodeError::Internal(error_msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_not_found_error() {
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let err = StateNodeError::ContentNotFound(content_id);
        assert_eq!(err.to_string(), "Content not found: content-1");
        assert_eq!(err.to_http_status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_not_a_member_error() {
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let err = StateNodeError::NotAMember {
            node_id: "node-1".to_string(),
            content_id,
        };
        assert_eq!(
            err.to_string(),
            "Node node-1 is not a member of content network content-1"
        );
        assert_eq!(err.to_http_status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_insufficient_capacity_error() {
        let err = StateNodeError::InsufficientCapacity {
            required: 1000,
            available: 500,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient capacity: required 1000, available 500"
        );
        assert_eq!(err.to_http_status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[test]
    fn test_no_available_members_error() {
        let err = StateNodeError::NoAvailableMembers;
        assert_eq!(err.to_string(), "No available member nodes found");
        assert_eq!(err.to_http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_network_error() {
        let network_err = NetworkError::ConnectionFailed("peer offline".to_string());
        let err = StateNodeError::from(network_err);
        assert!(err.to_string().contains("Connection failed"));
        assert_eq!(err.to_http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_crdt_error() {
        let crdt_err = CrdtError::InvalidOperation("bad op".to_string());
        let err = StateNodeError::from(crdt_err);
        assert!(err.to_string().contains("Invalid operation"));
        assert_eq!(err.to_http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_err = anyhow::anyhow!("Content network not found: content-1");
        let err: StateNodeError = anyhow_err.into();
        // anyhow errors convert to Internal by default
        assert_eq!(err.to_http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_anyhow_error_conversion_not_a_member() {
        let anyhow_err = anyhow::anyhow!("Local node node-1 is not a member");
        let err: StateNodeError = anyhow_err.into();
        assert_eq!(err.to_http_status(), StatusCode::FORBIDDEN);
    }
}
