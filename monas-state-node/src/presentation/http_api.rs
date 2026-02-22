//! HTTP API for the state node.

use crate::application_service::state_node_service::StateNodeService;
use crate::domain::auth_capability::AuthCapability;
use crate::domain::errors::StateNodeError;
use crate::domain::identity::Identity;
use crate::infrastructure::crdt_repository::CrslCrdtRepository;
use crate::infrastructure::gossipsub_publisher::GossipsubEventPublisher;
use crate::infrastructure::network::Libp2pNetwork;
use crate::infrastructure::persistence::{
    SledAccessControlRepository, SledContentNetworkRepository, SledNodeRegistry,
};
use crate::port::auth_token::AuthToken;
use crate::port::content_repository::ContentRepository;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Application state shared across handlers.
pub type AppState = Arc<
    StateNodeService<
        SledNodeRegistry,
        SledContentNetworkRepository,
        Libp2pNetwork,
        GossipsubEventPublisher<Libp2pNetwork>,
        CrslCrdtRepository,
        SledAccessControlRepository,
    >,
>;

/// Create the API router.
pub fn create_router(state: AppState) -> Router {
    use std::sync::Arc;
    use tower_governor::governor::GovernorConfigBuilder;
    use tower_governor::GovernorLayer;

    let governor_config = GovernorConfigBuilder::default()
        .per_second(100)
        .burst_size(200)
        .finish()
        .unwrap();

    Router::new()
        // --- Public endpoints (no auth required) ---
        // These are intentionally unauthenticated for P2P peer discovery,
        // node coordination, and operational monitoring.
        // SECURITY NOTE: These endpoints expose only node/content IDs and
        // capacity metadata — never content data itself.
        .route("/health", get(health_check))
        .route("/node/info", get(node_info))
        .route("/node/register", post(register_node))
        .route("/nodes", get(list_nodes))
        .route("/contents", get(list_contents))
        // --- Authenticated endpoints ---
        .route("/content", post(create_content))
        .route("/content/:id", put(update_content).delete(delete_content))
        .route("/content/:id/members", post(add_members))
        // CRDT-related endpoints
        .route("/content/:id/data", get(get_content_data))
        .route("/content/:id/history", get(get_content_history))
        .route("/content/:id/version/:version", get(get_content_version))
        .route("/content/:id/access/grant", post(grant_access_handler))
        // Request body size limit: 16 MiB
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        // Rate limit: 100 requests/sec, burst up to 200
        .layer(GovernorLayer {
            config: Arc::new(governor_config),
        })
        .with_state(state)
}

// ============================================================================
// Request/Response types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_id: String,
}

#[derive(Debug, Serialize)]
pub struct NodeInfoResponse {
    pub node_id: String,
    pub total_capacity: Option<u64>,
    pub available_capacity: Option<u64>,
    pub listen_addrs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterNodeRequest {
    pub total_capacity: u64,
}

#[derive(Debug, Serialize)]
pub struct RegisterNodeResponse {
    pub node_id: String,
    pub total_capacity: u64,
    pub available_capacity: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateContentRequest {
    pub data: String, // Base64 encoded content
}

#[derive(Debug, Serialize)]
pub struct CreateContentResponse {
    pub content_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateContentRequest {
    pub data: String, // Base64 encoded content
}

#[derive(Debug, Serialize)]
pub struct UpdateContentResponse {
    pub content_id: String,
    pub updated: bool,
}

#[derive(Debug, Serialize)]
pub struct DeleteContentResponse {
    pub content_id: String,
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddMembersRequest {
    /// Number of members to add
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct AddMembersResponse {
    pub content_id: String,
    pub added_node_id: String,
    pub member_nodes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Implement IntoResponse for StateNodeError to automatically map to HTTP responses.
///
/// Internal error details are sanitized to prevent information leakage.
/// Only client-facing error categories are returned; detailed messages are logged server-side.
impl IntoResponse for StateNodeError {
    fn into_response(self) -> Response {
        let status = self.to_http_status();
        let error_message = match &self {
            // Client errors: safe to expose the message
            StateNodeError::ContentNotFound(_) => self.to_string(),
            StateNodeError::ContentAlreadyExists(_) => self.to_string(),
            StateNodeError::NodeNotFound(_) => self.to_string(),
            StateNodeError::InsufficientCapacity { .. } => self.to_string(),
            StateNodeError::NoAvailableMembers => self.to_string(),
            StateNodeError::NotAMember { .. } => self.to_string(),
            StateNodeError::PermissionDenied(_) => "Permission denied".to_string(),
            StateNodeError::InvalidUcanToken(_) => "Invalid authentication token".to_string(),
            StateNodeError::AuthenticationFailed(_) => "Authentication failed".to_string(),
            StateNodeError::AuthorizationFailed(_) => "Authorization failed".to_string(),
            StateNodeError::InvalidCid(_) => "Invalid content identifier".to_string(),
            StateNodeError::InvalidConfiguration(_) => "Invalid request".to_string(),
            StateNodeError::ValueError(_) => "Invalid input value".to_string(),
            // Server errors: log details but return generic message
            StateNodeError::NetworkError(_)
            | StateNodeError::PeerNotReachable(_)
            | StateNodeError::CrdtError(_)
            | StateNodeError::StorageError(_)
            | StateNodeError::Internal(_) => {
                tracing::error!("Internal error: {}", self);
                "Internal server error".to_string()
            }
        };
        let error_response = ErrorResponse {
            error: error_message,
        };
        (status, Json(error_response)).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct GrantAccessRequest {
    pub grantee_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GrantAccessResponse {
    pub content_id: String,
    pub grantee_id: String,
    pub granted_capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContentDataResponse {
    pub content_id: String,
    pub data: String, // Base64 encoded content
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContentHistoryResponse {
    pub content_id: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VersionQuery {
    pub version: Option<String>,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Extract authentication token from Authorization header.
///
/// Supports both Bearer tokens and raw tokens:
/// - "Bearer <token>" -> extracts <token>
/// - "<token>" -> uses token as-is
///
/// Returns None if the Authorization header is missing.
fn extract_auth_token(headers: &HeaderMap) -> Option<AuthToken> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;

    // Check if it's a Bearer token
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Some(AuthToken::new(token.to_string()))
    } else {
        // Use the header value as-is (for DID-based auth)
        Some(AuthToken::new(auth_header.to_string()))
    }
}

/// Extract request signature from X-Request-Signature header.
///
/// The request signature is a base64-encoded signature that proves the requester
/// possesses the private key corresponding to the AuthToken's audience (aud).
///
/// Returns None if the header is missing or cannot be decoded.
fn extract_request_signature(headers: &HeaderMap) -> Option<Vec<u8>> {
    let signature_header = headers.get("x-request-signature")?.to_str().ok()?;

    // Decode base64-encoded signature
    base64::engine::general_purpose::STANDARD
        .decode(signature_header)
        .ok()
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint (public, no auth required).
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        node_id: state.local_node_id().to_string(),
    })
}

/// Get node info (public, no auth required).
///
/// Exposes node capacity and listen addresses for peer discovery.
/// Does not expose content data.
async fn node_info(State(state): State<AppState>) -> impl IntoResponse {
    let node_id = state.local_node_id().to_string();
    let listen_addrs = state.listen_addrs().await;

    match state.get_node(&node_id).await {
        Ok(Some(node)) => Json(NodeInfoResponse {
            node_id: node.node_id,
            total_capacity: Some(node.total_capacity),
            available_capacity: Some(node.available_capacity),
            listen_addrs,
        })
        .into_response(),
        Ok(None) => Json(NodeInfoResponse {
            node_id,
            total_capacity: None,
            available_capacity: None,
            listen_addrs,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Register the local node (public, no auth required).
///
/// This endpoint is called by the node operator to initialize the local node.
/// It is rate-limited by the global governor (100 req/s) to prevent abuse.
async fn register_node(
    State(state): State<AppState>,
    Json(req): Json<RegisterNodeRequest>,
) -> impl IntoResponse {
    match state.register_node(req.total_capacity).await {
        Ok((snapshot, _)) => Json(RegisterNodeResponse {
            node_id: snapshot.node_id,
            total_capacity: snapshot.total_capacity,
            available_capacity: snapshot.available_capacity,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// List all nodes (public, no auth required).
///
/// Returns node IDs only — no content data. Used for peer coordination.
async fn list_nodes(State(state): State<AppState>) -> impl IntoResponse {
    match state.list_nodes().await {
        Ok(nodes) => Json::<Vec<String>>(nodes).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Create new content.
async fn create_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateContentRequest>,
) -> impl IntoResponse {
    use base64::Engine;

    let data = match base64::engine::general_purpose::STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64 data: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Extract authentication token and request signature from headers
    let token = extract_auth_token(&headers);
    let request_signature = extract_request_signature(&headers);

    match state
        .create_content(&data, token.as_ref(), request_signature.as_deref())
        .await
    {
        Ok(event) => {
            if let crate::domain::events::Event::ContentCreated { content_id, .. } = event {
                (
                    StatusCode::CREATED,
                    Json(CreateContentResponse { content_id }),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Unexpected event type".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => e.into_response(),
    }
}

/// Update content.
async fn update_content(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateContentRequest>,
) -> impl IntoResponse {
    use base64::Engine;

    let data = match base64::engine::general_purpose::STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64 data: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Extract authentication token and request signature from headers
    let token = extract_auth_token(&headers);
    let request_signature = extract_request_signature(&headers);

    match state
        .update_content(
            &content_id,
            &data,
            token.as_ref(),
            request_signature.as_deref(),
        )
        .await
    {
        Ok(_) => Json(UpdateContentResponse {
            content_id,
            updated: true,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Delete content.
///
/// Physically deletes the ContentNetwork but preserves:
/// - CRDT history and CID for offline node notification
/// - ContentDeleted event for propagation to other nodes
async fn delete_content(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract authentication token and request signature from headers
    let token = extract_auth_token(&headers);
    let request_signature = extract_request_signature(&headers);

    match state
        .delete_content(&content_id, token.as_ref(), request_signature.as_deref())
        .await
    {
        Ok(_) => Json(DeleteContentResponse {
            content_id,
            deleted: true,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Add member nodes to a content network.
async fn add_members(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AddMembersRequest>,
) -> impl IntoResponse {
    use crate::domain::events::Event;

    let token = extract_auth_token(&headers);
    let request_signature = extract_request_signature(&headers);

    match state
        .add_member_to_content(
            &content_id,
            req.count,
            token.as_ref(),
            request_signature.as_deref(),
        )
        .await
    {
        Ok(event) => {
            if let Event::ContentNetworkManagerAdded {
                content_id,
                added_node_id,
                member_nodes,
                ..
            } = event
            {
                Json(AddMembersResponse {
                    content_id,
                    added_node_id,
                    member_nodes,
                })
                .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Unexpected event type".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => e.into_response(),
    }
}

/// List all content networks (public, no auth required).
///
/// Returns content IDs only — no content data. Used for sync coordination.
/// Content data access requires authentication via GET /content/:id/data.
async fn list_contents(State(state): State<AppState>) -> impl IntoResponse {
    match state.list_content_networks().await {
        Ok(contents) => Json::<Vec<String>>(contents).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Verify that the caller has read access to the given content.
///
/// Extracts a Bearer token from the Authorization header, then checks the
/// CRDT-embedded access policy for read permission.
async fn verify_read_access(
    state: &AppState,
    headers: &HeaderMap,
    content_id: &str,
) -> Result<(), Response> {
    let token = extract_auth_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Authorization header is required".to_string(),
            }),
        )
            .into_response()
    })?;

    // Authenticate the caller
    let _identity = state.authenticate_for_read(&token).await.map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!("Authentication failed: {}", e),
            }),
        )
            .into_response()
    })?;

    // Check access policy for read permission
    let crdt_repo = state.crdt_repo();
    if let Ok(Some(policy)) = crdt_repo.get_access_policy(content_id).await {
        if !policy.has_capability(
            &_identity,
            &crate::domain::auth_capability::AuthCapability::ReadContent,
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Insufficient permissions: read access required".to_string(),
                }),
            )
                .into_response());
        }
    }
    // If no policy exists, allow access (content may not have a policy yet)

    Ok(())
}

/// Get content data from CRDT repository.
///
/// Requires authentication. Returns the latest version of the content data.
async fn get_content_data(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<VersionQuery>,
) -> impl IntoResponse {
    if let Err(response) = verify_read_access(&state, &headers, &content_id).await {
        return response;
    }

    let crdt_repo = state.crdt_repo();

    // Get data based on version parameter
    let data_result = if let Some(version) = &query.version {
        crdt_repo.get_version(version).await
    } else {
        crdt_repo.get_latest(&content_id).await
    };

    match data_result {
        Ok(Some(data)) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            Json(ContentDataResponse {
                content_id,
                data: encoded,
                version: query.version,
            })
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Content data not found: {}", content_id),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Get content version history from CRDT repository.
///
/// Requires authentication.
async fn get_content_history(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = verify_read_access(&state, &headers, &content_id).await {
        return response;
    }

    let crdt_repo = state.crdt_repo();

    match crdt_repo.get_history(&content_id).await {
        Ok(versions) => Json(ContentHistoryResponse {
            content_id,
            versions,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Get a specific version of content data.
///
/// Requires authentication.
async fn get_content_version(
    State(state): State<AppState>,
    Path((content_id, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = verify_read_access(&state, &headers, &content_id).await {
        return response;
    }

    let crdt_repo = state.crdt_repo();

    match crdt_repo.get_version(&version).await {
        Ok(Some(data)) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            Json(ContentDataResponse {
                content_id,
                data: encoded,
                version: Some(version),
            })
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Version not found: {}", version),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Parse a capability string into an AuthCapability enum variant.
fn parse_capability(s: &str) -> Option<AuthCapability> {
    match s {
        "ReadContent" => Some(AuthCapability::ReadContent),
        "WriteContent" => Some(AuthCapability::WriteContent),
        "DeleteContent" => Some(AuthCapability::DeleteContent),
        "ManageMembers" => Some(AuthCapability::ManageMembers),
        "ShareContent" => Some(AuthCapability::ShareContent),
        "RevokeAccess" => Some(AuthCapability::RevokeAccess),
        "ReadMetadata" => Some(AuthCapability::ReadMetadata),
        _ => None,
    }
}

/// Grant access to a content for a specific identity.
async fn grant_access_handler(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<GrantAccessRequest>,
) -> impl IntoResponse {
    // Extract authentication token
    let token = match extract_auth_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication token is required".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse grantee identity from "type:id" format
    let grantee_identity = if let Some((type_str, id)) = req.grantee_id.split_once(':') {
        match type_str {
            "user" => Identity::user(id.to_string()),
            "node" => Identity::node(id.to_string()),
            "service" => Identity::service(id.to_string()),
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid grantee_id format: unknown type '{}'", type_str),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "grantee_id must be in 'type:id' format (e.g., 'user:account2')".to_string(),
            }),
        )
            .into_response();
    };

    let grantee_identity = match grantee_identity {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid grantee identity: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Parse capabilities
    let mut capabilities = Vec::new();
    for cap_str in &req.capabilities {
        match parse_capability(cap_str) {
            Some(cap) => capabilities.push(cap),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Unknown capability: '{}'", cap_str),
                    }),
                )
                    .into_response();
            }
        }
    }

    if capabilities.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "At least one capability is required".to_string(),
            }),
        )
            .into_response();
    }

    let granted_capabilities: Vec<String> = req.capabilities.clone();
    let request_signature = extract_request_signature(&headers);

    match state
        .grant_access(
            &content_id,
            grantee_identity,
            capabilities,
            &token,
            request_signature.as_deref(),
        )
        .await
    {
        Ok(()) => Json(GrantAccessResponse {
            content_id,
            grantee_id: req.grantee_id,
            granted_capabilities,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_node_request_deserialization() {
        let json = r#"{"total_capacity": 1000}"#;
        let request: RegisterNodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.total_capacity, 1000);
    }

    #[test]
    fn test_register_node_response_serialization() {
        let response = RegisterNodeResponse {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"node_id\":\"node-1\""));
        assert!(json.contains("\"total_capacity\":1000"));
        assert!(json.contains("\"available_capacity\":1000"));
    }

    #[test]
    fn test_create_content_request_deserialization() {
        let json = r#"{"data": "SGVsbG8gV29ybGQ="}"#;
        let request: CreateContentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.data, "SGVsbG8gV29ybGQ=");

        // Verify base64 decoding
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&request.data)
            .unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_create_content_response_serialization() {
        let response = CreateContentResponse {
            content_id: "cid-1".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        // member_nodes is no longer exposed to prevent information leakage
        assert!(!json.contains("\"member_nodes\""));
    }

    #[test]
    fn test_update_content_request_deserialization() {
        let json = r#"{"data": "dXBkYXRlZA=="}"#;
        let request: UpdateContentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.data, "dXBkYXRlZA==");

        // Verify base64 decoding
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&request.data)
            .unwrap();
        assert_eq!(decoded, b"updated");
    }

    #[test]
    fn test_update_content_response_serialization() {
        let response = UpdateContentResponse {
            content_id: "cid-1".to_string(),
            updated: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        assert!(json.contains("\"updated\":true"));
    }

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "Something went wrong".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\":\"Something went wrong\""));
    }

    #[test]
    fn test_content_data_response_serialization() {
        let response = ContentDataResponse {
            content_id: "cid-1".to_string(),
            data: "SGVsbG8=".to_string(),
            version: Some("v1".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        assert!(json.contains("\"data\":\"SGVsbG8=\""));
        assert!(json.contains("\"version\":\"v1\""));
    }

    #[test]
    fn test_content_data_response_without_version() {
        let response = ContentDataResponse {
            content_id: "cid-1".to_string(),
            data: "SGVsbG8=".to_string(),
            version: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"version\":null"));
    }

    #[test]
    fn test_content_history_response_serialization() {
        let response = ContentHistoryResponse {
            content_id: "cid-1".to_string(),
            versions: vec!["v1".to_string(), "v2".to_string(), "v3".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        assert!(json.contains("\"versions\""));
        assert!(json.contains("\"v1\""));
        assert!(json.contains("\"v2\""));
        assert!(json.contains("\"v3\""));
    }

    #[test]
    fn test_version_query_deserialization() {
        // With version
        let json = r#"{"version": "v1"}"#;
        let query: VersionQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.version, Some("v1".to_string()));

        // Without version (empty object)
        let json = r#"{}"#;
        let query: VersionQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.version, None);
    }

    #[test]
    fn test_invalid_base64_data() {
        let invalid = "not-valid-base64!!!";
        let result = base64::engine::general_purpose::STANDARD.decode(invalid);
        assert!(result.is_err());
    }
}
