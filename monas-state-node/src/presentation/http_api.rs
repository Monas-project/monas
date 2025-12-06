//! HTTP API for the state node.

use crate::application_service::state_node_service::StateNodeService;
use crate::infrastructure::crdt_repository::CrslCrdtRepository;
use crate::infrastructure::gossipsub_publisher::GossipsubEventPublisher;
use crate::infrastructure::network::Libp2pNetwork;
use crate::infrastructure::persistence::{SledContentNetworkRepository, SledNodeRegistry};
use crate::port::content_repository::ContentRepository;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
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
    >,
>;

/// Create the API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/node/info", get(node_info))
        .route("/node/register", post(register_node))
        .route("/nodes", get(list_nodes))
        .route("/content", post(create_content))
        .route("/content/:id", get(get_content))
        .route("/content/:id", put(update_content))
        .route("/contents", get(list_contents))
        // New CRDT-related endpoints
        .route("/content/:id/data", get(get_content_data))
        .route("/content/:id/history", get(get_content_history))
        .route("/content/:id/version/:version", get(get_content_version))
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
    pub member_nodes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContentResponse {
    pub content_id: String,
    pub member_nodes: Vec<String>,
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
pub struct ErrorResponse {
    pub error: String,
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
// Handlers
// ============================================================================

/// Health check endpoint.
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        node_id: state.local_node_id().to_string(),
    })
}

/// Get node info.
async fn node_info(State(state): State<AppState>) -> impl IntoResponse {
    let node_id = state.local_node_id().to_string();

    match state.get_node(&node_id).await {
        Ok(Some(node)) => Json(NodeInfoResponse {
            node_id: node.node_id,
            total_capacity: Some(node.total_capacity),
            available_capacity: Some(node.available_capacity),
        })
        .into_response(),
        Ok(None) => Json(NodeInfoResponse {
            node_id,
            total_capacity: None,
            available_capacity: None,
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

/// Register the local node.
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// List all nodes.
async fn list_nodes(State(state): State<AppState>) -> impl IntoResponse {
    match state.list_nodes().await {
        Ok(nodes) => Json::<Vec<String>>(nodes).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Create new content.
async fn create_content(
    State(state): State<AppState>,
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

    match state.create_content(&data).await {
        Ok(event) => {
            if let crate::domain::events::Event::ContentCreated {
                content_id,
                member_nodes,
                ..
            } = event
            {
                Json(CreateContentResponse {
                    content_id,
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Get content network info.
async fn get_content(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
) -> impl IntoResponse {
    match state.get_content_network(&content_id).await {
        Ok(Some(network)) => Json(ContentResponse {
            content_id: network.content_id,
            member_nodes: network.member_nodes.into_iter().collect(),
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Content not found: {}", content_id),
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

/// Update content.
async fn update_content(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
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

    match state.update_content(&content_id, &data).await {
        Ok(_) => Json(UpdateContentResponse {
            content_id,
            updated: true,
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

/// List all content networks.
async fn list_contents(State(state): State<AppState>) -> impl IntoResponse {
    match state.list_content_networks().await {
        Ok(contents) => Json::<Vec<String>>(contents).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// Get content data from CRDT repository.
///
/// Returns the latest version of the content data.
async fn get_content_data(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    Query(query): Query<VersionQuery>,
) -> impl IntoResponse {
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
async fn get_content_history(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
) -> impl IntoResponse {
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
async fn get_content_version(
    State(state): State<AppState>,
    Path((content_id, version)): Path<(String, String)>,
) -> impl IntoResponse {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
            node_id: "node-1".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"node_id\":\"node-1\""));
    }

    #[test]
    fn test_node_info_response_serialization() {
        let response = NodeInfoResponse {
            node_id: "node-1".to_string(),
            total_capacity: Some(1000),
            available_capacity: Some(800),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"node_id\":\"node-1\""));
        assert!(json.contains("\"total_capacity\":1000"));
        assert!(json.contains("\"available_capacity\":800"));
    }

    #[test]
    fn test_node_info_response_with_none() {
        let response = NodeInfoResponse {
            node_id: "node-1".to_string(),
            total_capacity: None,
            available_capacity: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"node_id\":\"node-1\""));
        assert!(json.contains("\"total_capacity\":null"));
        assert!(json.contains("\"available_capacity\":null"));
    }

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
            member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        assert!(json.contains("\"member_nodes\""));
        assert!(json.contains("\"node-1\""));
        assert!(json.contains("\"node-2\""));
    }

    #[test]
    fn test_content_response_serialization() {
        let response = ContentResponse {
            content_id: "cid-1".to_string(),
            member_nodes: vec!["node-1".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"content_id\":\"cid-1\""));
        assert!(json.contains("\"member_nodes\""));
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
    fn test_base64_encoding_roundtrip() {
        let original = b"Hello, World! This is test data.";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_invalid_base64_data() {
        let invalid = "not-valid-base64!!!";
        let result = base64::engine::general_purpose::STANDARD.decode(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_response_types_are_debug() {
        // Ensure all response types implement Debug
        let health = HealthResponse {
            status: "ok".to_string(),
            node_id: "n1".to_string(),
        };
        let _ = format!("{:?}", health);

        let node_info = NodeInfoResponse {
            node_id: "n1".to_string(),
            total_capacity: Some(100),
            available_capacity: None,
        };
        let _ = format!("{:?}", node_info);

        let error = ErrorResponse {
            error: "err".to_string(),
        };
        let _ = format!("{:?}", error);
    }
}
