use std::sync::Arc;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, patch, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    application_service::content_service::{
        ContentService, CreateContentCommand, CreateContentResult, DeleteContentCommand,
        UpdateContentCommand,
    },
    domain::content_id::ContentId,
    infrastructure::{
        content_id::Sha256ContentIdGenerator,
        encryption::{SimpleContentEncryption, SimpleContentEncryptionKeyGenerator},
        repository::InMemoryContentRepository,
        state_node_client::NoopStateNodeClient,
    },
};

#[derive(Clone)]
struct AppState {
    content_service: Arc<
        ContentService<
            Sha256ContentIdGenerator,
            InMemoryContentRepository,
            NoopStateNodeClient,
            SimpleContentEncryptionKeyGenerator,
            SimpleContentEncryption,
        >,
    >,
}

#[derive(Deserialize)]
pub struct CreateContentRequest {
    pub name: String,
    pub path: String,
    /// Base64でエンコードされたコンテンツバイナリ。
    pub content_base64: String,
}

#[derive(Serialize)]
pub struct CreateContentResponse {
    pub content_id: String,
    pub name: String,
    pub path: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct UpdateContentRequest {
    pub name: Option<String>,
    pub content_base64: Option<String>,
}

async fn health() -> &'static str {
    "ok"
}

async fn create_content(
    State(state): State<AppState>,
    Json(req): Json<CreateContentRequest>,
) -> Result<Json<CreateContentResponse>, (StatusCode, String)> {
    let raw = match base64::decode(&req.content_base64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid base64 content: {e}"),
            ))
        }
    };

    let cmd = CreateContentCommand {
        name: req.name,
        path: req.path,
        raw_content: raw,
    };

    let result = state
        .content_service
        .create(cmd)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(to_response(result)))
}

fn to_response(result: CreateContentResult) -> CreateContentResponse {
    let metadata = &result.metadata;
    CreateContentResponse {
        content_id: result.content_id.as_str().to_string(),
        name: metadata.name().to_string(),
        path: metadata.path().to_string(),
        status: format!("{:?}", crate::domain::content::ContentStatus::Active),
    }
}

async fn update_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateContentRequest>,
) -> Result<Json<CreateContentResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(id);

    // content_base64 が指定されている場合のみデコード
    let raw_opt = if let Some(b64) = req.content_base64 {
        let bytes = match base64::decode(&b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("invalid base64 content: {e}"),
                ))
            }
        };

        if bytes.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "raw_content must not be empty".to_string(),
            ));
        }

        Some(bytes)
    } else {
        None
    };

    let cmd = UpdateContentCommand {
        content_id,
        new_name: req.name,
        new_raw_content: raw_opt,
    };

    let result = state
        .content_service
        .update(cmd)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let metadata = &result.metadata;
    Ok(Json(CreateContentResponse {
        content_id: result.content_id.as_str().to_string(),
        name: metadata.name().to_string(),
        path: metadata.path().to_string(),
        status: format!("{:?}", crate::domain::content::ContentStatus::Active),
    }))
}

async fn delete_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let content_id = ContentId::new(id);

    let cmd = DeleteContentCommand { content_id };

    state
        .content_service
        .delete(cmd)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn create_router() -> Router {
    let service = ContentService {
        content_id_generator: Sha256ContentIdGenerator,
        content_repository: InMemoryContentRepository::default(),
        state_node_client: NoopStateNodeClient::default(),
        key_generator: SimpleContentEncryptionKeyGenerator,
        encryptor: SimpleContentEncryption,
    };

    let state = AppState {
        content_service: Arc::new(service),
    };

    Router::new()
        .route("/health", get(health))
        .route("/contents", post(create_content))
        .route("/contents/{id}", patch(update_content).delete(delete_content))
        .with_state(state)
}
