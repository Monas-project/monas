use std::sync::Arc;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, patch, post},
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{
    application_service::content_service::{
        CreateContentCommand, CreateContentResult, DeleteContentCommand, UpdateContentCommand,
    },
    domain::{content::ContentStatus, content_id::ContentId},
};

use super::AppState;

#[derive(Deserialize)]
pub struct CreateContentRequest {
    pub name: String,
    pub path: String,
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

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/contents", post(create_content))
        .route(
            "/contents/{id}",
            patch(update_content).delete(delete_content),
        )
        .route("/contents/{id}/fetch", get(fetch_content))
}

async fn create_content(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateContentRequest>,
) -> Result<Json<CreateContentResponse>, (StatusCode, String)> {
    let raw = match BASE64_STANDARD.decode(&req.content_base64) {
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
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateContentRequest>,
) -> Result<Json<CreateContentResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(id);

    // content_base64 が指定されている場合のみデコード
    let raw_opt = if let Some(b64) = req.content_base64 {
        let bytes = match BASE64_STANDARD.decode(&b64) {
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
    State(state): State<Arc<AppState>>,
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

#[derive(Serialize)]
pub struct FetchContentResponse {
    pub content_id: String,
    pub series_id: String,
    pub name: String,
    pub path: String,
    pub status: String,
    /// Base64でエンコードされた復号済みコンテンツバイナリ。
    pub content_base64: String,
}

async fn fetch_content(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<FetchContentResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(id);

    let result = state.content_service.fetch(content_id).map_err(|e| {
        // とりあえず NotFound 系は 404、それ以外は 400 として扱う。
        let status = match e {
            crate::application_service::content_service::FetchError::NotFound
            | crate::application_service::content_service::FetchError::Deleted => {
                StatusCode::NOT_FOUND
            }
            _ => StatusCode::BAD_REQUEST,
        };
        (status, e.to_string())
    })?;

    let metadata = &result.metadata;
    let status = format!("{:?}", ContentStatus::Active);

    let content_base64 = BASE64_STANDARD.encode(&result.raw_content);

    Ok(Json(FetchContentResponse {
        content_id: result.content_id.as_str().to_string(),
        series_id: result.series_id.as_str().to_string(),
        name: metadata.name().to_string(),
        path: metadata.path().to_string(),
        status,
        content_base64,
    }))
}
