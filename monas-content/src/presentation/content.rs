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
        CreateContentCommand, CreateContentResult, DecryptWithCekError, DeleteContentCommand,
        ReencryptContentCommand, ReencryptError, UpdateContentCommand,
    },
    domain::{
        content::ContentStatus, content_id::ContentId,
    },
};

use super::{
    AppState, decode_base64, decode_base64_optional, decode_cek_base64, decode_key_id_base64,
};

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
        .route("/contents/{id}/decrypt", post(decrypt_with_cek))
        .route("/contents/{id}/reencrypt", post(reencrypt_content))
}

async fn create_content(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateContentRequest>,
) -> Result<Json<CreateContentResponse>, (StatusCode, String)> {
    let raw = decode_base64(&req.content_base64, "content_base64")?;

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
    let raw_opt = decode_base64_optional(req.content_base64.as_deref(), "content_base64")?;

    if let Some(ref bytes) = raw_opt {
        if bytes.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "raw_content must not be empty".to_string(),
            ));
        }
    }

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

#[derive(Deserialize)]
pub struct DecryptWithCekRequest {
    pub cek_base64: String,
    pub ciphertext_base64: String,
}

#[derive(Serialize)]
pub struct DecryptWithCekResponse {
    pub content_base64: String,
}

async fn decrypt_with_cek(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<DecryptWithCekRequest>,
) -> Result<Json<DecryptWithCekResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(id);

    let cek = decode_cek_base64(&req.cek_base64, "cek_base64")?;

    let ciphertext = decode_base64(&req.ciphertext_base64, "ciphertext_base64")?;

    let plaintext = state
        .content_service
        .decrypt_with_cek(content_id, cek, ciphertext)
        .map_err(|e| {
            let status = match e {
                DecryptWithCekError::ContentIdMismatch { .. } => StatusCode::BAD_REQUEST,
                DecryptWithCekError::Domain(_) => StatusCode::BAD_REQUEST,
            };
            (status, e.to_string())
        })?;

    let content_base64 = BASE64_STANDARD.encode(&plaintext);

    Ok(Json(DecryptWithCekResponse { content_base64 }))
}

#[derive(Deserialize)]
pub struct ReencryptContentRequest {
    pub requester_key_id_base64: String,
    pub revoked_key_id_base64: String,
}

#[derive(Serialize)]
pub struct ReencryptContentResponse {
    pub content_id: String,
    pub series_id: String,
    pub name: String,
    pub path: String,
    pub updated_at: String,
    pub encrypted_content_base64: String,
}

async fn reencrypt_content(
    State(state): State<Arc<AppState>>,
    Path(content_id_str): Path<String>,
    Json(req): Json<ReencryptContentRequest>,
) -> Result<Json<ReencryptContentResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(content_id_str);

    // requester_key_id_base64をbase64デコードしてKeyIdに変換
    let requester_key_id = decode_key_id_base64(
        &req.requester_key_id_base64,
        "requester_key_id_base64",
    )?;

    // revoked_key_id_base64をbase64デコードしてKeyIdに変換
    let revoked_key_id = decode_key_id_base64(
        &req.revoked_key_id_base64,
        "revoked_key_id_base64",
    )?;

    // ReencryptContentCommandを構築
    let cmd = ReencryptContentCommand {
        content_id,
        requester_key_id,
        revoked_key_id,
    };

    // ContentService::reencrypt()を呼び出し
    let result = state.content_service.reencrypt(cmd).map_err(|e| {
        let status = match e {
            ReencryptError::ContentNotFound => StatusCode::NOT_FOUND,
            ReencryptError::ContentDeleted => StatusCode::NOT_FOUND,
            ReencryptError::ShareNotFound => StatusCode::NOT_FOUND,
            ReencryptError::OwnerPermissionDenied(..) => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, e.to_string())
    })?;

    // ReencryptContentResponseに変換
    let metadata = &result.metadata;
    let encrypted_content_base64 = BASE64_STANDARD.encode(&result.encrypted_content);

    Ok(Json(ReencryptContentResponse {
        content_id: result.content_id.as_str().to_string(),
        series_id: result.series_id.as_str().to_string(),
        name: metadata.name().to_string(),
        path: metadata.path().to_string(),
        updated_at: metadata.updated_at().to_rfc3339(),
        encrypted_content_base64,
    }))
}
