use std::sync::Arc;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{
    application_service::share_service::{GrantShareCommand, RevokeShareCommand},
    domain::share::{
        key_envelope::{KeyEnvelope, KeyWrapAlgorithm, WrappedRecipientKey},
        KeyId,
    },
    domain::{content_id::ContentId, share::Permission},
};

use super::AppState;

#[derive(Deserialize)]
pub struct GrantShareRequest {
    pub content_id: String,
    pub sender_key_id_base64: String,
    pub recipient_public_key_base64: String,
    pub permission: String,
}

#[derive(Serialize)]
pub struct GrantShareResponse {
    pub content_id: String,
    pub sender_key_id: String,
    pub recipient_key_id: String,
    pub permission: String,
    pub enc_base64: String,
    pub wrapped_cek_base64: String,
    pub ciphertext_base64: String,
}

#[derive(Deserialize)]
pub struct UnwrapCekRequest {
    pub content_id: String,
    pub sender_key_id_base64: String,
    pub recipient_key_id_base64: String,
    pub enc_base64: String,
    pub wrapped_cek_base64: String,
    pub ciphertext_base64: String,
    pub recipient_private_key_base64: String,
}

#[derive(Serialize)]
pub struct UnwrapCekResponse {
    pub cek_base64: String,
}

#[derive(Serialize)]
pub struct RevokeShareResponse {
    pub content_id: String,
    pub recipient_key_id: String,
}

#[derive(Serialize)]
pub struct ShareRecipientView {
    pub recipient_key_id: String,
    pub permissions: Vec<String>,
}

#[derive(Serialize)]
pub struct GetShareResponse {
    pub content_id: String,
    pub recipients: Vec<ShareRecipientView>,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/shares", post(grant_share))
        .route("/shares/unwrap", post(unwrap_cek))
        .route(
            "/shares/{content_id}/{recipient_key_id}",
            delete(revoke_share),
        )
        .route("/shares/{content_id}", get(get_share))
}

async fn grant_share(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GrantShareRequest>,
) -> Result<Json<GrantShareResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(req.content_id.clone());

    let sender_key_bytes = BASE64_STANDARD
        .decode(&req.sender_key_id_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid sender_key_id_base64: {e}"),
            )
        })?;
    let sender_key_id = KeyId::new(sender_key_bytes);

    let recipient_pubkey = BASE64_STANDARD
        .decode(&req.recipient_public_key_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid recipient_public_key_base64: {e}"),
            )
        })?;

    let permission = match req.permission.to_lowercase().as_str() {
        "read" => Permission::Read,
        "write" => Permission::Write,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid permission value: {other}"),
            ))
        }
    };

    let cmd = GrantShareCommand {
        content_id,
        sender_key_id,
        recipient_public_key: recipient_pubkey,
        permission,
    };

    let result = state
        .share_service
        .grant_share(cmd)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let env = result.envelope;
    let recipient = env.recipient();
    let sender_key_id_b64 = BASE64_STANDARD.encode(env.sender_key_id().as_bytes());
    let recipient_key_id_b64 = BASE64_STANDARD.encode(recipient.key_id().as_bytes());
    let enc_b64 = BASE64_STANDARD.encode(recipient.enc());
    let wrapped_cek_b64 = BASE64_STANDARD.encode(recipient.wrapped_cek());
    let ciphertext_b64 = BASE64_STANDARD.encode(env.ciphertext());

    Ok(Json(GrantShareResponse {
        content_id: env.content_id().as_str().to_string(),
        sender_key_id: sender_key_id_b64,
        recipient_key_id: recipient_key_id_b64,
        permission: req.permission.to_lowercase(),
        enc_base64: enc_b64,
        wrapped_cek_base64: wrapped_cek_b64,
        ciphertext_base64: ciphertext_b64,
    }))
}

async fn unwrap_cek(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnwrapCekRequest>,
) -> Result<Json<UnwrapCekResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(req.content_id.clone());

    let sender_key_bytes = BASE64_STANDARD
        .decode(&req.sender_key_id_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid sender_key_id_base64: {e}"),
            )
        })?;
    let sender_key_id = KeyId::new(sender_key_bytes);

    let recipient_key_bytes = BASE64_STANDARD
        .decode(&req.recipient_key_id_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid recipient_key_id_base64: {e}"),
            )
        })?;
    let recipient_key_id = KeyId::new(recipient_key_bytes);

    let enc = BASE64_STANDARD
        .decode(&req.enc_base64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid enc_base64: {e}")))?;

    let wrapped_cek = BASE64_STANDARD
        .decode(&req.wrapped_cek_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid wrapped_cek_base64: {e}"),
            )
        })?;

    let ciphertext = BASE64_STANDARD
        .decode(&req.ciphertext_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid ciphertext_base64: {e}"),
            )
        })?;

    let recipient_private_key = BASE64_STANDARD
        .decode(&req.recipient_private_key_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid recipient_private_key_base64: {e}"),
            )
        })?;

    let recipient = WrappedRecipientKey::new(recipient_key_id, enc, wrapped_cek);
    let envelope = KeyEnvelope::new(
        content_id,
        KeyWrapAlgorithm::HpkeV1,
        sender_key_id,
        recipient,
        ciphertext,
    );

    let cek = state
        .share_service
        .unwrap_cek_from_envelope(&envelope, &recipient_private_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let cek_base64 = BASE64_STANDARD.encode(&cek.0);

    Ok(Json(UnwrapCekResponse { cek_base64 }))
}

async fn revoke_share(
    State(state): State<Arc<AppState>>,
    Path((content_id_str, recipient_key_id_b64)): Path<(String, String)>,
) -> Result<Json<RevokeShareResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(content_id_str.clone());

    let recipient_key_bytes = BASE64_STANDARD.decode(&recipient_key_id_b64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid recipient_key_id (base64): {e}"),
        )
    })?;
    let recipient_key_id = KeyId::new(recipient_key_bytes);

    let cmd = RevokeShareCommand {
        content_id,
        recipient_key_id,
    };

    let result = state
        .share_service
        .revoke_share(cmd)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(RevokeShareResponse {
        content_id: result.content_id.as_str().to_string(),
        recipient_key_id: recipient_key_id_b64,
    }))
}

async fn get_share(
    State(state): State<Arc<AppState>>,
    Path(content_id_str): Path<String>,
) -> Result<Json<GetShareResponse>, (StatusCode, String)> {
    let content_id = ContentId::new(content_id_str.clone());

    let share_opt = state
        .share_service
        .get_share(content_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let share = match share_opt {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "share not found for content".to_string(),
            ))
        }
    };

    let mut recipients = Vec::new();
    for (key_id, recipient) in share.recipients() {
        let key_id_b64 = BASE64_STANDARD.encode(key_id.as_bytes());
        let permissions = recipient
            .permissions()
            .iter()
            .map(|p| match p {
                Permission::Read => "read".to_string(),
                Permission::Write => "write".to_string(),
            })
            .collect();

        recipients.push(ShareRecipientView {
            recipient_key_id: key_id_b64,
            permissions,
        });
    }

    Ok(Json(GetShareResponse {
        content_id: content_id_str,
        recipients,
    }))
}
