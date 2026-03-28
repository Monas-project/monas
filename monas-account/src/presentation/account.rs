use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::post,
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::application_service::{
    AccountService, IssueDelegatedTokenError, IssueDelegatedTokenRequest, SignError,
};
use crate::domain::delegation::DelegatedCapability;

use super::AppState;

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub key_type: String,
}

#[derive(Serialize)]
pub struct CreateAccountResponse {
    pub algorithm: String,
    pub public_key_base64: String,
    pub secret_key_base64: String,
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub message_base64: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature_base64: String,
}

#[derive(Deserialize)]
pub struct DelegateTokenRequest {
    pub recipient_public_key_base64: String,
    pub content_id: String,
    pub capabilities: Vec<String>,
    pub ttl_secs: u64,
}

#[derive(Serialize)]
pub struct DelegateTokenResponse {
    pub delegated_token: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub jti: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounts", post(create_account).delete(delete_account))
        .route("/accounts/sign", post(sign_account))
        .route("/issuer/delegate", post(delegate_token))
}

fn parse_key_type(
    s: &str,
) -> Result<crate::application_service::KeyTypeMapper, (StatusCode, String)> {
    use crate::application_service::KeyTypeMapper;
    match s.to_uppercase().as_str() {
        "K256" => Ok(KeyTypeMapper::K256),
        "P256" => Ok(KeyTypeMapper::P256),
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported key_type: {other}"),
        )),
    }
}

async fn create_account(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, (StatusCode, String)> {
    let key_type = parse_key_type(&req.key_type)?;

    let account = AccountService::create(&state.key_store, key_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let public_key_base64 = BASE64_STANDARD.encode(account.public_key_bytes());
    let secret_key_base64 = BASE64_STANDARD.encode(account.secret_key_bytes());

    Ok(Json(CreateAccountResponse {
        algorithm: req.key_type.to_uppercase(),
        public_key_base64,
        secret_key_base64,
    }))
}

async fn delete_account(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, String)> {
    AccountService::delete(&state.key_store)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sign_account(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, (StatusCode, String)> {
    let msg = BASE64_STANDARD.decode(&req.message_base64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid message_base64: {e}"),
        )
    })?;

    let (sig, _rec_id) = AccountService::sign(&state.key_store, &msg).map_err(|e| {
        let status = match e {
            SignError::NotFound => StatusCode::NOT_FOUND,
            SignError::KeyStore(_) | SignError::InvalidKey(_) => StatusCode::BAD_REQUEST,
        };
        (status, e.to_string())
    })?;

    let signature_base64 = BASE64_STANDARD.encode(&sig);

    Ok(Json(SignResponse { signature_base64 }))
}

fn parse_capabilities(values: &[String]) -> Result<Vec<DelegatedCapability>, (StatusCode, String)> {
    let mut out = Vec::with_capacity(values.len());
    for capability in values {
        let item = match capability.trim().to_lowercase().as_str() {
            "read" => DelegatedCapability::Read,
            "write" => DelegatedCapability::Write,
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unsupported capability: {other}"),
                ));
            }
        };
        out.push(item);
    }
    Ok(out)
}

async fn delegate_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DelegateTokenRequest>,
) -> Result<Json<DelegateTokenResponse>, (StatusCode, String)> {
    let recipient_public_key = BASE64_STANDARD
        .decode(&req.recipient_public_key_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid recipient_public_key_base64: {e}"),
            )
        })?;

    let capabilities = parse_capabilities(&req.capabilities)?;

    let issued = AccountService::issue_delegated_token(
        &state.key_store,
        IssueDelegatedTokenRequest {
            recipient_public_key,
            content_id: req.content_id,
            capabilities,
            ttl_secs: req.ttl_secs,
        },
    )
    .map_err(|e| {
        let status = match e {
            IssueDelegatedTokenError::NotFound => StatusCode::NOT_FOUND,
            IssueDelegatedTokenError::Validation(_) => StatusCode::BAD_REQUEST,
            IssueDelegatedTokenError::UnsupportedAlgorithm(_) => StatusCode::BAD_REQUEST,
            IssueDelegatedTokenError::KeyStore(_)
            | IssueDelegatedTokenError::InvalidKey(_)
            | IssueDelegatedTokenError::JwtSigning(_)
            | IssueDelegatedTokenError::Time(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, e.to_string())
    })?;

    Ok(Json(DelegateTokenResponse {
        delegated_token: issued.delegated_token,
        issued_at: issued.issued_at,
        expires_at: issued.expires_at,
        jti: issued.jti,
    }))
}
