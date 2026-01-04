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

use crate::application_service::account_service::{AccountService, SignError};

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

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounts", post(create_account).delete(delete_account))
        .route("/accounts/sign", post(sign_account))
}

fn parse_key_type(
    s: &str,
) -> Result<crate::application_service::account_service::KeyTypeMapper, (StatusCode, String)> {
    use crate::application_service::account_service::KeyTypeMapper;
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
