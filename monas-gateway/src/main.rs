use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use monas_sdk::models::content::{
    CreateContentInput, DeleteContentInput, GetContentInput, UpdateContentInput,
};
use monas_sdk::models::keypair::GenerateKeypairInput;
use monas_sdk::models::share::{GetSharedContentInput, RevokeShareInput, ShareContentInput};
use monas_sdk::models::state::{GetHistoryInput, GetLatestVersionInput, VerifyIntegrityInput};
use monas_sdk::{ApiResponse, MonasController, StateNodeAuthContext};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    controller: Arc<MonasController>,
}

#[tokio::main]
async fn main() {
    // monas-sdk側でもenvを見るが、ここで明示的に読むことで挙動が分かりやすくなる
    let state_node_url =
        std::env::var("MONAS_STATE_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let controller = Arc::new(MonasController::with_state_node_url(state_node_url));

    let app_state = AppState { controller };

    let app = Router::new()
        .route("/health", get(health))
        .route("/keypair", post(generate_keypair))
        .route("/content", post(create_content))
        .route(
            "/content/{id}",
            get(get_content).put(update_content).delete(delete_content),
        )
        // share
        .route("/share", post(share_content))
        .route("/share/revoke", post(revoke_share))
        .route("/share/get", post(get_shared_content))
        // state
        .route("/state/latest-version", post(get_latest_version))
        .route("/state/history", post(get_history))
        .route("/state/verify-integrity", post(verify_integrity))
        .with_state(app_state);

    let port: u16 = std::env::var("MONAS_API_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("monas-gateway listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn generate_keypair(
    State(state): State<AppState>,
    Json(input): Json<GenerateKeypairInput>,
) -> Json<ApiResponse<monas_sdk::models::keypair::GenerateKeypairOutput>> {
    Json(state.controller.generate_keypair(input))
}

async fn create_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateContentInput>,
) -> Json<ApiResponse<monas_sdk::models::content::CreateContentOutput>> {
    let auth = build_state_node_auth_context(&headers);
    Json(
        state
            .controller
            .create_content_with_auth(input, Some(&auth)),
    )
}

async fn get_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<monas_sdk::models::content::GetContentOutput>> {
    let input = GetContentInput {
        content_id: id,
        version: None,
    };
    Json(state.controller.get_content(input))
}

async fn update_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<UpdateContentInput>,
) -> Json<ApiResponse<monas_sdk::models::content::UpdateContentOutput>> {
    input.content_id = id;
    let auth = build_state_node_auth_context(&headers);
    Json(
        state
            .controller
            .update_content_with_auth(input, Some(&auth)),
    )
}

async fn delete_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Json<ApiResponse<monas_sdk::models::content::DeleteContentOutput>> {
    let input = DeleteContentInput { content_id: id };
    let auth = build_state_node_auth_context(&headers);
    Json(
        state
            .controller
            .delete_content_with_auth(input, Some(&auth)),
    )
}

async fn share_content(
    State(state): State<AppState>,
    Json(input): Json<ShareContentInput>,
) -> Json<ApiResponse<monas_sdk::models::share::ShareContentOutput>> {
    Json(state.controller.share_content(input))
}

async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RevokeShareInput>,
) -> Json<ApiResponse<monas_sdk::models::share::RevokeShareOutput>> {
    let auth = build_state_node_auth_context(&headers);
    Json(state.controller.revoke_share_with_auth(input, Some(&auth)))
}

async fn get_shared_content(
    State(state): State<AppState>,
    Json(input): Json<GetSharedContentInput>,
) -> Json<ApiResponse<monas_sdk::models::share::GetSharedContentOutput>> {
    Json(state.controller.get_shared_content(input))
}

async fn get_latest_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetLatestVersionInput>,
) -> Json<ApiResponse<monas_sdk::models::state::GetLatestVersionOutput>> {
    let auth = build_state_node_auth_context(&headers);
    Json(
        state
            .controller
            .get_latest_version_with_auth(input, Some(&auth)),
    )
}

async fn get_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetHistoryInput>,
) -> Json<ApiResponse<monas_sdk::models::state::GetHistoryOutput>> {
    let auth = build_state_node_auth_context(&headers);
    Json(state.controller.get_history_with_auth(input, Some(&auth)))
}

async fn verify_integrity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<VerifyIntegrityInput>,
) -> Json<ApiResponse<monas_sdk::models::state::VerifyIntegrityOutput>> {
    let auth = build_state_node_auth_context(&headers);
    Json(
        state
            .controller
            .verify_integrity_with_auth(input, Some(&auth)),
    )
}

fn build_state_node_auth_context(headers: &HeaderMap) -> StateNodeAuthContext {
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let request_signature = headers
        .get("x-request-signature")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let request_timestamp = headers
        .get("x-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    StateNodeAuthContext {
        authorization,
        request_signature,
        request_timestamp,
    }
}
