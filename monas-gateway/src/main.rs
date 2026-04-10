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
use monas_sdk::models::share::{
    DecryptSharedContentInput, RevokeShareInput, ShareContentInput,
};
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
    let account_url =
        std::env::var("MONAS_ACCOUNT_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".into());
    let controller = Arc::new(MonasController::with_urls(state_node_url, account_url));

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
        .route("/share/decrypt", post(decrypt_shared_content))
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
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::keypair::GenerateKeypairOutput>>) {
    api_json(state.controller.generate_keypair(input))
}

async fn create_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateContentInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::content::CreateContentOutput>>) {
    let auth = build_state_node_auth_context(&headers);
    api_json(
        state
            .controller
            .create_content(input, Some(&auth)),
    )
}

async fn get_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::content::GetContentOutput>>) {
    let input = GetContentInput { content_id: id };
    api_json(state.controller.get_content(input))
}

async fn update_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<UpdateContentInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::content::UpdateContentOutput>>) {
    input.base_version_id = id;
    let auth = build_state_node_auth_context(&headers);
    api_json(
        state
            .controller
            .update_content(input, Some(&auth)),
    )
}

async fn delete_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::content::DeleteContentOutput>>) {
    let input = DeleteContentInput { content_id: id };
    let auth = build_state_node_auth_context(&headers);
    api_json(
        state
            .controller
            .delete_content(input, Some(&auth)),
    )
}

async fn share_content(
    State(state): State<AppState>,
    Json(input): Json<ShareContentInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::share::ShareContentOutput>>) {
    api_json(state.controller.share_content(input))
}

async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RevokeShareInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::share::RevokeShareOutput>>) {
    let auth = build_state_node_auth_context(&headers);
    api_json(state.controller.revoke_share(input, Some(&auth)))
}

async fn decrypt_shared_content(
    State(state): State<AppState>,
    Json(input): Json<DecryptSharedContentInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::share::DecryptSharedContentOutput>>) {
    api_json(state.controller.decrypt_shared_content(input))
}

async fn get_latest_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetLatestVersionInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::state::GetLatestVersionOutput>>) {
    let auth = build_state_node_auth_context(&headers);
    api_json(
        state
            .controller
            .get_latest_version(input, Some(&auth)),
    )
}

async fn get_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetHistoryInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::state::GetHistoryOutput>>) {
    let auth = build_state_node_auth_context(&headers);
    api_json(state.controller.get_history(input, Some(&auth)))
}

async fn verify_integrity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<VerifyIntegrityInput>,
) -> (StatusCode, Json<ApiResponse<monas_sdk::models::state::VerifyIntegrityOutput>>) {
    let auth = build_state_node_auth_context(&headers);
    api_json(
        state
            .controller
            .verify_integrity(input, Some(&auth)),
    )
}

fn api_json<T>(response: ApiResponse<T>) -> (StatusCode, Json<ApiResponse<T>>) {
    let status = response
        .error
        .as_ref()
        .and_then(|error| StatusCode::from_u16(error.status_code()).ok())
        .unwrap_or(StatusCode::OK);
    (status, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use monas_sdk::ApiError;
    use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
    use std::sync::Arc;

    #[test]
    fn api_json_uses_error_status_code() {
        let response: ApiResponse<()> =
            ApiResponse::error(ApiError::Forbidden("forbidden".into()), "trace_test".into());
        let (status, Json(body)) = api_json(response);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.success);
    }

    #[test]
    fn api_json_returns_ok_on_success() {
        let response = ApiResponse::success("ok", "trace_test".into());
        let (status, Json(body)) = api_json(response);
        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_content_handler_returns_bad_request_for_invalid_input() {
        let controller = Arc::new(MonasController::with_state_node_url("http://127.0.0.1:8080"));
        let state = State(AppState { controller });
        let headers = HeaderMap::new();
        let input = Json(CreateContentInput {
            content: String::new(),
            metadata: Some(ContentMetadata {
                name: Some("invalid.txt".into()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        });

        let (status, Json(body)) = create_content(state, headers, input).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.success);
        assert!(matches!(body.error, Some(ApiError::Validation(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_content_handler_returns_not_found_for_missing_local_content() {
        let controller = Arc::new(MonasController::with_state_node_url("http://127.0.0.1:8080"));
        let state = State(AppState { controller });
        let path = Path(String::from("missing-content-id"));

        let (status, Json(body)) = get_content(state, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.success);
        assert!(matches!(body.error, Some(ApiError::NotFound(_))));
    }
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
