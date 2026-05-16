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
use monas_sdk::models::share::{DecryptSharedContentInput, RevokeShareInput, ShareContentInput};
use monas_sdk::models::state::{GetHistoryInput, GetLatestVersionInput, VerifyIntegrityInput};
use monas_sdk::{
    generate_trace_id, ApiError, ApiResponse, MonasConfig, MonasController, StateNodeAuthContext,
};
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

    // 本番運用は MONAS_PERSISTENCE_DIR を必ず設定する。未設定時は in-memory にフォールバックし、
    // SDK 側で stderr に警告が出る (CEK と share が再起動で揮発する)。
    let mut config = MonasConfig::new(state_node_url, account_url);
    if let Ok(dir) = std::env::var("MONAS_PERSISTENCE_DIR") {
        config = config.with_persistence_dir(dir);
    }
    let controller = Arc::new(
        MonasController::with_config(config)
            .expect("failed to initialize MonasController persistence"),
    );

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
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::keypair::GenerateKeypairOutput>>,
) {
    api_json(
        Arc::clone(&state.controller)
            .generate_keypair_async(input)
            .await,
    )
}

async fn create_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateContentInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::content::CreateContentOutput>>,
) {
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .create_content_async(input, Some(auth))
            .await,
    )
}

async fn get_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::content::GetContentOutput>>,
) {
    let input = GetContentInput { content_id: id };
    api_json(Arc::clone(&state.controller).get_content_async(input).await)
}

async fn update_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<UpdateContentInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::content::UpdateContentOutput>>,
) {
    input.local_content_id = id;
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .update_content_async(input, Some(auth))
            .await,
    )
}

async fn delete_content(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<DeleteContentInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::content::DeleteContentOutput>>,
) {
    input.local_content_id = id;
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .delete_content_async(input, Some(auth))
            .await,
    )
}

async fn share_content(
    State(state): State<AppState>,
    Json(input): Json<ShareContentInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::share::ShareContentOutput>>,
) {
    api_json(
        Arc::clone(&state.controller)
            .share_content_async(input)
            .await,
    )
}

async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RevokeShareInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::share::RevokeShareOutput>>,
) {
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .revoke_share_async(input, Some(auth))
            .await,
    )
}

async fn decrypt_shared_content(
    State(state): State<AppState>,
    Json(input): Json<DecryptSharedContentInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::share::DecryptSharedContentOutput>>,
) {
    api_json(
        Arc::clone(&state.controller)
            .decrypt_shared_content_async(input)
            .await,
    )
}

async fn get_latest_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetLatestVersionInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::state::GetLatestVersionOutput>>,
) {
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .get_latest_version_async(input, Some(auth))
            .await,
    )
}

async fn get_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GetHistoryInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::state::GetHistoryOutput>>,
) {
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .get_history_async(input, Some(auth))
            .await,
    )
}

async fn verify_integrity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<VerifyIntegrityInput>,
) -> (
    StatusCode,
    Json<ApiResponse<monas_sdk::models::state::VerifyIntegrityOutput>>,
) {
    let auth = match build_state_node_auth_context(&headers) {
        Ok(auth) => auth,
        Err(error) => return auth_error_json(error),
    };
    api_json(
        Arc::clone(&state.controller)
            .verify_integrity_async(input, Some(auth))
            .await,
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

fn auth_error_json<T>(error: ApiError) -> (StatusCode, Json<ApiResponse<T>>) {
    api_json(ApiResponse::error(error, generate_trace_id()))
}

fn build_state_node_auth_context(headers: &HeaderMap) -> Result<StateNodeAuthContext, ApiError> {
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
        .ok_or_else(|| ApiError::Unauthorized("X-Request-Timestamp is required".into()))?
        .to_str()
        .map_err(|_| {
            ApiError::Unauthorized("X-Request-Timestamp must be a valid Unix timestamp".into())
        })?
        .parse::<u64>()
        .map_err(|_| {
            ApiError::Unauthorized("X-Request-Timestamp must be a valid Unix timestamp".into())
        })?;

    Ok(StateNodeAuthContext {
        authorization,
        request_signature,
        request_timestamp: Some(request_timestamp),
    })
}

#[cfg(test)]
#[allow(deprecated)] // tests use the test/dev-only `with_state_node_url` constructor
mod tests {
    use super::*;
    use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
    use std::sync::Arc;

    fn headers_with_timestamp(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-timestamp", value.parse().unwrap());
        headers
    }

    fn current_timestamp_header() -> HeaderMap {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        headers_with_timestamp(&ts)
    }

    fn valid_create_input() -> Json<CreateContentInput> {
        Json(CreateContentInput {
            content: "Z2F0ZXdheS1jb250ZW50".into(),
            metadata: Some(ContentMetadata {
                name: Some("gateway.txt".into()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        })
    }

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
        let controller = Arc::new(MonasController::with_state_node_url(
            "http://127.0.0.1:8080",
        ));
        let state = State(AppState { controller });
        let headers = current_timestamp_header();
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
    async fn create_content_handler_rejects_missing_timestamp() {
        let controller = Arc::new(MonasController::with_state_node_url(
            "http://127.0.0.1:8080",
        ));
        let state = State(AppState { controller });
        let headers = HeaderMap::new();

        let (status, Json(body)) = create_content(state, headers, valid_create_input()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!body.success);
        match body.error {
            Some(ApiError::Unauthorized(msg)) => {
                assert!(msg.contains("X-Request-Timestamp"), "msg={msg}");
                assert!(msg.contains("required"), "msg={msg}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_content_handler_rejects_malformed_timestamp() {
        let controller = Arc::new(MonasController::with_state_node_url(
            "http://127.0.0.1:8080",
        ));
        let state = State(AppState { controller });
        let headers = headers_with_timestamp("not-a-number");

        let (status, Json(body)) = create_content(state, headers, valid_create_input()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!body.success);
        match body.error {
            Some(ApiError::Unauthorized(msg)) => {
                assert!(msg.contains("valid Unix timestamp"), "msg={msg}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_content_handler_returns_not_found_for_missing_local_content() {
        let controller = Arc::new(MonasController::with_state_node_url(
            "http://127.0.0.1:8080",
        ));
        let state = State(AppState { controller });
        let path = Path(String::from("missing-content-id"));

        let (status, Json(body)) = get_content(state, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.success);
        assert!(matches!(body.error, Some(ApiError::NotFound(_))));
    }
}
