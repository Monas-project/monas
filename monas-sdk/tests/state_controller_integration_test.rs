// Integration tests intentionally use the test/dev-only `with_state_node_url` constructor.
#![allow(deprecated)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::state::{GetHistoryInput, GetLatestVersionInput, VerifyIntegrityInput};
use monas_sdk::{ApiError, MonasController, StateNodeAuthContext};

mod support;
use support::acquire_test_lock;

fn now_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn stale_auth_context() -> StateNodeAuthContext {
    StateNodeAuthContext {
        authorization: Some("Bearer x".into()),
        request_signature: Some("sig".into()),
        request_timestamp: Some(now_unix_timestamp().saturating_sub(3600)),
    }
}

fn missing_timestamp_auth_context() -> StateNodeAuthContext {
    StateNodeAuthContext {
        authorization: Some("Bearer x".into()),
        request_signature: Some("sig".into()),
        request_timestamp: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_history_maps_state_node_401_to_unauthorized() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let history_mock = server
        .mock("GET", "/content/test-content/history")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"missing auth"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.get_history(
        GetHistoryInput {
            content_id: "test-content".into(),
            limit: 10,
        },
        None,
    );

    assert!(!response.success, "get_history should fail");
    history_mock.assert();
    match response.error {
        Some(ApiError::Unauthorized(msg)) => assert!(msg.contains("missing auth")),
        other => panic!("expected Unauthorized, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_history_rejects_missing_timestamp_with_unauthorized() {
    let _guard = acquire_test_lock();
    let controller = MonasController::with_state_node_url("http://127.0.0.1:1");
    let auth = missing_timestamp_auth_context();

    let response = controller.get_history(
        GetHistoryInput {
            content_id: "test-content".into(),
            limit: 10,
        },
        Some(&auth),
    );

    assert!(!response.success);
    match response.error {
        Some(ApiError::Unauthorized(msg)) => {
            assert!(msg.contains("X-Request-Timestamp"), "msg={msg}");
            assert!(msg.contains("required"), "msg={msg}");
        }
        other => panic!("expected Unauthorized, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_latest_version_rejects_stale_timestamp_with_unauthorized() {
    let _guard = acquire_test_lock();
    let controller = MonasController::with_state_node_url("http://127.0.0.1:1");
    let auth = stale_auth_context();

    let response = controller.get_latest_version(
        GetLatestVersionInput {
            content_id: "test-content".into(),
        },
        Some(&auth),
    );

    assert!(!response.success);
    match response.error {
        Some(ApiError::Unauthorized(msg)) => {
            assert!(
                msg.contains("out of acceptable window"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected Unauthorized, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_integrity_rejects_stale_timestamp_with_unauthorized() {
    let _guard = acquire_test_lock();
    let controller = MonasController::with_state_node_url("http://127.0.0.1:1");
    let auth = stale_auth_context();

    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some("v1".into()),
        },
        Some(&auth),
    );

    assert!(!response.success);
    assert!(matches!(response.error, Some(ApiError::Unauthorized(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn get_history_maps_state_node_403_to_forbidden() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let history_mock = server
        .mock("GET", "/content/test-content/history")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.get_history(
        GetHistoryInput {
            content_id: "test-content".into(),
            limit: 10,
        },
        None,
    );

    assert!(!response.success, "get_history should fail");
    history_mock.assert();
    match response.error {
        Some(ApiError::Forbidden(msg)) => assert!(msg.contains("forbidden")),
        other => panic!("expected Forbidden, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_history_maps_state_node_409_to_conflict() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let history_mock = server
        .mock("GET", "/content/test-content/history")
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"version conflict"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.get_history(
        GetHistoryInput {
            content_id: "test-content".into(),
            limit: 10,
        },
        None,
    );

    assert!(!response.success, "get_history should fail");
    history_mock.assert();
    match response.error {
        Some(ApiError::Conflict(msg)) => assert!(msg.contains("version conflict")),
        other => panic!("expected Conflict, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_integrity_returns_api_error_when_history_cannot_be_fetched() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let history_mock = server
        .mock("GET", "/content/test-content/history")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"forbidden"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: None,
        },
        None,
    );

    assert!(!response.success, "verify_integrity should fail");
    history_mock.assert();
    match response.error {
        Some(ApiError::Forbidden(msg)) => assert!(msg.contains("forbidden")),
        other => panic!("expected Forbidden, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_integrity_returns_api_error_when_version_cannot_be_fetched() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let version_mock = server
        .mock("GET", "/content/test-content/version/v1")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"missing version"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some("v1".into()),
        },
        None,
    );

    assert!(!response.success, "verify_integrity should fail");
    version_mock.assert();
    match response.error {
        Some(ApiError::NotFound(msg)) => assert!(msg.contains("missing version")),
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_integrity_keeps_false_only_for_actual_content_mismatch() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let version_mock = server
        .mock("GET", "/content/test-content/version/v1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"test-content","data":"d29ybGQ=","version":"v1"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some("v1".into()),
        },
        None,
    );

    assert!(
        response.success,
        "verify_integrity should compare successfully"
    );
    version_mock.assert();
    let output = response.data.expect("verify_integrity should return data");
    assert!(!output.valid, "content mismatch should remain valid=false");
    assert!(
        output
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("content mismatch")),
        "reason should explain mismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_integrity_returns_api_error_for_invalid_state_node_base64() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let version_mock = server
        .mock("GET", "/content/test-content/version/v1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"test-content","data":"!!!not-base64!!!","version":"v1"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some("v1".into()),
        },
        None,
    );

    assert!(!response.success, "verify_integrity should fail");
    version_mock.assert();
    match response.error {
        Some(ApiError::Internal(msg)) => assert!(msg.contains("invalid base64 data")),
        other => panic!("expected Internal, got: {other:?}"),
    }
}
