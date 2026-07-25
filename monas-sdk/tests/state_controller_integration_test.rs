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
            local_content_id: None,
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
            local_content_id: None,
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
            local_content_id: None,
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

    // State Node は Node CBOR を返す。CID 検証は通し、payload("world")と
    // 引数の content("hello")の不一致だけで valid=false になることを確認する。
    let node_bytes = support::node_mirror::make_node_bytes(b"world", vec![], None);
    let version_cid =
        monas_content::infrastructure::node_verification::recompute_node_cid(&node_bytes).unwrap();
    let body = serde_json::json!({
        "content_id": "test-content",
        "data": base64::engine::general_purpose::STANDARD.encode(&node_bytes),
        "version": version_cid,
    });
    let version_mock = server
        .mock(
            "GET",
            format!("/content/test-content/version/{version_cid}").as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body.to_string())
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some(version_cid.clone()),
            local_content_id: None,
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
async fn verify_integrity_rejects_forged_node_with_self_reported_version() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;

    // 攻撃シナリオ: クライアントは version V の検証を要求しているのに、
    // state node(攻撃者)は「クライアントの content と一致する偽 Node」と
    // その偽 Node 自身の CID を version フィールドに詰めて返す。
    // 応答内の自己申告 version に対して CID 照合すると必ず通ってしまうため、
    // 照合はクライアントが選択した version に束縛されなければならない。
    let real_node_bytes = support::node_mirror::make_node_bytes(b"secret-original", vec![], None);
    let real_version =
        monas_content::infrastructure::node_verification::recompute_node_cid(&real_node_bytes)
            .unwrap();

    let forged_node_bytes = support::node_mirror::make_node_bytes(b"hello", vec![], None);
    let forged_cid =
        monas_content::infrastructure::node_verification::recompute_node_cid(&forged_node_bytes)
            .unwrap();
    assert_ne!(real_version, forged_cid);

    let body = serde_json::json!({
        "content_id": "test-content",
        "data": base64::engine::general_purpose::STANDARD.encode(&forged_node_bytes),
        "version": forged_cid,
    });
    let version_mock = server
        .mock(
            "GET",
            format!("/content/test-content/version/{real_version}").as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body.to_string())
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let response = controller.verify_integrity(
        VerifyIntegrityInput {
            content_id: "test-content".into(),
            content: URL_SAFE_NO_PAD.encode(b"hello"),
            expected_version: Some(real_version.clone()),
            local_content_id: None,
        },
        None,
    );

    assert!(response.success, "verification itself should complete");
    version_mock.assert();
    let output = response.data.expect("verify_integrity should return data");
    assert!(
        !output.valid,
        "forged node must fail verification against the client-selected version"
    );
    assert!(
        output
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("CID verification")),
        "reason should point at CID verification failure: {:?}",
        output.reason
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
            local_content_id: None,
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
