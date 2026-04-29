use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use mockito::Server;
use monas_sdk::models::content::{
    ContentMetadata, CreateContentInput, DeleteContentInput, GetContentInput, UpdateContentInput,
};
use monas_sdk::{ApiError, MonasConfig, MonasController, StateNodeAuthContext};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

fn compute_content_id(raw_content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_content);
    format!("{:x}", hasher.finalize())
}

/// `X-Request-Timestamp` の skew チェックを実質的に無効化した `MonasController`。
///
/// 古い固定値 (e.g. `1_717_171_717`) で署名検証する旧来テスト用のヘルパ。
/// 本番運用ではこの設定を使わない。
fn controller_for_legacy_timestamps(
    state_node_url: String,
    account_url: String,
) -> MonasController {
    let config = MonasConfig::new(state_node_url, account_url)
        // 100 年以上の skew を許容することで、テスト固定 timestamp の絶対値を気にしなくてよくする。
        .with_request_timestamp_skew(Duration::from_secs(60 * 60 * 24 * 365 * 100));
    MonasController::with_config(config).expect("with_config")
}

#[tokio::test(flavor = "multi_thread")]
async fn create_content_and_get_content_round_trip_succeeds_with_mock_state_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkqaaa-test-remote"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let raw_content = b"integration test content";
    let content_base64url = URL_SAFE_NO_PAD.encode(raw_content);

    let create_input = CreateContentInput {
        content: content_base64url.clone(),
        metadata: Some(ContentMetadata {
            name: Some("test.txt".to_string()),
            content_type: Some("text/plain".to_string()),
            created_at: None,
            updated_at: None,
        }),
    };

    let create_response = controller.create_content(create_input, None);
    assert!(create_response.success, "create_content should succeed");
    assert!(create_response.error.is_none(), "unexpected create error");

    let created = create_response
        .data
        .expect("create_content should return data");
    assert_eq!(
        created.remote_content_id.as_deref(),
        Some("bafkqaaa-test-remote")
    );
    create_mock.assert();

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id,
    });

    assert!(get_response.success, "get_content should succeed");
    assert!(get_response.error.is_none(), "unexpected get error");

    let fetched = get_response.data.expect("get_content should return data");
    let fetched_bytes = URL_SAFE_NO_PAD
        .decode(fetched.content)
        .expect("fetched content should be base64url");

    assert_eq!(fetched_bytes, raw_content);
    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_content_round_trip_succeeds() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkdelete-roundtrip"}"#)
        .create_async()
        .await;
    let delete_mock = server
        .mock(
            "DELETE",
            mockito::Matcher::Regex(r"^/content/.+$".to_string()),
        )
        .with_status(200)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"before-delete"),
            metadata: Some(ContentMetadata {
                name: Some("delete.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let delete_response = controller.delete_content(
        DeleteContentInput {
            local_content_id: created.content_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
        },
        None,
    );
    assert!(delete_response.success, "delete_content should succeed");
    assert!(delete_response.error.is_none(), "unexpected delete error");
    let deleted = delete_response.data.expect("delete should return data");
    delete_mock.assert();
    assert!(deleted.deleted, "deleted flag should be true");
    assert_eq!(deleted.content_id, created.content_id);

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id,
    });
    assert!(
        !get_response.success,
        "get_content should fail after delete"
    );
    assert!(get_response.data.is_none(), "no data expected after delete");
    match get_response.error {
        Some(ApiError::NotFound(msg)) => {
            assert!(
                msg.contains("deleted") || msg.contains("not found"),
                "unexpected not found message: {msg}"
            );
        }
        other => panic!("expected NotFound error, got: {other:?}"),
    }

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_content_rolls_back_locally_when_state_node_delete_fails() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkdelete-rollback"}"#)
        .create_async()
        .await;
    let delete_mock = server
        .mock(
            "DELETE",
            mockito::Matcher::Regex(r"^/content/.+$".to_string()),
        )
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"delete failed"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let raw_content = b"delete-rollback";
    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(raw_content),
            metadata: Some(ContentMetadata {
                name: Some("rollback.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let delete_response = controller.delete_content(
        DeleteContentInput {
            local_content_id: created.content_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
        },
        None,
    );
    assert!(
        !delete_response.success,
        "delete_content should fail when state node delete fails"
    );
    delete_mock.assert();

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id.clone(),
    });
    assert!(
        get_response.success,
        "get_content should succeed after local rollback"
    );
    let fetched = get_response.data.expect("get should return data");
    let fetched_bytes = URL_SAFE_NO_PAD
        .decode(fetched.content)
        .expect("fetched content should be base64url");
    assert_eq!(fetched_bytes, raw_content);

    let second_delete_response = controller.delete_content(
        DeleteContentInput {
            local_content_id: created.content_id,
            remote_content_id: created
                .remote_content_id
                .expect("create should return remote_content_id"),
        },
        None,
    );
    assert!(
        !second_delete_response.success,
        "delete should remain re-executable after rollback"
    );

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn update_content_round_trip_succeeds_with_mock_state_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkupdate-roundtrip"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());

    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"before-update"),
            metadata: Some(ContentMetadata {
                name: Some("before.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();
    let update_mock = server
        .mock(
            "PUT",
            mockito::Matcher::Exact(format!(
                "/content/{}",
                created
                    .remote_content_id
                    .as_ref()
                    .expect("create should return remote_content_id")
            )),
        )
        .expect(2)
        .with_status(200)
        .create_async()
        .await;

    let first_update_response = controller.update_content(
        UpdateContentInput {
            local_content_id: created.content_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
            content: URL_SAFE_NO_PAD.encode(b"after-update"),
            metadata: Some(ContentMetadata {
                name: Some("after.txt".to_string()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(
        first_update_response.success,
        "first update_content should succeed"
    );
    assert!(
        first_update_response.error.is_none(),
        "unexpected first update error"
    );
    let first_updated = first_update_response
        .data
        .expect("first update should return data");
    assert_eq!(first_updated.series_id, created.content_id);
    assert_eq!(first_updated.previous_version_id, first_updated.series_id);

    let second_update_response = controller.update_content(
        UpdateContentInput {
            local_content_id: first_updated.version_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
            content: URL_SAFE_NO_PAD.encode(b"after-second-update"),
            metadata: Some(ContentMetadata {
                name: Some("after-second.txt".to_string()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(
        second_update_response.success,
        "second update_content should succeed"
    );
    assert!(
        second_update_response.error.is_none(),
        "unexpected second update error"
    );
    let second_updated = second_update_response
        .data
        .expect("second update should return data");
    update_mock.assert();
    assert_eq!(second_updated.series_id, created.content_id);
    assert_eq!(second_updated.previous_version_id, first_updated.version_id);

    let get_response = controller.get_content(GetContentInput {
        content_id: second_updated.version_id,
    });
    assert!(
        get_response.success,
        "get_content should succeed after second update"
    );
    let fetched = get_response.data.expect("get should return data");
    let fetched_bytes = URL_SAFE_NO_PAD
        .decode(fetched.content)
        .expect("updated content should be base64url");
    assert_eq!(fetched_bytes, b"after-second-update");

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn create_content_rolls_back_locally_when_state_node_create_fails_and_can_retry() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let failing_create_mock = server
        .mock("POST", "/content")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"create failed"}"#)
        .expect(1)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let raw_content = b"create-rollback";
    let create_input = CreateContentInput {
        content: URL_SAFE_NO_PAD.encode(raw_content),
        metadata: Some(ContentMetadata {
            name: Some("create-rollback.txt".to_string()),
            content_type: Some("text/plain".to_string()),
            created_at: None,
            updated_at: None,
        }),
    };

    let first_response = controller.create_content(create_input.clone(), None);
    assert!(
        !first_response.success,
        "create_content should fail when state node create fails"
    );
    failing_create_mock.assert();

    let succeeding_create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkcreate-retry"}"#)
        .expect(1)
        .create_async()
        .await;

    let second_response = controller.create_content(create_input, None);
    assert!(
        second_response.success,
        "create_content should be retryable after rollback: {:?}",
        second_response.error
    );
    let created = second_response
        .data
        .expect("second create should return data");
    succeeding_create_mock.assert();

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id,
    });
    assert!(get_response.success, "created content should be readable");
    let fetched = get_response.data.expect("get should return data");
    let fetched_bytes = URL_SAFE_NO_PAD
        .decode(fetched.content)
        .expect("fetched content should be base64url");
    assert_eq!(fetched_bytes, raw_content);

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn create_content_uses_account_signature_for_state_node_request() {
    let _guard = acquire_test_lock();
    let mut state_node_server = Server::new_async().await;
    let mut account_server = Server::new_async().await;

    let account_sign_mock = account_server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"P256"}"#,
        )
        .expect(1)
        .create_async()
        .await;

    let create_mock = state_node_server
        .mock("POST", "/content")
        .match_header("authorization", "user:010203")
        .match_header("x-request-signature", "c2lnbmVk")
        .match_header("x-request-timestamp", "1717171717")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"remote-id-for-auth-test"}"#)
        .expect(1)
        .create_async()
        .await;

    let controller =
        controller_for_legacy_timestamps(state_node_server.url(), account_server.url());
    let auth = StateNodeAuthContext {
        authorization: Some("Bearer old".into()),
        request_signature: Some("old-signature".into()),
        request_timestamp: Some(1_717_171_717),
    };

    let response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"account-signed-content"),
            metadata: Some(ContentMetadata {
                name: Some("account-signed.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        Some(&auth),
    );

    assert!(response.success, "create_content should succeed");
    account_sign_mock.assert();
    create_mock.assert();
    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn create_content_fails_fast_when_account_key_is_not_p256() {
    let _guard = acquire_test_lock();
    let state_node_server = Server::new_async().await;
    let mut account_server = Server::new_async().await;

    let account_sign_mock = account_server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"K256"}"#,
        )
        .expect(1)
        .create_async()
        .await;

    let controller =
        controller_for_legacy_timestamps(state_node_server.url(), account_server.url());
    let auth = StateNodeAuthContext {
        authorization: None,
        request_signature: None,
        request_timestamp: Some(1_717_171_717),
    };

    let response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"account-signing-with-k256"),
            metadata: Some(ContentMetadata {
                name: Some("invalid-algorithm.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        Some(&auth),
    );

    assert!(!response.success, "create_content should fail");
    assert!(matches!(response.error, Some(ApiError::Validation(_))));
    account_sign_mock.assert();
    let _ = state_node_server;
    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn update_content_rolls_back_new_version_when_state_node_update_fails() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkupdate-rollback"}"#)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());
    let original_raw = b"before-update-rollback";
    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(original_raw),
            metadata: Some(ContentMetadata {
                name: Some("before-rollback.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let updated_raw = b"after-update-rollback";
    let failed_update_mock = server
        .mock(
            "PUT",
            mockito::Matcher::Exact(format!(
                "/content/{}",
                created
                    .remote_content_id
                    .as_ref()
                    .expect("create should return remote_content_id")
            )),
        )
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"update failed"}"#)
        .expect(1)
        .create_async()
        .await;

    let failed_update = controller.update_content(
        UpdateContentInput {
            local_content_id: created.content_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
            content: URL_SAFE_NO_PAD.encode(updated_raw),
            metadata: Some(ContentMetadata {
                name: Some("after-rollback.txt".to_string()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(
        !failed_update.success,
        "update_content should fail when state node update fails"
    );
    failed_update_mock.assert();

    let old_version_response = controller.get_content(GetContentInput {
        content_id: created.content_id.clone(),
    });
    assert!(
        old_version_response.success,
        "base version should still be readable after rollback"
    );
    let old_version = old_version_response.data.expect("old version should exist");
    let old_bytes = URL_SAFE_NO_PAD
        .decode(old_version.content)
        .expect("old content should be base64url");
    assert_eq!(old_bytes, original_raw);

    let expected_new_version_id = compute_content_id(updated_raw);
    let rolled_back_version_response = controller.get_content(GetContentInput {
        content_id: expected_new_version_id.clone(),
    });
    assert!(
        !rolled_back_version_response.success,
        "rolled back version should not remain readable"
    );
    match rolled_back_version_response.error {
        Some(ApiError::NotFound(msg)) => {
            assert!(
                msg.contains("deleted") || msg.contains("not found"),
                "unexpected rolled back version error: {msg}"
            );
        }
        other => panic!("expected NotFound for rolled back version, got: {other:?}"),
    }

    let succeeding_update_mock = server
        .mock(
            "PUT",
            mockito::Matcher::Exact(format!(
                "/content/{}",
                created
                    .remote_content_id
                    .as_ref()
                    .expect("create should return remote_content_id")
            )),
        )
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let second_update = controller.update_content(
        UpdateContentInput {
            local_content_id: created.content_id.clone(),
            remote_content_id: created
                .remote_content_id
                .clone()
                .expect("create should return remote_content_id"),
            content: URL_SAFE_NO_PAD.encode(updated_raw),
            metadata: Some(ContentMetadata {
                name: Some("after-rollback.txt".to_string()),
                content_type: None,
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(
        second_update.success,
        "update_content should be retryable after rollback: {:?}",
        second_update.error
    );
    let updated = second_update
        .data
        .expect("second update should return data");
    succeeding_update_mock.assert();
    assert_eq!(updated.version_id, expected_new_version_id);

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_content_uses_account_signature_for_metadata_request() {
    let _guard = acquire_test_lock();
    let mut state_node_server = Server::new_async().await;
    let mut account_server = Server::new_async().await;

    let create_mock = state_node_server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"bafkdelete-signed"}"#)
        .expect(1)
        .create_async()
        .await;

    let controller =
        controller_for_legacy_timestamps(state_node_server.url(), account_server.url());
    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"delete-account-signed"),
                metadata: Some(ContentMetadata {
                    name: Some("delete-account-signed.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create should return data");
    create_mock.assert();

    let expected_signing_message =
        BASE64_STANDARD.encode(format!("delete:{}:1818181818", "bafkdelete-signed").as_bytes());

    let account_sign_mock = account_server
        .mock("POST", "/accounts/sign")
        .match_body(mockito::Matcher::PartialJsonString(format!(
            r#"{{"message_base64":"{expected_signing_message}"}}"#
        )))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"bWV0YS1zaWc=","public_key_base64":"BAUG","algorithm":"P256"}"#,
        )
        .expect(1)
        .create_async()
        .await;

    let delete_mock = state_node_server
        .mock(
            "DELETE",
            mockito::Matcher::Exact("/content/bafkdelete-signed".to_string()),
        )
        .match_header("authorization", "user:040506")
        .match_header("x-request-signature", "bWV0YS1zaWc=")
        .match_header("x-request-timestamp", "1818181818")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let auth = StateNodeAuthContext {
        authorization: None,
        request_signature: None,
        request_timestamp: Some(1_818_181_818),
    };

    let response = controller.delete_content(
        DeleteContentInput {
            local_content_id: created.content_id,
            remote_content_id: created
                .remote_content_id
                .expect("create should return remote_content_id"),
        },
        Some(&auth),
    );

    assert!(
        response.success,
        "delete_content should succeed: {:?}",
        response.error
    );
    account_sign_mock.assert();
    delete_mock.assert();
    cleanup_content_artifacts();
}

/// §4: State Node が content_id を返さない場合 (例: `{"ok":true}`) は成功扱いせず
/// `ApiError::Internal` にする。
///
/// 以前は `StateNodeCreateContentResponse.content_id` が `#[serde(default)]` で
/// 空文字を許容していたため、silent に `remote_content_id=None` の CreateContentOutput が
/// 返り、後続の update/delete で `remote_content_id` が必須になると二度と操作できない
/// コンテンツが量産される状態だった。
#[tokio::test(flavor = "multi_thread")]
async fn create_content_fails_when_state_node_omits_content_id() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"ok":true}"#)
        .expect(1)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());

    let response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"silent-none-repro"),
            metadata: Some(ContentMetadata {
                name: Some("silent-none.txt".into()),
                content_type: Some("text/plain".into()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );

    assert!(
        !response.success,
        "create_content must NOT succeed when state node omits content_id"
    );
    match response.error {
        Some(ApiError::Internal(msg)) => {
            let lower = msg.to_lowercase();
            assert!(
                lower.contains("content_id"),
                "error message should mention content_id, got: {msg}"
            );
        }
        other => panic!("expected ApiError::Internal about content_id, got {other:?}"),
    }

    cleanup_content_artifacts();
}

/// §2: `MonasConfig::with_request_timeout` が効き、State Node がハングする場合に
/// `ApiError::Timeout` が設定した時間内に返ることを検証する。
///
/// TcpListener を bind するが accept しないダミーサーバを立てる。
/// OS によっては connect は成功するが read/write が応答しないため、
/// 設定したグローバルタイムアウトで打ち切られるはず。
#[tokio::test(flavor = "multi_thread")]
async fn create_content_returns_timeout_when_state_node_hangs() {
    let _guard = acquire_test_lock();

    // accept しないダミーサーバ
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}");

    let config =
        MonasConfig::new(url.clone(), url).with_request_timeout(Duration::from_millis(200));
    let controller = MonasController::with_config(config).expect("with_config");

    let input = CreateContentInput {
        content: URL_SAFE_NO_PAD.encode(b"timeout test"),
        metadata: Some(ContentMetadata {
            name: Some("timeout.txt".into()),
            content_type: Some("text/plain".into()),
            created_at: None,
            updated_at: None,
        }),
    };

    let started = Instant::now();
    let response = controller.create_content(input, None);
    let elapsed = started.elapsed();

    assert!(!response.success, "should fail due to timeout");
    match response.error {
        Some(ApiError::Timeout(_)) => {}
        other => panic!("expected ApiError::Timeout, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout should fire well under 3s, took {elapsed:?}"
    );

    // listener は drop で自動的に閉じる。念のため明示。
    drop(listener);
    cleanup_content_artifacts();
}
