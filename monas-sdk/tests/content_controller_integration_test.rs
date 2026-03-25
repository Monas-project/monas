use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::content::{
    ContentMetadata, CreateContentInput, DeleteContentInput, GetContentInput, UpdateContentInput,
};
use monas_sdk::ApiError;
use monas_sdk::MonasController;
mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

#[tokio::test(flavor = "multi_thread")]
async fn create_content_and_get_content_round_trip_succeeds_with_mock_state_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"ok":true}"#)
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

    let create_response = controller.create_content(create_input);
    assert!(create_response.success, "create_content should succeed");
    assert!(create_response.error.is_none(), "unexpected create error");

    let created = create_response
        .data
        .expect("create_content should return data");
    create_mock.assert();

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id,
        version: None,
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
    let create_response = controller.create_content(CreateContentInput {
        content: URL_SAFE_NO_PAD.encode(b"before-delete"),
        metadata: Some(ContentMetadata {
            name: Some("delete.txt".to_string()),
            content_type: Some("text/plain".to_string()),
            created_at: None,
            updated_at: None,
        }),
    });
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let delete_response = controller.delete_content(DeleteContentInput {
        content_id: created.content_id.clone(),
    });
    assert!(delete_response.success, "delete_content should succeed");
    assert!(delete_response.error.is_none(), "unexpected delete error");
    let deleted = delete_response.data.expect("delete should return data");
    delete_mock.assert();
    assert!(deleted.deleted, "deleted flag should be true");
    assert_eq!(deleted.content_id, created.content_id);

    let get_response = controller.get_content(GetContentInput {
        content_id: created.content_id,
        version: None,
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
async fn update_content_round_trip_succeeds_with_mock_state_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .create_async()
        .await;
    let update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());

    let create_response = controller.create_content(CreateContentInput {
        content: URL_SAFE_NO_PAD.encode(b"before-update"),
        metadata: Some(ContentMetadata {
            name: Some("before.txt".to_string()),
            content_type: Some("text/plain".to_string()),
            created_at: None,
            updated_at: None,
        }),
    });
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let update_response = controller.update_content(UpdateContentInput {
        content_id: created.content_id,
        content: URL_SAFE_NO_PAD.encode(b"after-update"),
        metadata: Some(ContentMetadata {
            name: Some("after.txt".to_string()),
            content_type: None,
            created_at: None,
            updated_at: None,
        }),
    });
    assert!(update_response.success, "update_content should succeed");
    assert!(update_response.error.is_none(), "unexpected update error");
    let updated = update_response.data.expect("update should return data");
    update_mock.assert();

    let get_response = controller.get_content(GetContentInput {
        content_id: updated.new_version,
        version: None,
    });
    assert!(
        get_response.success,
        "get_content should succeed after update"
    );
    let fetched = get_response.data.expect("get should return data");
    let fetched_bytes = URL_SAFE_NO_PAD
        .decode(fetched.content)
        .expect("updated content should be base64url");
    assert_eq!(fetched_bytes, b"after-update");

    cleanup_content_artifacts();
}
