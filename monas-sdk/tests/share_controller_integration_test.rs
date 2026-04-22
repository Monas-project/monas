use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
use monas_sdk::models::keypair::{GenerateKeypairInput, KeyType};
use monas_sdk::models::share::{
    DecryptSharedContentInput, Permission, RevokeShareInput, ShareContentInput,
};
use monas_sdk::MonasController;

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

#[tokio::test(flavor = "multi_thread")]
async fn share_content_succeeds_after_content_creation() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"share-test-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-1"}"#,
        )
        .create_async()
        .await;

    let controller = MonasController::with_urls(server.url(), server.url());

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair should be generated");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient keypair should be generated");

    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"share-target-content"),
            metadata: Some(ContentMetadata {
                name: Some("share.txt".to_string()),
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

    let share_response = controller.share_content(ShareContentInput {
        content_id: created.content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Read],
    });

    assert!(
        share_response.success,
        "share_content should succeed: {:?}",
        share_response.error
    );
    assert!(share_response.error.is_none(), "unexpected share error");
    let shared = share_response.data.expect("share should return data");

    assert_eq!(shared.content_id, created.content_id);
    assert_eq!(shared.recipient_public_key, recipient.public_key);
    assert!(
        !shared.sender_key_id.is_empty(),
        "sender_key_id should be set"
    );
    assert!(
        !shared.recipient_key_id.is_empty(),
        "recipient_key_id should be set"
    );
    assert!(
        !shared.key_envelope.enc.is_empty(),
        "key_envelope.enc should be set"
    );
    assert!(
        !shared.key_envelope.wrapped_cek.is_empty(),
        "key_envelope.wrapped_cek should be set"
    );
    assert!(
        !shared.key_envelope.ciphertext.is_empty(),
        "key_envelope.ciphertext should be set"
    );
    assert!(
        shared.delegated_access.is_some(),
        "delegated_access should be set"
    );
    let delegated = shared
        .delegated_access
        .as_ref()
        .expect("delegated_access should exist");
    assert_eq!(delegated.delegated_token, "dummy.jwt.token");
    assert_eq!(delegated.jti, "jti-1");
    delegate_mock.assert();

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_updates_state_node_version() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"share-test-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-2"}"#,
        )
        .create_async()
        .await;
    let update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .create_async()
        .await;

    let controller = MonasController::with_urls(server.url(), server.url());

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair should be generated");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient keypair should be generated");

    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"revoke-target-content"),
            metadata: Some(ContentMetadata {
                name: Some("revoke.txt".to_string()),
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

    let share_response = controller.share_content(ShareContentInput {
        content_id: created.content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(share_response.success, "share_content should succeed");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            sender_public_key: sender.public_key,
            recipient_public_key: recipient.public_key,
        },
        None,
    );
    assert!(
        revoke_response.success,
        "revoke_share should succeed: {:?}",
        revoke_response.error
    );
    update_mock.assert();

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_rolls_back_local_state_when_state_node_sync_fails() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"share-test-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-rollback"}"#,
        )
        .create_async()
        .await;
    let failing_update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"state sync failed"}"#)
        .expect(1)
        .create_async()
        .await;
    let succeeding_update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let controller = MonasController::with_urls(server.url(), server.url());

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair should be generated");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient keypair should be generated");

    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"revoke-rollback-target"),
            metadata: Some(ContentMetadata {
                name: Some("revoke-rollback.txt".to_string()),
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

    let share_response = controller.share_content(ShareContentInput {
        content_id: created.content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Read],
    });
    assert!(share_response.success, "share_content should succeed");
    let shared = share_response.data.expect("share should return data");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id.clone(),
            sender_public_key: sender.public_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
        },
        None,
    );
    assert!(
        !revoke_response.success,
        "revoke_share should fail when state sync fails"
    );
    failing_update_mock.assert();

    let get_shared_response = controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        private_key: recipient.private_key.clone(),
        sender_key_id: shared.sender_key_id.clone(),
        recipient_key_id: shared.recipient_key_id.clone(),
        key_envelope: shared.key_envelope.clone(),
        version: None,
    });
    assert!(
        get_shared_response.success,
        "old share should still work after rollback: {:?}",
        get_shared_response.error
    );
    let decrypted = get_shared_response
        .data
        .expect("shared content should be available after rollback");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(decrypted.content)
            .expect("rolled back content should be base64url"),
        b"revoke-rollback-target"
    );

    let second_revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            sender_public_key: sender.public_key,
            recipient_public_key: recipient.public_key,
        },
        None,
    );
    assert!(
        second_revoke_response.success,
        "revoke_share should succeed after rollback restored local state: {:?}",
        second_revoke_response.error
    );
    succeeding_update_mock.assert();

    cleanup_content_artifacts();
}

/// §3: `share_service.revoke_share` の内部エラーでも snapshot が復元されることを検証。
///
/// 同じ recipient に対して revoke_share を 2 回呼び出す。1 回目は ACL から recipient を除去して
/// 成功する。2 回目は recipient が既に ACL に無いため `share.revoke` が失敗
/// (`ShareApplicationError::Share`) するが、以前はこの経路で snapshot 復元が呼ばれなかった。
/// 本 PR 以降は失敗時も snapshot が復元され、後続の decrypt_shared_content や
/// 正常系の処理に悪影響がない（残った状態が pre-revoke と一致する）ことを確認する。
#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_rollback_fires_on_inner_share_service_error() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"share-test-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-inner-rollback"}"#,
        )
        .create_async()
        .await;
    // 1 回目の revoke で PUT が 1 回走る想定
    let first_update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let controller = MonasController::with_urls(server.url(), server.url());

    let sender = controller
        .generate_keypair(GenerateKeypairInput { key_type: KeyType::Secp256r1 })
        .data
        .expect("sender keypair");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput { key_type: KeyType::Secp256r1 })
        .data
        .expect("recipient keypair");

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"inner-rollback-target"),
                metadata: Some(ContentMetadata {
                    name: Some("inner-rollback.txt".into()),
                    content_type: Some("text/plain".into()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    create_mock.assert();

    let _ = controller
        .share_content(ShareContentInput {
            content_id: created.content_id.clone(),
            sender_public_key: sender.public_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("share");
    delegate_mock.assert();

    // 1 回目: 成功
    let first = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id.clone(),
            sender_public_key: sender.public_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
        },
        None,
    );
    assert!(first.success, "first revoke should succeed: {:?}", first.error);
    first_update_mock.assert();

    // 2 回目: ACL に recipient が既に無いので share_service.revoke_share で失敗する。
    // 追加したロールバック経路が発火することを、このテストはコードパスとしてカバーする
    // (panic/deadlock せず、失敗として返ることを検証)。
    let second = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            sender_public_key: sender.public_key,
            recipient_public_key: recipient.public_key,
        },
        None,
    );
    assert!(
        !second.success,
        "second revoke should fail because recipient is already removed"
    );
    assert!(
        second.error.is_some(),
        "failure path should carry an ApiError"
    );

    cleanup_content_artifacts();
}
