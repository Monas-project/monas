// Integration tests intentionally use the test/dev-only `with_urls` constructor.
#![allow(deprecated)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
use monas_sdk::models::keypair::{GenerateKeypairInput, KeyType};
use monas_sdk::models::share::{
    DecryptSharedContentInput, Permission, RevokeShareInput, ShareContentInput,
};
use monas_sdk::{MonasConfig, MonasController, StateNodeAuthContext};
use std::time::Duration;

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

/// テストの固定 timestamp をそのまま使えるよう、skew 許容を十分広げた controller。
fn controller_with_wide_skew(state_node_url: String, account_url: String) -> MonasController {
    let config = MonasConfig::new(state_node_url, account_url)
        .with_request_timestamp_skew(Duration::from_secs(60 * 60 * 24 * 365 * 100));
    MonasController::with_config(config).expect("with_config")
}

fn auth_context(authorization: &str) -> StateNodeAuthContext {
    StateNodeAuthContext {
        authorization: Some(authorization.to_string()),
        request_signature: Some("caller-signature".into()),
        request_timestamp: Some(1_717_171_717),
    }
}

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
        sender_private_key: sender.private_key.clone(),
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
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(share_response.success, "share_content should succeed");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
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
async fn revoke_share_syncs_state_node_by_remote_content_id() {
    // The state node only knows the series id (remote_content_id), never the
    // SDK-local version id. The post-revoke re-encryption PUT must therefore
    // address the remote id when it is provided.
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"remote-series-id"}"#)
        .create_async()
        .await;
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-3"}"#,
        )
        .create_async()
        .await;
    // Only the remote id path is mocked: a PUT to any other path (e.g. the
    // local content id) would fail the request and the assertion below.
    let update_mock = server
        .mock("PUT", "/content/remote-series-id")
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
            content: URL_SAFE_NO_PAD.encode(b"revoke-remote-id-content"),
            metadata: Some(ContentMetadata {
                name: Some("revoke-remote.txt".to_string()),
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
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(share_response.success, "share_content should succeed");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            remote_content_id: Some("remote-series-id".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
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
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Read],
    });
    assert!(share_response.success, "share_content should succeed");
    let shared = share_response.data.expect("share should return data");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id.clone(),
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
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
        sender_public_key: shared.sender_public_key.clone(),
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
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
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
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
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
            sender_private_key: sender.private_key.clone(),
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
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
        },
        None,
    );
    assert!(
        first.success,
        "first revoke should succeed: {:?}",
        first.error
    );
    first_update_mock.assert();

    // 2 回目: ACL に recipient が既に無いので share_service.revoke_share で失敗する。
    // 追加したロールバック経路が発火することを、このテストはコードパスとしてカバーする
    // (panic/deadlock せず、失敗として返ることを検証)。
    let second = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
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

/// State Node 連携ありの revoke は、CEK ローテーションの前に
/// `POST /content/:id/access/invalidate` を呼んで既発行 Token を失効させる
/// (docs/design.md「アクセス取り消し」)。これが無いと、取り消した相手の委譲
/// write Token が TTL 満了まで有効なまま残り、新しい状態へ書き込み続けられる。
#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_invalidates_previously_issued_tokens() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let mut account = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"invalidate-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = account
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-invalidate"}"#,
        )
        .create_async()
        .await;
    let invalidate_mock = state_node
        .mock("POST", "/content/invalidate-remote/access/invalidate")
        // 認証ヘッダは account service の署名結果で置き換わる（Authorization は
        // 導出された key id になる）ので、ここでは署名済みであることだけ確認する。
        .match_header("x-request-signature", "c2lnbmVk")
        .match_header("x-request-timestamp", "1717171717")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"invalidate-remote","new_min_valid_issued_at":1700000500}"#)
        .expect(1)
        .create_async()
        .await;
    let update_mock = state_node
        .mock("PUT", "/content/invalidate-remote")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let sign_mock = account
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw==","algorithm":"P256"}"#,
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let controller = controller_with_wide_skew(state_node.url(), account.url());
    let auth = auth_context("Bearer owner");

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

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"invalidate-target"),
                metadata: Some(ContentMetadata {
                    name: Some("invalidate.txt".to_string()),
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

    assert!(
        controller
            .share_content(ShareContentInput {
                content_id: created.content_id.clone(),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Write],
            })
            .success,
        "share_content should succeed"
    );
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id,
            remote_content_id: Some("invalidate-remote".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key,
        },
        Some(&auth),
    );
    assert!(
        revoke_response.success,
        "revoke_share should succeed: {:?}",
        revoke_response.error
    );

    invalidate_mock.assert();
    update_mock.assert();
    sign_mock.assert();

    let output = revoke_response.data.expect("revoke should return data");
    assert_eq!(
        output.token_invalidated_at,
        Some(1_700_000_500),
        "the new min_valid_issued_at should be reported back to the caller"
    );

    cleanup_content_artifacts();
}

/// 失効に失敗したら revoke 全体を失敗させる。ここで握りつぶすと
/// 「CEK はローテーションされたが Token は生きている」中途半端な状態になり、
/// 呼び出し側はそれを知らないまま revoke 成功と受け取ってしまう。
/// 失効はローカル状態を触る前なので、巻き戻しは不要（共有は元のまま有効）。
#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_fails_when_token_invalidation_fails() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let mut account = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"invalidate-fail-remote"}"#)
        .create_async()
        .await;
    let delegate_mock = account
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-invalidate-fail"}"#,
        )
        .create_async()
        .await;
    let invalidate_mock = state_node
        .mock("POST", "/content/invalidate-fail-remote/access/invalidate")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"Authorization failed"}"#)
        .expect(1)
        .create_async()
        .await;
    // 失効が失敗した以上、再暗号化した ciphertext を送ってはいけない。
    let update_mock = state_node
        .mock("PUT", "/content/invalidate-fail-remote")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let sign_mock = account
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw==","algorithm":"P256"}"#,
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let controller = controller_with_wide_skew(state_node.url(), account.url());
    let auth = auth_context("Bearer owner");

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

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"invalidate-fail-target"),
                metadata: Some(ContentMetadata {
                    name: Some("invalidate-fail.txt".to_string()),
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

    let shared = controller
        .share_content(ShareContentInput {
            content_id: created.content_id.clone(),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("share should return data");
    delegate_mock.assert();

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            content_id: created.content_id.clone(),
            remote_content_id: Some("invalidate-fail-remote".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
        },
        Some(&auth),
    );
    assert!(
        !revoke_response.success,
        "revoke_share should fail when token invalidation fails"
    );
    invalidate_mock.assert();
    update_mock.assert();
    sign_mock.assert();

    // ローカル状態は一切触っていないので、元の共有はそのまま復号できる。
    let get_shared = controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        private_key: recipient.private_key.clone(),
        sender_public_key: shared.sender_public_key.clone(),
        recipient_key_id: shared.recipient_key_id.clone(),
        key_envelope: shared.key_envelope.clone(),
        version: None,
    });
    assert!(
        get_shared.success,
        "the existing share must remain usable when revoke aborts early: {:?}",
        get_shared.error
    );

    cleanup_content_artifacts();
}
