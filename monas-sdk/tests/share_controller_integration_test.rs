// Integration tests intentionally use the test/dev-only `with_state_node_url` constructor.
#![allow(deprecated)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
use monas_sdk::models::keypair::{GenerateKeypairInput, KeyType};
use monas_sdk::models::share::{
    DecryptSharedContentInput, Permission, RevokeShareInput, ShareContentInput,
    UpdateSharePermissionInput,
};
use monas_sdk::{MonasConfig, MonasController, StateNodeAuthContext};
use std::time::Duration;

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

/// A controller with the skew tolerance widened enough that the tests' fixed timestamps can be
/// used as-is.
fn controller_with_wide_skew(state_node_url: String) -> MonasController {
    let config = MonasConfig::new(state_node_url)
        .with_request_timestamp_skew(Duration::from_secs(60 * 60 * 24 * 365 * 100));
    let controller = MonasController::with_config(config).expect("with_config");
    // The SDK never creates a signing key by itself; a user creates the account.
    controller
        .create_signing_account()
        .data
        .expect("create signing account");
    controller
}

/// A controller with a signing account created (default skew). The SDK does not create signing
/// keys on its own.
fn controller_with_account(state_node_url: String) -> MonasController {
    let controller = MonasController::with_state_node_url(state_node_url);
    controller
        .create_signing_account()
        .data
        .expect("create signing account");
    controller
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

    let controller = controller_with_account(server.url());

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
        file_id: created.file_id.clone(),
        remote_content_id: created.remote_content_id.clone(),
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
    assert_eq!(
        delegated.delegated_token.split('.').count(),
        3,
        "delegated token should be a JWT"
    );
    assert!(!delegated.jti.is_empty());
    assert!(delegated.expires_at > delegated.issued_at);

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
    let update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .create_async()
        .await;

    let controller = controller_with_account(server.url());

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
        file_id: created.file_id.clone(),
        remote_content_id: created.remote_content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(share_response.success, "share_content should succeed");
    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id,
            remote_content_id: created.remote_content_id.clone(),
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
    // Only the remote id path is mocked: a PUT to any other path (e.g. the
    // local content id) would fail the request and the assertion below.
    let update_mock = server
        .mock("PUT", "/content/remote-series-id")
        .with_status(200)
        .create_async()
        .await;

    let controller = controller_with_account(server.url());

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
        file_id: created.file_id.clone(),
        remote_content_id: None,
        sender_public_key: sender.public_key.clone(),
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(share_response.success, "share_content should succeed");
    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id,
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

    let controller = controller_with_account(server.url());

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
        file_id: created.file_id.clone(),
        remote_content_id: created.remote_content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Read],
    });
    assert!(share_response.success, "share_content should succeed");
    let shared = share_response.data.expect("share should return data");
    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id.clone(),
            remote_content_id: created.remote_content_id.clone(),
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
        remote_content_id: None,
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
            file_id: created.file_id,
            remote_content_id: created.remote_content_id.clone(),
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

/// §3: Verifies that the snapshot is restored even on an internal error in
/// `share_service.revoke_share`.
///
/// Calls revoke_share twice for the same recipient. The first call removes the recipient from the
/// ACL and succeeds. The second call fails in `share.revoke` (`ShareApplicationError::Share`)
/// because the recipient is no longer in the ACL; previously snapshot restoration was not invoked
/// on this path. From this PR on, the snapshot is restored on failure as well; this checks that
/// subsequent decrypt_shared_content and normal-path processing are not adversely affected (the
/// remaining state matches pre-revoke).
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
    // Expect the PUT to run once for the first revoke
    let first_update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let controller = controller_with_account(server.url());

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
            file_id: created.file_id.clone(),
            remote_content_id: created.remote_content_id.clone(),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("share");
    // First: succeeds
    let first = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id.clone(),
            remote_content_id: created.remote_content_id.clone(),
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

    // Second: the recipient is no longer in the ACL, so share_service.revoke_share fails.
    // This test covers, as a code path, that the added rollback path fires
    // (verifying it returns as a failure without panicking/deadlocking).
    let second = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id,
            remote_content_id: created.remote_content_id.clone(),
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

/// A revoke with State Node integration calls `POST /content/:id/access/invalidate` before the
/// CEK rotation to revoke already-issued tokens (the access revocation section of
/// docs/design.md). Without this, the revoked party's delegated write token stays valid until its TTL
/// expires, and they can keep writing to the new state.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_invalidates_previously_issued_tokens() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"invalidate-remote"}"#)
        .create_async()
        .await;
    let invalidate_mock = state_node
        .mock("POST", "/content/invalidate-remote/access/invalidate")
        // The auth header is built from the signing key inside the SDK. The caller's Bearer is
        // replaced.
        .match_header(
            "x-request-signature",
            mockito::Matcher::Regex(r"^[A-Za-z0-9+/]+=*$".into()),
        )
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

    let controller = controller_with_wide_skew(state_node.url());
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
                file_id: created.file_id.clone(),
                remote_content_id: None,
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Write],
            })
            .success,
        "share_content should succeed"
    );
    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id,
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
    // No history/version mock here: the pre-rotation head pull cannot run,
    // and the revoke must still go through (a writer must never be able to
    // block revocation) while saying so.
    assert!(
        revoke_response
            .data
            .as_ref()
            .and_then(|d| d.head_pull_error.as_deref())
            .is_some(),
        "the failed head pull must be reported"
    );

    invalidate_mock.assert();
    update_mock.assert();
    let output = revoke_response.data.expect("revoke should return data");
    assert_eq!(
        output.token_invalidated_at,
        Some(1_700_000_500),
        "the new min_valid_issued_at should be reported back to the caller"
    );

    cleanup_content_artifacts();
}

/// If the revocation fails, the whole revoke fails. Swallowing it here would leave a half-done
/// state of "the CEK was rotated but the token is still alive", and the caller would take it as
/// a successful revoke without knowing that.
/// The revocation happens before local state is touched, so no rollback is needed (the share
/// remains valid as before).
#[tokio::test(flavor = "multi_thread")]
async fn revoke_share_fails_when_token_invalidation_fails() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"invalidate-fail-remote"}"#)
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
    // Since the revocation failed, the re-encrypted ciphertext must not be sent.
    let update_mock = state_node
        .mock("PUT", "/content/invalidate-fail-remote")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let controller = controller_with_wide_skew(state_node.url());
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
            file_id: created.file_id.clone(),
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("share should return data");
    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id.clone(),
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
    // Local state was not touched at all, so the original share can still be decrypted.
    let get_shared = controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        remote_content_id: None,
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

/// Even when revokes on the same content run concurrently, both recipient removals persist.
///
/// revoke is a load-modify-save spanning the ACL, CEK, local ciphertext, and state node state,
/// with no version CAS anywhere. Without serialization, two revokes read the same Share and save
/// last-writer-wins, and one of the removals is lost (lost update). `MonasController` is shared
/// via `Arc` from the gateway, so this is not merely theoretical.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_revokes_do_not_lose_either_removal() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"concurrent-revoke-remote"}"#)
        .create_async()
        .await;
    let _update_mock = server
        .mock("PUT", mockito::Matcher::Regex(r"^/content/.+$".to_string()))
        .with_status(200)
        .expect_at_least(1)
        .create_async()
        .await;

    let controller = std::sync::Arc::new(controller_with_account(server.url()));

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair should be generated");
    let recipient_a = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient a keypair should be generated");
    let recipient_b = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient b keypair should be generated");

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"concurrent-revoke-target"),
                metadata: Some(ContentMetadata {
                    name: Some("concurrent-revoke.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create should return data");

    for recipient in [&recipient_a, &recipient_b] {
        assert!(
            controller
                .share_content(ShareContentInput {
                    file_id: created.file_id.clone(),
                    remote_content_id: None,
                    sender_public_key: sender.public_key.clone(),
                    sender_private_key: sender.private_key.clone(),
                    recipient_public_key: recipient.public_key.clone(),
                    permissions: vec![Permission::Read],
                })
                .success,
            "share_content should succeed"
        );
    }

    // Revoke two recipients at the same time
    let handles: Vec<_> = [&recipient_a, &recipient_b]
        .into_iter()
        .map(|recipient| {
            let controller = controller.clone();
            let file_id = created.file_id.clone();
            let sender_public_key = sender.public_key.clone();
            let sender_private_key = sender.private_key.clone();
            let recipient_public_key = recipient.public_key.clone();
            // The filesync repository requires a Tokio reactor, so run it as a
            // blocking task rather than a bare std::thread.
            tokio::task::spawn_blocking(move || {
                controller.revoke_share(
                    RevokeShareInput {
                        file_id,
                        remote_content_id: None,
                        sender_public_key,
                        sender_private_key,
                        recipient_public_key,
                    },
                    None,
                )
            })
        })
        .collect();

    for handle in handles {
        let response = handle.await.expect("revoke task should not panic");
        assert!(
            response.success,
            "concurrent revoke should succeed: {:?}",
            response.error
        );
    }

    // Re-sharing to both succeeds = both removals persisted.
    // If one removal had been lost to a lost update, that recipient would still be in the ACL
    // and re-sharing would fail with `AlreadyShared`.
    for (label, recipient) in [("a", &recipient_a), ("b", &recipient_b)] {
        let shared_again = controller.share_content(ShareContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        });
        assert!(
            shared_again.success,
            "re-sharing to recipient {label} should succeed after revoke: {:?}",
            shared_again.error
        );
    }

    cleanup_content_artifacts();
}

/// revoke also revokes the remaining recipients' tokens (`min_valid_issued_at` advances), so the
/// reissued envelope bundles a token whose iat is after the boundary. If it was issued in the same
/// second as the boundary, wait until the next second and reissue — because under the State
/// Node's `iat > min_valid_issued_at`, a token from the same second is invalid from the moment
/// it is created. The boundary is set to "now" so that the first issuance is always at or below
/// the boundary.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_reissues_a_valid_token_for_each_surviving_recipient() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"reissue-remote"}"#)
        .create_async()
        .await;
    // The state node's new boundary is "now": a token issued in this second is
    // already invalid, so the SDK must wait for the next second.
    let boundary = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1;
    let invalidate_mock = state_node
        .mock("POST", "/content/reissue-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"reissue-remote","new_min_valid_issued_at":{boundary}}}"#
        ))
        .expect(1)
        .create_async()
        .await;
    let update_mock = state_node
        .mock("PUT", "/content/reissue-remote")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let controller = controller_with_wide_skew(state_node.url());
    let auth = auth_context("Bearer owner");
    let keypair = || {
        controller
            .generate_keypair(GenerateKeypairInput {
                key_type: KeyType::Secp256r1,
            })
            .data
            .expect("keypair")
    };
    let sender = keypair();
    let survivor = keypair();
    let revoked = keypair();

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"reissue-target"),
                metadata: Some(ContentMetadata {
                    name: Some("reissue.txt".to_string()),
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

    for (recipient, permissions) in [
        (&survivor, vec![Permission::Write]),
        (&revoked, vec![Permission::Read]),
    ] {
        let shared = controller.share_content(ShareContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: Some("reissue-remote".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions,
        });
        assert!(shared.success, "{:?}", shared.error);
    }

    let revoke_response = controller.revoke_share(
        RevokeShareInput {
            file_id: created.file_id,
            remote_content_id: Some("reissue-remote".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: revoked.public_key,
        },
        Some(&auth),
    );
    assert!(revoke_response.success, "{:?}", revoke_response.error);
    invalidate_mock.assert();
    update_mock.assert();

    let output = revoke_response.data.expect("revoke should return data");
    assert_eq!(output.token_invalidated_at, Some(boundary));
    assert_eq!(output.reissued_envelopes.len(), 1, "one survivor");
    let token = output.reissued_envelopes[0]
        .delegated_access
        .as_ref()
        .expect("the survivor gets a fresh token with the re-wrapped envelope");
    assert!(!token.delegated_token.is_empty());
    assert!(
        token.issued_at > boundary,
        "reissued token iat {} must be after the boundary {boundary}",
        token.issued_at
    );

    cleanup_content_artifacts();
}

/// The share ACL is keyed by the fixed file ID, not the version ID, so it survives an edit that
/// changes the version ID. If it were keyed by version ID, then when another recipient is revoked
/// after the edit, recipients from before the edit would be locked out of the CEK rotation
/// (neither an envelope nor a token is reissued).
#[tokio::test(flavor = "multi_thread")]
async fn share_acl_survives_an_edit_so_a_later_revoke_reissues_to_earlier_recipients() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;

    let create_mock = state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"acl-remote"}"#)
        .create_async()
        .await;
    let _update_mock = state_node
        .mock("PUT", "/content/acl-remote")
        .with_status(200)
        .expect_at_least(1)
        .create_async()
        .await;
    let _invalidate_mock = state_node
        .mock("POST", "/content/acl-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"acl-remote","new_min_valid_issued_at":1700000500}"#)
        .create_async()
        .await;
    let controller = controller_with_wide_skew(state_node.url());
    let auth = auth_context("Bearer owner");
    let keypair = || {
        controller
            .generate_keypair(GenerateKeypairInput {
                key_type: KeyType::Secp256r1,
            })
            .data
            .expect("keypair")
    };
    let sender = keypair();
    let bob = keypair();
    let carol = keypair();

    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"acl v1"),
                metadata: Some(ContentMetadata {
                    name: Some("acl.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    create_mock.assert();

    let share = |content_id: &str,
                 recipient: &monas_sdk::models::keypair::GenerateKeypairOutput| {
        controller.share_content(ShareContentInput {
            file_id: content_id.to_string(),
            remote_content_id: Some("acl-remote".to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient.public_key.clone(),
            permissions: vec![Permission::Read],
        })
    };
    assert!(share(&created.file_id, &bob).success);

    // The owner edits: a new version id.
    let updated = controller
        .update_content(
            monas_sdk::models::content::UpdateContentInput {
                file_id: created.file_id.clone(),
                remote_content_id: "acl-remote".to_string(),
                content: URL_SAFE_NO_PAD.encode(b"acl v2 after edit"),
                metadata: None,
            },
            Some(&auth),
        )
        .data
        .expect("update");
    assert_ne!(updated.version_id, created.content_id);

    // Share the file (now at the new version) to carol, then revoke her.
    assert!(share(&updated.file_id, &carol).success);
    let revoke = controller
        .revoke_share(
            RevokeShareInput {
                file_id: updated.file_id.clone(),
                remote_content_id: Some("acl-remote".to_string()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: carol.public_key.clone(),
            },
            Some(&auth),
        )
        .data
        .expect("revoke");

    // Bob, shared before the edit, is still a recipient and gets re-wrapped.
    let bob_key_id = {
        use sha2::{Digest, Sha256};
        let pk = URL_SAFE_NO_PAD.decode(&bob.public_key).unwrap();
        URL_SAFE_NO_PAD.encode(&Sha256::digest(&pk)[..16])
    };
    assert!(
        revoke
            .reissued_envelopes
            .iter()
            .any(|e| e.recipient_key_id == bob_key_id),
        "bob must be re-wrapped after the edit; got {:?}",
        revoke
            .reissued_envelopes
            .iter()
            .map(|e| &e.recipient_key_id)
            .collect::<Vec<_>>()
    );

    cleanup_content_artifacts();
}

// ============================================
// update_share_permission
// ============================================

/// Extracts the capability name (`read` / `write`) from a JWT payload.
fn token_capabilities(jwt: &str) -> Vec<String> {
    let payload = jwt.split('.').nth(1).expect("jwt payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("payload base64url");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("payload json");
    let text = value.to_string();
    ["read", "write"]
        .iter()
        .filter(|c| text.contains(&format!("\"{c}\"")))
        .map(|c| c.to_string())
        .collect()
}

struct PermissionFixture {
    controller: MonasController,
    file_id: String,
    sender: monas_sdk::models::keypair::GenerateKeypairOutput,
    target: monas_sdk::models::keypair::GenerateKeypairOutput,
    other: monas_sdk::models::keypair::GenerateKeypairOutput,
}

/// Sets up a state where `target` is shared with the `initial` permission and `other` with read.
async fn permission_fixture(
    state_node: &mut mockito::ServerGuard,
    initial: Permission,
) -> PermissionFixture {
    state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"perm-remote"}"#)
        .create_async()
        .await;
    let controller = controller_with_wide_skew(state_node.url());
    let kp = || {
        controller
            .generate_keypair(GenerateKeypairInput {
                key_type: KeyType::Secp256r1,
            })
            .data
            .expect("keypair")
    };
    let (sender, target, other) = (kp(), kp(), kp());
    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"permission-target"),
                metadata: Some(ContentMetadata {
                    name: Some("perm.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    for (who, perm) in [(&target, initial), (&other, Permission::Read)] {
        let r = controller.share_content(ShareContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: who.public_key.clone(),
            permissions: vec![perm],
        });
        assert!(r.success, "share: {:?}", r.error);
    }
    PermissionFixture {
        controller,
        file_id: created.file_id,
        sender,
        target,
        other,
    }
}

/// Re-sharing to the same party returns a 409 that makes clear "change the permission instead"
/// (previously it was a 500 `Share domain error: AlreadyShared`, and the UI could only show
/// "Share failed").
#[tokio::test(flavor = "multi_thread")]
async fn resharing_to_an_existing_recipient_is_a_conflict() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Read).await;
    let r = f.controller.share_content(ShareContentInput {
        file_id: f.file_id.clone(),
        remote_content_id: Some("perm-remote".into()),
        sender_public_key: f.sender.public_key.clone(),
        sender_private_key: f.sender.private_key.clone(),
        recipient_public_key: f.target.public_key.clone(),
        permissions: vec![Permission::Write],
    });
    assert!(!r.success);
    assert!(
        matches!(r.error, Some(monas_sdk::ApiError::Conflict(_))),
        "{:?}",
        r.error
    );
    cleanup_content_artifacts();
}

/// Promotion (read → write): goes through without a revoke. Neither token revocation nor CEK
/// rotation happens (nothing is sent to the state node). The new token has write.
#[tokio::test(flavor = "multi_thread")]
async fn upgrading_read_to_write_reissues_a_write_token_without_rotation() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Read).await;
    let invalidate_mock = state_node
        .mock("POST", "/content/perm-remote/access/invalidate")
        .expect(0)
        .create_async()
        .await;
    let put_mock = state_node
        .mock("PUT", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;

    let r = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Read, Permission::Write],
        },
        Some(&auth_context("Bearer owner")),
    );
    assert!(r.success, "{:?}", r.error);
    let out = r.data.expect("data");
    assert_eq!(out.permissions, vec![Permission::Write]);
    assert_eq!(
        token_capabilities(&out.delegated_access.delegated_token),
        vec!["write"]
    );
    assert!(out.token_invalidated_at.is_none());
    assert!(out.reissued_tokens.is_empty());
    invalidate_mock.assert();
    put_mock.assert();

    // The change persists in the ACL: asking for write again is treated as an "unchanged request",
    // and the other recipients' tokens are returned. If the ACL were still read, it would be
    // judged a promotion and the other recipients' part would be empty.
    let again = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Write],
        },
        Some(&auth_context("Bearer owner")),
    );
    assert!(again.success, "{:?}", again.error);
    let again = again.data.expect("data");
    assert_eq!(
        again
            .reissued_tokens
            .iter()
            .map(|t| t.recipient_key_id.clone())
            .collect::<Vec<_>>(),
        vec![key_id_of(&f.other)],
        "the ACL holds write: a second write request is unchanged, not an upgrade"
    );
    invalidate_mock.assert();
    cleanup_content_artifacts();
}

/// Demotion (write → read): advances the boundary to stop the write token the recipient holds.
/// The new token is read-only with an iat after the boundary. Other recipients revoked as
/// collateral are also reissued tokens with their own permissions. The CEK is not rotated (no PUT).
#[tokio::test(flavor = "multi_thread")]
async fn downgrading_write_to_read_invalidates_and_reissues_tokens() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Write).await;
    let boundary = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let invalidate_mock = state_node
        .mock("POST", "/content/perm-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"perm-remote","new_min_valid_issued_at":{boundary},"notified_members":["n2"],"unreached_members":[],"relayed":false}}"#
        ))
        .expect(1)
        .create_async()
        .await;
    let put_mock = state_node
        .mock("PUT", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;

    let r = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Read],
        },
        Some(&auth_context("Bearer owner")),
    );
    assert!(r.success, "{:?}", r.error);
    invalidate_mock.assert();
    put_mock.assert();
    let out = r.data.expect("data");
    assert_eq!(out.permissions, vec![Permission::Read]);
    assert_eq!(
        token_capabilities(&out.delegated_access.delegated_token),
        vec!["read"]
    );
    assert!(out.delegated_access.issued_at > boundary);
    assert_eq!(out.token_invalidated_at, Some(boundary));
    assert_eq!(
        out.token_invalidation_reach.map(|r| r.notified_members),
        Some(vec!["n2".to_string()])
    );
    assert_eq!(out.reissued_tokens.len(), 1, "the other recipient");
    let other_token = out.reissued_tokens[0]
        .delegated_access
        .as_ref()
        .expect("other recipient gets a fresh token");
    assert!(other_token.issued_at > boundary);
    assert_eq!(
        token_capabilities(&other_token.delegated_token),
        vec!["read"]
    );
    assert_eq!(out.reissued_tokens[0].recipient_key_id, key_id_of(&f.other));

    // The change persists in the ACL: asking for read again is not a demotion, so the boundary is
    // not advanced (invalidate stays at 1 call). If the ACL were still write, invalidate would be
    // called as a second demotion.
    let again = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Read],
        },
        Some(&auth_context("Bearer owner")),
    );
    assert!(again.success, "{:?}", again.error);
    assert_eq!(again.data.expect("data").token_invalidated_at, None);
    invalidate_mock.assert();
    cleanup_content_artifacts();
}

/// Changing the permission of a party not shared with returns 404 (it does not silently create
/// a new share).
#[tokio::test(flavor = "multi_thread")]
async fn updating_permission_of_an_unshared_key_is_not_found() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Read).await;
    let stranger = f
        .controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("keypair");
    let r = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: stranger.public_key,
            permissions: vec![Permission::Write],
        },
        Some(&auth_context("Bearer owner")),
    );
    assert!(
        matches!(r.error, Some(monas_sdk::ApiError::NotFound(_))),
        "{:?}",
        r.error
    );
    cleanup_content_artifacts();
}

/// If issuing the target's token fails after the demotion's revocation, the ACL is reverted to
/// write. Otherwise a retry is judged "read → read" and performs neither the revocation nor the
/// reissue to other recipients, so the other recipients' tokens invalidated by the first
/// revocation are never returned.
#[tokio::test(flavor = "multi_thread")]
async fn downgrade_retry_after_token_issuance_failure_still_reissues_other_tokens() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Write).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The boundary is 60 seconds ahead of the SDK's clock: this exceeds the wait limit, so token
    // issuance fails.
    let skewed = state_node
        .mock("POST", "/content/perm-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"perm-remote","new_min_valid_issued_at":{}}}"#,
            now + 60
        ))
        .expect(1)
        .create_async()
        .await;
    let input = UpdateSharePermissionInput {
        file_id: f.file_id.clone(),
        remote_content_id: Some("perm-remote".into()),
        recipient_public_key: f.target.public_key.clone(),
        permissions: vec![Permission::Read],
    };
    let failed = f
        .controller
        .update_share_permission(input.clone(), Some(&auth_context("Bearer owner")));
    assert!(
        !failed.success,
        "issuance must fail with a far-future cutoff"
    );
    skewed.assert();
    skewed.remove_async().await;

    let fixed = state_node
        .mock("POST", "/content/perm-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"perm-remote","new_min_valid_issued_at":{now}}}"#
        ))
        .expect(1)
        .create_async()
        .await;
    let retry = f
        .controller
        .update_share_permission(input, Some(&auth_context("Bearer owner")));
    assert!(retry.success, "{:?}", retry.error);
    fixed.assert();
    let out = retry.data.expect("data");
    assert_eq!(
        out.token_invalidated_at,
        Some(now),
        "retry must redo the downgrade"
    );
    assert_eq!(
        out.reissued_tokens.len(),
        1,
        "the other recipient's token is reissued"
    );
    assert!(out.reissued_tokens[0].delegated_access.is_some());
    cleanup_content_artifacts();
}

// ============================================
// When the body is reverted to the same content as before (plainCid matches a past one)
// ============================================

/// The recipient's KeyId (base64url). Same computation as the SDK output (first 16 bytes of the
/// public key's SHA-256).
fn key_id_of(kp: &monas_sdk::models::keypair::GenerateKeypairOutput) -> String {
    use sha2::{Digest, Sha256};
    let pk = URL_SAFE_NO_PAD.decode(&kp.public_key).unwrap();
    URL_SAFE_NO_PAD.encode(&Sha256::digest(&pk)[..16])
}

struct RevertFixture {
    controller: MonasController,
    /// The file's key (target of owner-side operations)
    file_id: String,
    /// plainCid of the version at creation
    created_id: String,
    sender: monas_sdk::models::keypair::GenerateKeypairOutput,
    bob: monas_sdk::models::keypair::GenerateKeypairOutput,
    carol: monas_sdk::models::keypair::GenerateKeypairOutput,
}

/// Sets up a state created with body "body A" and shared to Bob and Carol with `initial`.
/// The state node accepts all creates, updates, and revocations.
async fn revert_fixture(
    state_node: &mut mockito::ServerGuard,
    initial: Permission,
) -> RevertFixture {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    state_node
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"revert-remote"}"#)
        .create_async()
        .await;
    state_node
        .mock("PUT", "/content/revert-remote")
        .with_status(200)
        .create_async()
        .await;
    state_node
        .mock("POST", "/content/revert-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"revert-remote","new_min_valid_issued_at":{now}}}"#
        ))
        .create_async()
        .await;
    let controller = controller_with_wide_skew(state_node.url());
    let kp = || {
        controller
            .generate_keypair(GenerateKeypairInput {
                key_type: KeyType::Secp256r1,
            })
            .data
            .expect("keypair")
    };
    let (sender, bob, carol) = (kp(), kp(), kp());
    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"body A"),
                metadata: Some(ContentMetadata {
                    name: Some("revert.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    for who in [&bob, &carol] {
        let r = controller.share_content(ShareContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: Some("revert-remote".into()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: who.public_key.clone(),
            permissions: vec![initial],
        });
        assert!(r.success, "share: {:?}", r.error);
    }
    RevertFixture {
        controller,
        file_id: created.file_id,
        created_id: created.content_id,
        sender,
        bob,
        carol,
    }
}

impl RevertFixture {
    /// Edits the body and returns the new version's plainCid.
    fn edit(&self, body: &[u8]) -> String {
        self.controller
            .update_content(
                monas_sdk::models::content::UpdateContentInput {
                    file_id: self.file_id.clone(),
                    remote_content_id: "revert-remote".to_string(),
                    content: URL_SAFE_NO_PAD.encode(body),
                    metadata: None,
                },
                Some(&auth_context("Bearer owner")),
            )
            .data
            .expect("update")
            .version_id
    }

    fn downgrade(
        &self,
        who: &monas_sdk::models::keypair::GenerateKeypairOutput,
    ) -> monas_sdk::models::share::UpdateSharePermissionOutput {
        let r = self.controller.update_share_permission(
            UpdateSharePermissionInput {
                file_id: self.file_id.clone(),
                remote_content_id: Some("revert-remote".into()),
                recipient_public_key: who.public_key.clone(),
                permissions: vec![Permission::Read],
            },
            Some(&auth_context("Bearer owner")),
        );
        assert!(r.success, "downgrade: {:?}", r.error);
        r.data.expect("data")
    }

    fn revoke(
        &self,
        who: &monas_sdk::models::keypair::GenerateKeypairOutput,
    ) -> monas_sdk::models::share::RevokeShareOutput {
        let r = self.controller.revoke_share(
            RevokeShareInput {
                file_id: self.file_id.clone(),
                remote_content_id: Some("revert-remote".into()),
                sender_public_key: self.sender.public_key.clone(),
                sender_private_key: self.sender.private_key.clone(),
                recipient_public_key: who.public_key.clone(),
            },
            Some(&auth_context("Bearer owner")),
        );
        assert!(r.success, "revoke: {:?}", r.error);
        r.data.expect("data")
    }
}

/// Reverting the body after a demotion does not undo the demotion.
///
/// Back when share settings were held per plainCid, reverting the body to "body A" made the
/// plainCid the same as at creation, and the "Bob = write" left on the creation-time plainCid was
/// picked up, so demoting Carol reissued Bob's collateral token as write.
/// Now share settings are held as a single entry under the file's key, so Bob's reissued token
/// stays read.
#[tokio::test(flavor = "multi_thread")]
async fn reverting_the_body_does_not_revive_a_downgraded_recipients_write() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = revert_fixture(&mut state_node, Permission::Write).await;

    f.edit(b"body B");
    f.downgrade(&f.bob);
    let reverted = f.edit(b"body A");
    assert_eq!(reverted, f.created_id, "same body, same plainCid");

    let out = f.downgrade(&f.carol);
    let bob = out
        .reissued_tokens
        .iter()
        .find(|t| t.recipient_key_id == key_id_of(&f.bob))
        .expect("bob's token is reissued after the cutoff");
    assert_eq!(
        token_capabilities(
            &bob.delegated_access
                .as_ref()
                .expect("bob token")
                .delegated_token
        ),
        vec!["read"],
        "bob was downgraded before the body was reverted"
    );
    cleanup_content_artifacts();
}

/// Reverting the body after a revocation does not bring the revoked party back as a share
/// recipient.
///
/// With per-plainCid share settings, the "Bob and Carol" left on the reverted plainCid was picked
/// up, so revoking Bob next reissued an envelope for the new CEK to the already-revoked Carol
/// (a party that should have been cut off could read again).
#[tokio::test(flavor = "multi_thread")]
async fn reverting_the_body_does_not_reissue_to_a_revoked_recipient() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = revert_fixture(&mut state_node, Permission::Read).await;

    f.edit(b"body B");
    f.revoke(&f.carol);
    let reverted = f.edit(b"body A");
    assert_eq!(reverted, f.created_id, "same body, same plainCid");

    let out = f.revoke(&f.bob);
    let reissued: Vec<_> = out
        .reissued_envelopes
        .iter()
        .map(|e| e.recipient_key_id.clone())
        .collect();
    assert!(
        !reissued.contains(&key_id_of(&f.carol)),
        "carol was revoked before the body was reverted; reissued to {reissued:?}"
    );
    cleanup_content_artifacts();
}

/// Even when the same demotion is retried after its success response was lost (timeout, tab
/// reload), the other recipients' reissued tokens are returned. The first demotion already
/// advanced the revocation boundary, and the other recipients' old tokens can no longer be used,
/// so without them there is no way to restore those people's access. The retry does not repeat
/// the revocation.
#[tokio::test(flavor = "multi_thread")]
async fn retrying_a_downgrade_whose_response_was_lost_still_reissues_other_tokens() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Write).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let invalidate = state_node
        .mock("POST", "/content/perm-remote/access/invalidate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"perm-remote","new_min_valid_issued_at":{now}}}"#
        ))
        .expect(1)
        .create_async()
        .await;
    let downgrade = || {
        f.controller.update_share_permission(
            UpdateSharePermissionInput {
                file_id: f.file_id.clone(),
                remote_content_id: Some("perm-remote".into()),
                recipient_public_key: f.target.public_key.clone(),
                permissions: vec![Permission::Read],
            },
            Some(&auth_context("Bearer owner")),
        )
    };
    let first = downgrade();
    assert!(first.success, "{:?}", first.error);
    // The first response is "lost"; the caller retries the same request.
    let retry = downgrade();
    assert!(retry.success, "{:?}", retry.error);
    invalidate.assert();
    let out = retry.data.expect("data");
    assert_eq!(
        out.token_invalidated_at, None,
        "the retry does not cut off again"
    );
    let other = out
        .reissued_tokens
        .iter()
        .find(|t| t.recipient_key_id == key_id_of(&f.other))
        .expect("the other recipient's token is returned on the retry too");
    let token = other.delegated_access.as_ref().expect("issued");
    assert!(token.issued_at > now);
    assert_eq!(token_capabilities(&token.delegated_token), vec!["read"]);
    cleanup_content_artifacts();
}

/// Demotion advances the State Node's revocation boundary to stop old write tokens.
/// If it cannot reach the State Node (no auth), it does not return success without stopping them.
#[tokio::test(flavor = "multi_thread")]
async fn a_downgrade_without_state_node_auth_is_refused() {
    let _guard = acquire_test_lock();
    let mut state_node = Server::new_async().await;
    let f = permission_fixture(&mut state_node, Permission::Write).await;
    let r = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Read],
        },
        None,
    );
    assert!(
        matches!(r.error, Some(monas_sdk::ApiError::Validation(_))),
        "{:?}",
        r.error
    );
    // The ACL is unchanged: the target still has write.
    let again = f.controller.update_share_permission(
        UpdateSharePermissionInput {
            file_id: f.file_id.clone(),
            remote_content_id: Some("perm-remote".into()),
            recipient_public_key: f.target.public_key.clone(),
            permissions: vec![Permission::Write],
        },
        None,
    );
    assert!(again.success, "{:?}", again.error);
    assert!(again
        .data
        .unwrap()
        .reissued_tokens
        .iter()
        .all(|t| t.recipient_key_id != key_id_of(&f.target)));
    cleanup_content_artifacts();
}
