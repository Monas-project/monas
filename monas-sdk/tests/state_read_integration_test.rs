// Integration tests intentionally use the test/dev-only `with_state_node_url` constructor.
#![allow(deprecated)]
//! Integration tests for `read_content_from_state_node` (verified read).
//!
//! Mocks the State Node with mockito and verifies that:
//! - The creator can read their own content via the state node and decrypt it down to the
//!   plaintext (A + decryption)
//! - A share recipient can read the same content after processing the KeyEnvelope (CEK persistence)
//! - A recipient that has not processed the KeyEnvelope is guided by a NotFound derived from
//!   MissingKey
//! - A tampered Node (CID mismatch) is rejected
//!
//! The Node CBOR returned by the State Node is generated with a mirror struct that has the same
//! CBOR shape as crsl-lib `Node` (the mirror's correctness is ensured by the crsl-lib parity tests
//! in monas-content).

use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use mockito::{Mock, Server, ServerGuard};
use monas_content::infrastructure::node_verification::recompute_node_cid;
use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
use monas_sdk::models::keypair::{GenerateKeypairInput, KeyType};
use monas_sdk::models::share::{
    DecryptSharedContentInput, Permission, ShareContentInput, UpdateSharedContentInput,
};
use monas_sdk::models::state::ReadContentFromStateNodeInput;
use monas_sdk::{ApiError, MonasController};

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts, node_mirror::make_node_bytes};

const REMOTE_ID: &str = "state-read-remote";

async fn mock_history(server: &mut ServerGuard, versions: &[&str]) -> Mock {
    let body = serde_json::json!({
        "content_id": REMOTE_ID,
        "versions": versions,
    });
    server
        .mock("GET", format!("/content/{REMOTE_ID}/history").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body.to_string())
        .create_async()
        .await
}

async fn mock_version_data(server: &mut ServerGuard, version: &str, node_bytes: &[u8]) -> Mock {
    let body = serde_json::json!({
        "content_id": REMOTE_ID,
        "data": BASE64_STANDARD.encode(node_bytes),
        "version": version,
    });
    server
        .mock(
            "GET",
            format!("/content/{REMOTE_ID}/version/{version}").as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body.to_string())
        .create_async()
        .await
}

/// A controller with a signing account created. The SDK does not create signing keys on its own.
#[allow(deprecated)]
fn controller_with_account(state_node_url: String) -> MonasController {
    let controller = MonasController::with_state_node_url(state_node_url);
    controller
        .create_signing_account()
        .data
        .expect("create signing account");
    controller
}

/// Creates content and obtains the actual AES-GCM ciphertext via share
/// (the share envelope is the only public path that takes the ciphertext out of the SDK).
/// Returns: (local_content_id, ciphertext, share output, sender/recipient keypair)
struct CreatedContent {
    /// Target of owner-side operations (the file's key)
    file_id: String,
    /// plainCid of the shared version (used to match the recipient-side read)
    local_content_id: String,
    ciphertext: Vec<u8>,
    shared: monas_sdk::models::share::ShareContentOutput,
    recipient_private_key: String,
}

async fn create_and_share(
    server: &mut ServerGuard,
    controller: &MonasController,
    plaintext: &[u8],
) -> CreatedContent {
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;

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

    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(plaintext),
            metadata: Some(ContentMetadata {
                name: Some("state-read.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(
        create_response.success,
        "create_content should succeed: {:?}",
        create_response.error
    );
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let share_response = controller.share_content(ShareContentInput {
        file_id: created.file_id.clone(),
        remote_content_id: None,
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
    let shared = share_response.data.expect("share should return data");
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&shared.key_envelope.ciphertext)
        .expect("envelope ciphertext should be base64url");

    CreatedContent {
        file_id: created.file_id,
        local_content_id: created.content_id,
        ciphertext,
        shared,
        recipient_private_key: recipient.private_key,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn creator_reads_own_content_from_state_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = controller_with_account(server.url());

    let plaintext = b"state-read-roundtrip";
    let created = create_and_share(&mut server, &controller, plaintext).await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    let history_mock = mock_history(&mut server, &[&genesis_cid]).await;
    let data_mock = mock_version_data(&mut server, &genesis_cid, &genesis_bytes).await;

    let response = controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: Some(created.file_id.clone()),
            local_content_id: String::new(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(
        response.success,
        "read should succeed: {:?}",
        response.error
    );
    let output = response.data.expect("read should return data");
    assert_eq!(output.version, genesis_cid);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(output.content).unwrap(),
        plaintext,
        "decrypted content should round-trip"
    );
    history_mock.assert();
    data_mock.assert();

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_reads_content_after_processing_envelope() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());

    let plaintext = b"shared-then-read";
    let created = create_and_share(&mut server, &creator, plaintext).await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    // The recipient is a separate instance (= equivalent to a separate device; it has neither
    // local content nor a CEK)
    let recipient_controller = controller_with_account(server.url());

    // Before the KeyEnvelope is processed there is no CEK, and NotFound guides toward share
    // processing (the read is done twice, before and after, so the mock expects 2 hits)
    let history_mock = mock_history(&mut server, &[&genesis_cid])
        .await
        .expect_at_least(1);
    let data_mock = mock_version_data(&mut server, &genesis_cid, &genesis_bytes)
        .await
        .expect_at_least(1);
    let before = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: None,
            local_content_id: created.local_content_id.clone(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(!before.success, "read without CEK should fail");
    match before.error {
        Some(ApiError::NotFound(msg)) => {
            assert!(msg.contains("KeyEnvelope"), "msg should guide user: {msg}")
        }
        other => panic!("expected NotFound, got: {other:?}"),
    }

    // Processing the KeyEnvelope persists the CEK locally on the recipient
    let decrypt_response = recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.local_content_id.clone(),
        remote_content_id: None,
        private_key: created.recipient_private_key.clone(),
        sender_public_key: created.shared.sender_public_key.clone(),
        recipient_key_id: created.shared.recipient_key_id.clone(),
        key_envelope: created.shared.key_envelope.clone(),
        version: None,
    });
    assert!(
        decrypt_response.success,
        "decrypt_shared_content should succeed: {:?}",
        decrypt_response.error
    );

    // From then on it can be read via the verified read through the state node
    let after = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: None,
            local_content_id: created.local_content_id.clone(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(
        after.success,
        "read after envelope processing should succeed: {:?}",
        after.error
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(after.data.unwrap().content).unwrap(),
        plaintext
    );
    history_mock.assert_async().await;
    data_mock.assert_async().await;

    cleanup_content_artifacts();
}

/// Following CEK rotation: after revoke rotates the CEK,
/// - a read by a recipient holding only the old CEK fails with Forbidden (stale key),
/// - processing the reissued KeyEnvelope from the revoke output updates the stored CEK,
/// - and subsequent state node reads can decrypt the new ciphertext.
#[tokio::test(flavor = "multi_thread")]
async fn cek_rotation_after_revoke_updates_recipient_and_read() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());

    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;

    let sender = creator
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair");
    let revoked_recipient = creator
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("revoked recipient keypair");
    let surviving_recipient = creator
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("surviving recipient keypair");

    let plaintext = b"rotation-target-content";
    let create_response = creator.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(plaintext),
            metadata: Some(ContentMetadata {
                name: Some("rotation.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    assert!(create_response.success, "{:?}", create_response.error);
    let created = create_response.data.unwrap();

    // Share with 2 recipients (one of them is revoked later)
    let share_to = |recipient_pub: &str| {
        creator.share_content(ShareContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: None,
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: recipient_pub.to_string(),
            permissions: vec![Permission::Read],
        })
    };
    let share_revoked = share_to(&revoked_recipient.public_key);
    assert!(share_revoked.success, "{:?}", share_revoked.error);
    let share_surviving = share_to(&surviving_recipient.public_key);
    assert!(share_surviving.success, "{:?}", share_surviving.error);
    let shared_surviving = share_surviving.data.unwrap();

    // The remaining recipient (separate device) processes the envelope for the old CEK
    let recipient_controller = controller_with_account(server.url());
    let decrypt_v1 = recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        remote_content_id: None,
        private_key: surviving_recipient.private_key.clone(),
        sender_public_key: shared_surviving.sender_public_key.clone(),
        recipient_key_id: shared_surviving.recipient_key_id.clone(),
        key_envelope: shared_surviving.key_envelope.clone(),
        version: None,
    });
    assert!(decrypt_v1.success, "{:?}", decrypt_v1.error);

    // revoke → CEK rotation + envelope reissue for the remaining recipients
    let _update_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}","updated":true}}"#))
        .create_async()
        .await;
    let revoke_response = creator.revoke_share(
        monas_sdk::models::share::RevokeShareInput {
            file_id: created.file_id.clone(),
            remote_content_id: Some(REMOTE_ID.into()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: revoked_recipient.public_key.clone(),
        },
        None,
    );
    assert!(revoke_response.success, "{:?}", revoke_response.error);
    let revoked_output = revoke_response.data.unwrap();
    assert_eq!(
        revoked_output.reissued_envelopes.len(),
        1,
        "one surviving recipient should get a reissued envelope"
    );
    let reissued = &revoked_output.reissued_envelopes[0];
    assert_eq!(
        reissued.recipient_key_id, shared_surviving.recipient_key_id,
        "reissued envelope should target the surviving recipient"
    );
    assert_ne!(
        reissued.key_envelope.ciphertext, shared_surviving.key_envelope.ciphertext,
        "ciphertext must change after CEK rotation"
    );

    // Prepare the state node's new version v2 with the post-rotation ciphertext
    let old_ciphertext = URL_SAFE_NO_PAD
        .decode(&shared_surviving.key_envelope.ciphertext)
        .unwrap();
    let new_ciphertext = URL_SAFE_NO_PAD
        .decode(&reissued.key_envelope.ciphertext)
        .unwrap();
    let genesis_bytes = make_node_bytes(&old_ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();
    let v2_bytes = make_node_bytes(&new_ciphertext, vec![&genesis_cid], Some(&genesis_cid));
    let v2_cid = recompute_node_cid(&v2_bytes).unwrap();

    let _history_mock = mock_history(&mut server, &[&genesis_cid, &v2_cid]).await;
    let _v2_data = mock_version_data(&mut server, &v2_cid, &v2_bytes).await;

    let read_latest = || {
        recipient_controller.read_content_from_state_node(
            ReadContentFromStateNodeInput {
                content_id: REMOTE_ID.into(),
                file_id: None,
                local_content_id: created.content_id.clone(),
                version: None,
                accept_any_version: false,
            },
            None,
        )
    };

    // The new ciphertext cannot be decrypted with the old CEK (guided by an error saying the key
    // is stale)
    let stale_read = read_latest();
    assert!(!stale_read.success, "stale-CEK read must fail");
    match stale_read.error {
        Some(ApiError::Forbidden(msg)) => {
            assert!(
                msg.contains("rotation") || msg.contains("revoked"),
                "msg={msg}"
            )
        }
        other => panic!("expected Forbidden(stale CEK), got: {other:?}"),
    }

    // Process the reissued envelope → the stored CEK is updated to the post-rotation one
    let decrypt_v2 = recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        remote_content_id: None,
        private_key: surviving_recipient.private_key.clone(),
        sender_public_key: shared_surviving.sender_public_key.clone(),
        recipient_key_id: reissued.recipient_key_id.clone(),
        key_envelope: reissued.key_envelope.clone(),
        version: None,
    });
    assert!(decrypt_v2.success, "{:?}", decrypt_v2.error);

    // Subsequent reads can decrypt the new ciphertext
    let fresh_read = read_latest();
    assert!(fresh_read.success, "{:?}", fresh_read.error);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(fresh_read.data.unwrap().content)
            .unwrap(),
        plaintext
    );

    // Resending a pre-rotation old envelope (with an older key_epoch) does not roll back the
    // stored CEK (replay prevention). An attacker cannot use a legitimate old envelope they saved
    // to revert the recipient's CEK to an older generation and break reads.
    assert!(
        reissued.key_envelope.key_epoch > shared_surviving.key_envelope.key_epoch,
        "rotation must advance the envelope key_epoch"
    );
    let replay = recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.content_id.clone(),
        remote_content_id: None,
        private_key: surviving_recipient.private_key.clone(),
        sender_public_key: shared_surviving.sender_public_key.clone(),
        recipient_key_id: shared_surviving.recipient_key_id.clone(),
        key_envelope: shared_surviving.key_envelope.clone(),
        version: None,
    });
    assert!(!replay.success, "pre-rotation envelope replay must fail");
    match replay.error {
        Some(ApiError::Conflict(msg)) => {
            assert!(msg.contains("stale key envelope"), "msg={msg}")
        }
        other => panic!("expected Conflict(stale envelope), got: {other:?}"),
    }
    // The read still succeeds with the new CEK (proof that it was not rolled back)
    let read_after_replay = read_latest();
    assert!(
        read_after_replay.success,
        "read must still succeed after rejected replay: {:?}",
        read_after_replay.error
    );

    // Reprocessing an envelope of the same generation leaves the (sender key, generation, CEK)
    // triple unchanged and does not break reads. Previously this path was "keep the pin, save
    // only the CEK unconditionally", so combined with concurrent processing it could produce a
    // state where the generation and CEK disagree (pin=N+1 / CEK=N). The triple is now swapped
    // via a CAS on a single record, so this path cannot create an inconsistency.
    let reprocess_same_epoch =
        recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
            content_id: created.content_id.clone(),
            remote_content_id: None,
            private_key: surviving_recipient.private_key.clone(),
            sender_public_key: shared_surviving.sender_public_key.clone(),
            recipient_key_id: reissued.recipient_key_id.clone(),
            key_envelope: reissued.key_envelope.clone(),
            version: None,
        });
    assert!(
        reprocess_same_epoch.success,
        "re-processing the current envelope must stay idempotent: {:?}",
        reprocess_same_epoch.error
    );
    let read_after_reprocess = read_latest();
    assert!(
        read_after_reprocess.success,
        "read must still succeed after re-processing the current envelope: {:?}",
        read_after_reprocess.error
    );

    cleanup_content_artifacts();
}

#[tokio::test(flavor = "multi_thread")]
async fn read_rejects_tampered_node() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = controller_with_account(server.url());

    let created = create_and_share(&mut server, &controller, b"tamper-target").await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    // An attacker returns a Node with a fake ciphertext, claiming the legitimate version's CID
    let forged_bytes = make_node_bytes(b"forged-by-attacker", vec![], None);

    let _history_mock = mock_history(&mut server, &[&genesis_cid]).await;
    let _data_mock = mock_version_data(&mut server, &genesis_cid, &forged_bytes).await;

    let response = controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: Some(created.file_id.clone()),
            local_content_id: String::new(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(!response.success, "tampered node must be rejected");
    match response.error {
        Some(ApiError::Internal(msg)) => {
            assert!(msg.contains("CID verification"), "msg={msg}")
        }
        other => panic!("expected Internal(CID verification), got: {other:?}"),
    }

    cleanup_content_artifacts();
}

/// The KeyEnvelope is wrapped in HPKE Auth mode, and the recipient unwraps it with the sender's
/// public key (success = proof that the holder of that key created it).
/// - Processing with the wrong sender key fails at decryption itself
/// - Once processed with the correct key, it is pinned via TOFU, and any other key passed later
///   is rejected
#[tokio::test(flavor = "multi_thread")]
async fn envelope_sender_auth_rejects_wrong_sender_key() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());

    let created = create_and_share(&mut server, &creator, b"sender-auth-target").await;

    let recipient_controller = controller_with_account(server.url());
    let attacker = recipient_controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("attacker keypair");

    let decrypt_with_sender = |sender_public_key: String| {
        recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
            content_id: created.local_content_id.clone(),
            remote_content_id: None,
            private_key: created.recipient_private_key.clone(),
            sender_public_key,
            recipient_key_id: created.shared.recipient_key_id.clone(),
            key_envelope: created.shared.key_envelope.clone(),
            version: None,
        })
    };

    // 1. Process with the wrong sender key (the attacker's key) → unwrap fails
    let wrong_key = decrypt_with_sender(attacker.public_key.clone());
    assert!(!wrong_key.success, "wrong sender key must fail to unwrap");
    match wrong_key.error {
        Some(ApiError::Forbidden(msg)) => {
            assert!(msg.contains("unwrap"), "msg={msg}")
        }
        other => panic!("expected Forbidden(unwrap failure), got: {other:?}"),
    }

    // 2. Process with the correct sender key → succeeds and is pinned via TOFU
    let correct = decrypt_with_sender(created.shared.sender_public_key.clone());
    assert!(correct.success, "{:?}", correct.error);

    // 3. Pass a different key after pinning → rejected for pin mismatch before unwrap
    let after_pin = decrypt_with_sender(attacker.public_key.clone());
    assert!(!after_pin.success, "non-pinned sender key must be rejected");
    match after_pin.error {
        Some(ApiError::Forbidden(msg)) => {
            assert!(msg.contains("pinned"), "msg={msg}")
        }
        other => panic!("expected Forbidden(pin mismatch), got: {other:?}"),
    }

    cleanup_content_artifacts();
}

/// A recipient on a separate device reads a version the owner wrote after sharing.
///
/// The recipient's CEK is under "the id of the shared version". The plaintext CID of the version
/// the owner updated differs from it, so a strict read rejects it with ContentIdMismatch (it cannot
/// be distinguished from tampering). With `accept_any_version`, it decrypts and returns the id the
/// plaintext points to.
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_reads_a_version_written_after_the_share() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());

    let created = create_and_share(&mut server, &creator, b"first version").await;

    // The recipient is a separate instance. It processes the envelope to obtain the CEK.
    let recipient_controller = controller_with_account(server.url());
    let decrypt_response = recipient_controller.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.local_content_id.clone(),
        remote_content_id: None,
        private_key: created.recipient_private_key.clone(),
        sender_public_key: created.shared.sender_public_key.clone(),
        recipient_key_id: created.shared.recipient_key_id.clone(),
        key_envelope: created.shared.key_envelope.clone(),
        version: None,
    });
    assert!(decrypt_response.success, "{:?}", decrypt_response.error);

    // The owner writes a new version (re-encrypted with the same CEK). The new ciphertext is
    // extracted from the envelope produced by sharing once more.
    let update_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .create_async()
        .await;
    let updated = creator
        .update_content(
            monas_sdk::models::content::UpdateContentInput {
                file_id: created.file_id.clone(),
                remote_content_id: REMOTE_ID.into(),
                content: URL_SAFE_NO_PAD.encode(b"second version, written after sharing"),
                metadata: None,
            },
            None,
        )
        .data
        .expect("update should succeed");
    update_mock.assert();
    assert_ne!(updated.version_id, created.local_content_id);

    // Re-sharing is only to extract the ciphertext, so any sender key and destination will do
    // (no recipient processes this envelope). The ACL has been carried over to the edited
    // version, so re-sharing to the original recipient is rejected as "already shared" —
    // use a different destination.
    let sender = creator
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .unwrap();
    let other = creator
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .unwrap();
    let reshared = creator
        .share_content(ShareContentInput {
            file_id: updated.file_id.clone(),
            remote_content_id: Some(REMOTE_ID.into()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: other.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("re-share should succeed");
    let new_ciphertext = URL_SAFE_NO_PAD
        .decode(&reshared.key_envelope.ciphertext)
        .unwrap();

    let v2_bytes = make_node_bytes(&new_ciphertext, vec![], None);
    let v2_cid = recompute_node_cid(&v2_bytes).unwrap();
    let _history = mock_history(&mut server, &[&v2_cid])
        .await
        .expect_at_least(1);
    let _data = mock_version_data(&mut server, &v2_cid, &v2_bytes)
        .await
        .expect_at_least(1);

    // Strict read: reading while expecting the shared version's id is rejected as a mismatch
    let strict = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: None,
            local_content_id: created.local_content_id.clone(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(
        !strict.success,
        "a strict read must not accept a newer version"
    );
    assert!(
        matches!(strict.error, Some(ApiError::Conflict(_))),
        "expected Conflict, got {:?}",
        strict.error
    );

    // any-version read: decrypts with the same CEK, and the id the plaintext points to = the
    // owner's new version id
    let lenient = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: None,
            local_content_id: created.local_content_id.clone(),
            version: None,
            accept_any_version: true,
        },
        None,
    );
    assert!(lenient.success, "{:?}", lenient.error);
    let out = lenient.data.unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.decode(out.content).unwrap(),
        b"second version, written after sharing"
    );
    assert_eq!(out.version, v2_cid);
    assert_eq!(
        out.local_content_id, updated.version_id,
        "the derived plain id is the owner's new version id"
    );

    cleanup_content_artifacts();
}

/// A delegated token is issued with the series ID the State Node knows. A token issued with the
/// local version ID always fails the `monas://content/<series ID>` check.
#[tokio::test(flavor = "multi_thread")]
async fn delegated_token_is_issued_for_the_remote_content_id() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = controller_with_account(server.url());

    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;
    let create_response = controller.create_content(
        CreateContentInput {
            content: URL_SAFE_NO_PAD.encode(b"token resource"),
            metadata: Some(ContentMetadata {
                name: Some("token.txt".to_string()),
                content_type: Some("text/plain".to_string()),
                created_at: None,
                updated_at: None,
            }),
        },
        None,
    );
    let created = create_response
        .data
        .unwrap_or_else(|| panic!("create: {:?}", create_response.error));
    create_mock.assert();
    assert_ne!(created.content_id, REMOTE_ID);

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .unwrap();
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .unwrap();
    let shared = controller.share_content(ShareContentInput {
        file_id: created.file_id.clone(),
        remote_content_id: Some(REMOTE_ID.into()),
        sender_public_key: sender.public_key,
        sender_private_key: sender.private_key,
        recipient_public_key: recipient.public_key,
        permissions: vec![Permission::Read],
    });
    assert!(shared.success, "{:?}", shared.error);

    // The issued token must name the *remote* id, never the local one.
    let token = shared
        .data
        .and_then(|o| o.delegated_access)
        .expect("share issues a delegated token")
        .delegated_token;
    let claims = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).expect("jwt payload"))
            .expect("base64url payload"),
    )
    .unwrap();
    assert!(claims.contains(REMOTE_ID), "claims: {claims}");
    assert!(
        !claims.contains(&created.content_id),
        "token must not name the local id: {claims}"
    );

    cleanup_content_artifacts();
}

/// Read as a share recipient: when the caller passes the delegated token via
/// `Authorization: Bearer` and passes no signature, the SDK signs the read request
/// signature (`monas-request-v1`, operation `read`, resource = id) with the account key while
/// keeping the token as-is. The State Node verifies the signature with the
/// token's `aud` key, so swapping it for a `user:` token does not pass.
#[tokio::test(flavor = "multi_thread")]
async fn delegated_read_keeps_the_bearer_token_and_signs_with_the_account_key() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = controller_with_account(server.url());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let history_mock = server
        .mock("GET", format!("/content/{REMOTE_ID}/history").as_str())
        .match_header("authorization", "Bearer delegated.jwt.token")
        .match_header(
            "x-request-signature",
            mockito::Matcher::Regex(r"^[A-Za-z0-9+/]+=*$".into()),
        )
        .match_header("x-request-timestamp", now.to_string().as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"{REMOTE_ID}","versions":["v1"]}}"#
        ))
        .expect(1)
        .create_async()
        .await;

    let auth = monas_sdk::StateNodeAuthContext {
        authorization: Some("Bearer delegated.jwt.token".to_string()),
        request_signature: None,
        request_timestamp: Some(now),
    };
    let response = controller.get_latest_version(
        monas_sdk::models::state::GetLatestVersionInput {
            content_id: REMOTE_ID.into(),
        },
        Some(&auth),
    );
    assert!(response.success, "{:?}", response.error);
    assert_eq!(response.data.unwrap().latest_version, "v1");
    history_mock.assert();
}

/// The sender pin (record of the key generation) belongs to the series ID. If pinned by version
/// ID, then even when revoke advances the generation after the owner edits and the version ID
/// changes, an old envelope made with the pre-edit version ID is accepted as "no record for that
/// version ID", and rotation's replay prevention is bypassed by a single edit.
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_rotation_envelope_for_an_older_version_id_is_still_refused() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());

    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;
    let _update_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .expect_at_least(1)
        .create_async()
        .await;

    let keypair = || {
        creator
            .generate_keypair(GenerateKeypairInput {
                key_type: KeyType::Secp256r1,
            })
            .data
            .expect("keypair")
    };
    let sender = keypair();
    let bob = keypair();
    let carol = keypair();

    let created = creator
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"pin v1"),
                metadata: Some(ContentMetadata {
                    name: Some("pin.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");

    let share = |content_id: &str,
                 recipient: &monas_sdk::models::keypair::GenerateKeypairOutput| {
        creator
            .share_content(ShareContentInput {
                file_id: content_id.to_string(),
                remote_content_id: Some(REMOTE_ID.into()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Read],
            })
            .data
            .expect("share")
    };
    let bob_v1 = share(&created.file_id, &bob);

    // Bob (another device) processes the epoch-0 envelope for version 1.
    let bob_device = controller_with_account(server.url());
    let decrypt = |content_id: &str, envelope: &monas_sdk::models::share::KeyEnvelope| {
        bob_device.decrypt_shared_content(DecryptSharedContentInput {
            content_id: content_id.to_string(),
            remote_content_id: Some(REMOTE_ID.into()),
            private_key: bob.private_key.clone(),
            sender_public_key: bob_v1.sender_public_key.clone(),
            recipient_key_id: bob_v1.recipient_key_id.clone(),
            key_envelope: envelope.clone(),
            version: None,
        })
    };
    let first = decrypt(&created.content_id, &bob_v1.key_envelope);
    assert!(first.success, "{:?}", first.error);

    // The owner edits (new version id), shares to carol, revokes carol:
    // the CEK rotates and Bob gets an epoch-1 envelope for version 2.
    let updated = creator
        .update_content(
            monas_sdk::models::content::UpdateContentInput {
                file_id: created.file_id.clone(),
                remote_content_id: REMOTE_ID.into(),
                content: URL_SAFE_NO_PAD.encode(b"pin v2 after edit"),
                metadata: None,
            },
            None,
        )
        .data
        .expect("update");
    assert_ne!(updated.version_id, created.content_id);
    share(&updated.file_id, &carol);
    let revoked = creator
        .revoke_share(
            monas_sdk::models::share::RevokeShareInput {
                file_id: updated.file_id.clone(),
                remote_content_id: Some(REMOTE_ID.into()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: carol.public_key.clone(),
            },
            None,
        )
        .data
        .expect("revoke");
    let bob_v2 = revoked
        .reissued_envelopes
        .iter()
        .find(|e| e.recipient_key_id == bob_v1.recipient_key_id)
        .expect("bob is re-wrapped");
    assert!(bob_v2.key_envelope.key_epoch > bob_v1.key_envelope.key_epoch);
    let second = decrypt(&updated.version_id, &bob_v2.key_envelope);
    assert!(second.success, "{:?}", second.error);

    // Replaying the pre-rotation envelope — which names the OLD version id —
    // must be refused: the series has moved on to epoch 1.
    let replay = decrypt(&created.content_id, &bob_v1.key_envelope);
    assert!(
        !replay.success,
        "a pre-rotation envelope must not be accepted"
    );
    match replay.error {
        Some(ApiError::Conflict(msg)) => assert!(msg.contains("stale key envelope"), "{msg}"),
        other => panic!("expected Conflict(stale), got {other:?}"),
    }

    cleanup_content_artifacts();
}

/// Write by the side that received the share. The recipient has no content record, so it
/// encrypts the new plaintext with the sender pin's CEK and PUTs to the owner's series ID with
/// `Authorization: Bearer` (delegated token) + an account-key signature. The owner can decrypt
/// the ciphertext that reached the State Node with their own CEK, and the id the plaintext points
/// to is the returned `version_id`.
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_writes_a_new_version_with_the_delegated_token() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());
    let created = create_and_share(&mut server, &creator, b"owner's first version").await;

    let recipient = controller_with_account(server.url());
    let decrypted = recipient.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.local_content_id.clone(),
        remote_content_id: Some(REMOTE_ID.into()),
        private_key: created.recipient_private_key.clone(),
        sender_public_key: created.shared.sender_public_key.clone(),
        recipient_key_id: created.shared.recipient_key_id.clone(),
        key_envelope: created.shared.key_envelope.clone(),
        version: None,
    });
    assert!(decrypted.success, "{:?}", decrypted.error);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = captured.clone();
    let put_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .match_header("authorization", "Bearer delegated.jwt.token")
        .match_header(
            "x-request-signature",
            mockito::Matcher::Regex(r"^[A-Za-z0-9+/]+=*$".into()),
        )
        .match_header("x-request-timestamp", now.to_string().as_str())
        .match_request(move |req| {
            *sink.lock().unwrap() = req.body().unwrap().clone();
            true
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}","updated":true}}"#))
        .expect(1)
        .create_async()
        .await;

    let auth = monas_sdk::StateNodeAuthContext {
        authorization: Some("Bearer delegated.jwt.token".to_string()),
        request_signature: None,
        request_timestamp: Some(now),
    };
    let written = recipient.update_shared_content(
        UpdateSharedContentInput {
            remote_content_id: REMOTE_ID.into(),
            content: URL_SAFE_NO_PAD.encode(b"recipient's edit"),
        },
        Some(&auth),
    );
    assert!(written.success, "{:?}", written.error);
    let written = written.data.unwrap();
    put_mock.assert();

    // What reached the state node decrypts under the owner's CEK: serve it
    // back as a version and let the owner read it, expecting the id the
    // recipient reported.
    let body: serde_json::Value = serde_json::from_slice(&captured.lock().unwrap()).unwrap();
    let ciphertext = BASE64_STANDARD
        .decode(body["data"].as_str().unwrap())
        .unwrap();
    let node_bytes = make_node_bytes(&ciphertext, vec![], None);
    let cid = recompute_node_cid(&node_bytes).unwrap();
    let _history = mock_history(&mut server, &[&cid]).await;
    let _data = mock_version_data(&mut server, &cid, &node_bytes).await;

    let owner_read = creator.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: Some(created.file_id.clone()),
            local_content_id: String::new(),
            version: None,
            accept_any_version: true,
        },
        None,
    );
    assert!(owner_read.success, "{:?}", owner_read.error);
    let out = owner_read.data.unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.decode(out.content).unwrap(),
        b"recipient's edit"
    );
    assert_eq!(out.local_content_id, written.version_id);
    assert_ne!(written.version_id, created.local_content_id);

    // The recipient can read back the version it wrote, too (CEK cached under
    // the new id as well as pinned on the series).
    let own_read = recipient.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            file_id: None,
            local_content_id: written.version_id.clone(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(own_read.success, "{:?}", own_read.error);

    cleanup_content_artifacts();
}

/// Without a delegated token, the write is rejected before reaching the State Node. The owner's
/// write goes through `update_content`; arriving here with `user:` is a caller error.
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_write_requires_a_bearer_token() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());
    let created = create_and_share(&mut server, &creator, b"owner's version").await;

    let recipient = controller_with_account(server.url());
    let decrypted = recipient.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.local_content_id.clone(),
        remote_content_id: Some(REMOTE_ID.into()),
        private_key: created.recipient_private_key.clone(),
        sender_public_key: created.shared.sender_public_key.clone(),
        recipient_key_id: created.shared.recipient_key_id.clone(),
        key_envelope: created.shared.key_envelope.clone(),
        version: None,
    });
    assert!(decrypted.success, "{:?}", decrypted.error);

    let put_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for authorization in [None, Some("user:010203".to_string())] {
        let auth = monas_sdk::StateNodeAuthContext {
            authorization,
            request_signature: None,
            request_timestamp: Some(now),
        };
        let written = recipient.update_shared_content(
            UpdateSharedContentInput {
                remote_content_id: REMOTE_ID.into(),
                content: URL_SAFE_NO_PAD.encode(b"edit"),
            },
            Some(&auth),
        );
        assert!(
            matches!(written.error, Some(ApiError::Unauthorized(_))),
            "expected Unauthorized, got {:?}",
            written.error
        );
    }
    put_mock.assert();

    cleanup_content_artifacts();
}

/// A series whose share package has not been imported has no CEK, so it cannot be written.
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_write_needs_an_imported_share() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let recipient = controller_with_account(server.url());
    let put_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let auth = monas_sdk::StateNodeAuthContext {
        authorization: Some("Bearer delegated.jwt.token".to_string()),
        request_signature: None,
        request_timestamp: Some(now),
    };
    let written = recipient.update_shared_content(
        UpdateSharedContentInput {
            remote_content_id: "never-shared-here".into(),
            content: URL_SAFE_NO_PAD.encode(b"edit"),
        },
        Some(&auth),
    );
    match written.error {
        Some(ApiError::NotFound(msg)) => assert!(msg.contains("share package"), "{msg}"),
        other => panic!("expected NotFound, got {other:?}"),
    }
    put_mock.assert();

    cleanup_content_artifacts();
}

/// A State Node 4xx reaches the caller with its status intact. Previously ureq turned non-2xx
/// into a transport error, so it was discarded along with the body before reaching
/// `try_state_node_http_error`, and a revoked token's 403 looked like a 500 from the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn a_state_node_refusal_keeps_its_status_and_reason() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = controller_with_account(server.url());
    let created = create_and_share(&mut server, &creator, b"owner's version").await;

    let recipient = controller_with_account(server.url());
    let decrypted = recipient.decrypt_shared_content(DecryptSharedContentInput {
        content_id: created.local_content_id.clone(),
        remote_content_id: Some(REMOTE_ID.into()),
        private_key: created.recipient_private_key.clone(),
        sender_public_key: created.shared.sender_public_key.clone(),
        recipient_key_id: created.shared.recipient_key_id.clone(),
        key_envelope: created.shared.key_envelope.clone(),
        version: None,
    });
    assert!(decrypted.success, "{:?}", decrypted.error);

    let _refused = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"AuthToken invalidated: iat 1 < min_valid_issued_at 2"}"#)
        .create_async()
        .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let auth = monas_sdk::StateNodeAuthContext {
        authorization: Some("Bearer revoked.jwt.token".to_string()),
        request_signature: None,
        request_timestamp: Some(now),
    };

    // Recipient write…
    let written = recipient.update_shared_content(
        UpdateSharedContentInput {
            remote_content_id: REMOTE_ID.into(),
            content: URL_SAFE_NO_PAD.encode(b"after revoke"),
        },
        Some(&auth),
    );
    match written.error {
        Some(ApiError::Forbidden(msg)) => assert!(msg.contains("invalidated"), "{msg}"),
        other => panic!("expected Forbidden, got {other:?}"),
    }

    // …and the owner's own update path map the same way.
    let owner_auth = monas_sdk::StateNodeAuthContext {
        authorization: None,
        request_signature: None,
        request_timestamp: Some(now),
    };
    let updated = creator.update_content(
        monas_sdk::models::content::UpdateContentInput {
            file_id: created.file_id.clone(),
            remote_content_id: REMOTE_ID.into(),
            content: URL_SAFE_NO_PAD.encode(b"owner after refusal"),
            metadata: None,
        },
        Some(&owner_auth),
    );
    match updated.error {
        Some(ApiError::Forbidden(msg)) => assert!(msg.contains("invalidated"), "{msg}"),
        other => panic!("expected Forbidden, got {other:?}"),
    }

    cleanup_content_artifacts();
}

/// Owner-side pull, and revoke not rolling back the recipient's version.
///
/// After Bob, who was delegated write, writes a new version, the owner's local record is older
/// than head. `pull_content_from_state_node` imports that version via a verified read (the local
/// version ID advances to Bob's version ID), and `revoke_share` performs the same import itself
/// before re-encrypting, so both the post-rotation ciphertext and the envelopes reissued to the
/// remaining recipients carry Bob's version.
#[tokio::test(flavor = "multi_thread")]
async fn owner_pulls_a_recipients_version_and_revoke_rotates_that_version() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let owner = controller_with_account(server.url());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let _create = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;
    let puts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let sink = puts.clone();
    let _put = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .match_request(move |req| {
            sink.lock().unwrap().push(req.body().unwrap().clone());
            true
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}","updated":true}}"#))
        .create_async()
        .await;
    let _invalidate = server
        .mock(
            "POST",
            format!("/content/{REMOTE_ID}/access/invalidate").as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"{REMOTE_ID}","new_min_valid_issued_at":{}}}"#,
            now
        ))
        .create_async()
        .await;

    let keypair = |c: &MonasController| {
        c.generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("keypair")
    };
    let sender = keypair(&owner);
    let bob_key = keypair(&owner);
    let carol_key = keypair(&owner);

    let created = owner
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"owner's first version"),
                metadata: Some(ContentMetadata {
                    name: Some("pull.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    let share = |content_id: &str,
                 recipient: &monas_sdk::models::keypair::GenerateKeypairOutput| {
        owner
            .share_content(ShareContentInput {
                file_id: content_id.to_string(),
                remote_content_id: Some(REMOTE_ID.into()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Read, Permission::Write],
            })
            .data
            .expect("share")
    };
    let bob_share = share(&created.file_id, &bob_key);

    // Bob (another device) imports and writes.
    let bob = controller_with_account(server.url());
    let bob_decrypt = |content_id: &str, envelope: &monas_sdk::models::share::KeyEnvelope| {
        bob.decrypt_shared_content(DecryptSharedContentInput {
            content_id: content_id.to_string(),
            remote_content_id: Some(REMOTE_ID.into()),
            private_key: bob_key.private_key.clone(),
            sender_public_key: bob_share.sender_public_key.clone(),
            recipient_key_id: bob_share.recipient_key_id.clone(),
            key_envelope: envelope.clone(),
            version: None,
        })
    };
    let imported = bob_decrypt(&created.content_id, &bob_share.key_envelope);
    assert!(imported.success, "{:?}", imported.error);
    let bob_auth = monas_sdk::StateNodeAuthContext {
        authorization: Some("Bearer delegated.jwt.token".to_string()),
        request_signature: None,
        request_timestamp: Some(now),
    };
    let written = bob
        .update_shared_content(
            UpdateSharedContentInput {
                remote_content_id: REMOTE_ID.into(),
                content: URL_SAFE_NO_PAD.encode(b"bob's version"),
            },
            Some(&bob_auth),
        )
        .data
        .expect("bob writes");

    // The state node now serves Bob's version as the head.
    let bob_body: serde_json::Value =
        serde_json::from_slice(&puts.lock().unwrap().last().unwrap().clone()).unwrap();
    let bob_ciphertext = BASE64_STANDARD
        .decode(bob_body["data"].as_str().unwrap())
        .unwrap();
    let bob_node = make_node_bytes(&bob_ciphertext, vec![], None);
    let bob_cid = recompute_node_cid(&bob_node).unwrap();
    let _history = mock_history(&mut server, &[&bob_cid]).await;
    let _data = mock_version_data(&mut server, &bob_cid, &bob_node).await;

    // Owner pulls: the local record moves to Bob's version, keeping the
    // state node's ciphertext byte for byte.
    let pulled = owner
        .pull_content_from_state_node(
            monas_sdk::models::state::PullContentFromStateNodeInput {
                content_id: REMOTE_ID.into(),
                file_id: created.file_id.clone(),
            },
            None,
        )
        .data
        .expect("pull");
    assert!(pulled.adopted);
    assert_eq!(pulled.local_content_id, written.version_id);
    assert_eq!(pulled.version, bob_cid);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&pulled.content).unwrap(),
        b"bob's version"
    );
    let local = owner
        .get_content(monas_sdk::models::content::GetContentInput {
            file_id: created.file_id.clone(),
        })
        .data
        .expect("adopted version is a local record");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&local.content).unwrap(),
        b"bob's version"
    );
    // Pulling again is a no-op.
    let again = owner
        .pull_content_from_state_node(
            monas_sdk::models::state::PullContentFromStateNodeInput {
                content_id: REMOTE_ID.into(),
                file_id: created.file_id.clone(),
            },
            None,
        )
        .data
        .expect("pull again");
    assert!(!again.adopted);
    assert_eq!(again.local_content_id, pulled.local_content_id);

    // The share ACL is the file's, so it is unaffected by the adoption:
    // sharing to carol works, and revoking her re-wraps Bob (the surviving
    // recipient) for the adopted version.
    share(&created.file_id, &carol_key);
    let owner_auth = monas_sdk::StateNodeAuthContext {
        authorization: None,
        request_signature: None,
        request_timestamp: Some(now),
    };
    let revoked = owner.revoke_share(
        monas_sdk::models::share::RevokeShareInput {
            file_id: created.file_id.clone(),
            remote_content_id: Some(REMOTE_ID.into()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: carol_key.public_key.clone(),
        },
        Some(&owner_auth),
    );
    assert!(revoked.success, "{:?}", revoked.error);
    let revoked = revoked.data.unwrap();
    assert_eq!(revoked.content_id, pulled.local_content_id);
    let bob_rewrap = revoked
        .reissued_envelopes
        .iter()
        .find(|e| e.recipient_key_id == bob_share.recipient_key_id)
        .expect("bob survives the revoke");
    // …and what Bob unwraps from the rotated envelope is his own version,
    // not the owner's stale first draft.
    let rotated = bob_decrypt(&revoked.content_id, &bob_rewrap.key_envelope);
    assert!(rotated.success, "{:?}", rotated.error);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(rotated.data.unwrap().content)
            .unwrap(),
        b"bob's version"
    );
    // The revoke's re-encryption sent to the state node is Bob's version too.
    assert_eq!(
        puts.lock().unwrap().len(),
        2,
        "bob's write + the revoke's rotation"
    );

    cleanup_content_artifacts();
}
