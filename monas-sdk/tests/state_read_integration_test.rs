// Integration tests intentionally use the test/dev-only `with_urls` constructor.
#![allow(deprecated)]
//! `read_content_from_state_node`(検証付き read)の統合テスト。
//!
//! mockito で State Node を模擬し、以下を検証する:
//! - 作成者が自分の content を state node 経由で読み、平文まで復号できる(A + 復号)
//! - share 受信者が KeyEnvelope 処理後に同じ content を読める(CEK 永続化)
//! - KeyEnvelope 未処理の受信者は MissingKey 由来の NotFound で誘導される
//! - 改ざんされた Node(CID 不一致)は拒否される
//!
//! State Node が返す Node CBOR は crsl-lib `Node` と同じ CBOR 形状のミラー構造体で
//! 生成する(ミラーの正しさは monas-content 側の crsl-lib パリティテストで担保)。

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

/// content を作成し、share 経由で実際の AES-GCM 暗号文を入手する
/// (ciphertext を SDK の外に取り出す公開経路が share envelope しかないため)。
/// 戻り値: (local_content_id, ciphertext, share 出力, sender/recipient keypair)
struct CreatedContent {
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
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-1"}"#,
        )
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
        content_id: created.content_id.clone(),
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
    delegate_mock.assert();

    let ciphertext = URL_SAFE_NO_PAD
        .decode(&shared.key_envelope.ciphertext)
        .expect("envelope ciphertext should be base64url");

    CreatedContent {
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
    let controller = MonasController::with_urls(server.url(), server.url());

    let plaintext = b"state-read-roundtrip";
    let created = create_and_share(&mut server, &controller, plaintext).await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    let history_mock = mock_history(&mut server, &[&genesis_cid]).await;
    let data_mock = mock_version_data(&mut server, &genesis_cid, &genesis_bytes).await;

    let response = controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            local_content_id: created.local_content_id.clone(),
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
    let creator = MonasController::with_urls(server.url(), server.url());

    let plaintext = b"shared-then-read";
    let created = create_and_share(&mut server, &creator, plaintext).await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    // 受信者は別インスタンス(= 別デバイス相当。ローカル content も CEK も無い)
    let recipient_controller = MonasController::with_urls(server.url(), server.url());

    // KeyEnvelope 未処理の状態では CEK が無く、NotFound で share 処理へ誘導される
    // (read は前後 2 回行うので、mock は 2 ヒットを期待する)
    let history_mock = mock_history(&mut server, &[&genesis_cid])
        .await
        .expect_at_least(1);
    let data_mock = mock_version_data(&mut server, &genesis_cid, &genesis_bytes)
        .await
        .expect_at_least(1);
    let before = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
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

    // KeyEnvelope を処理すると CEK が受信者ローカルに永続化される
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

    // 以後は state node 経由の検証付き read で読める
    let after = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
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

/// CEK ローテーションの追従: revoke で CEK が回転した後、
/// - 旧 CEK しか持たない受信者の read は Forbidden(鍵が古い)で落ち、
/// - revoke 出力の再発行 KeyEnvelope を処理すると保存 CEK が更新され、
/// - 以後の state node read が新 ciphertext を復号できる。
#[tokio::test(flavor = "multi_thread")]
async fn cek_rotation_after_revoke_updates_recipient_and_read() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());

    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;
    let _delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-1"}"#,
        )
        .expect_at_least(1)
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

    // 2 名に share(片方を後で revoke する)
    let share_to = |recipient_pub: &str| {
        creator.share_content(ShareContentInput {
            content_id: created.content_id.clone(),
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

    // 残存受信者(別デバイス)が旧 CEK の envelope を処理
    let recipient_controller = MonasController::with_urls(server.url(), server.url());
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

    // revoke → CEK ローテーション + 残存受信者向け envelope 再発行
    let _update_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}","updated":true}}"#))
        .create_async()
        .await;
    let revoke_response = creator.revoke_share(
        monas_sdk::models::share::RevokeShareInput {
            content_id: created.content_id.clone(),
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

    // ローテーション後の ciphertext で state node の新版 v2 を用意
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
                local_content_id: created.content_id.clone(),
                version: None,
                accept_any_version: false,
            },
            None,
        )
    };

    // 旧 CEK のままでは新 ciphertext を復号できない(鍵が古い旨のエラーで誘導)
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

    // 再発行 envelope を処理 → 保存 CEK がローテーション後のものへ更新される
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

    // 以後の read は新 ciphertext を復号できる
    let fresh_read = read_latest();
    assert!(fresh_read.success, "{:?}", fresh_read.error);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(fresh_read.data.unwrap().content)
            .unwrap(),
        plaintext
    );

    // rotation 前の旧 envelope(key_epoch が古い)を再送しても、保存済み CEK は
    // 巻き戻らない(replay 防止)。攻撃者が保存しておいた正規の旧 envelope で
    // 受信者の CEK を旧世代へ戻し、read を壊すことはできない。
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
    // read は引き続き新 CEK で成功する(巻き戻っていない証明)
    let read_after_replay = read_latest();
    assert!(
        read_after_replay.success,
        "read must still succeed after rejected replay: {:?}",
        read_after_replay.error
    );

    // 同一世代の envelope を再処理しても、送信者鍵・世代・CEK の3つ組は
    // そのままで read も壊れない。以前はこの経路が「pin は据え置き、CEK だけ
    // 無条件 save」だったため、並行処理と組み合わせると世代と CEK が食い違う
    // 状態を作れた(pin=N+1 / CEK=N)。3つ組を1レコードの CAS で入れ替える
    // ようにしたので、この経路からは不整合が作れない。
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
    let controller = MonasController::with_urls(server.url(), server.url());

    let created = create_and_share(&mut server, &controller, b"tamper-target").await;

    let genesis_bytes = make_node_bytes(&created.ciphertext, vec![], None);
    let genesis_cid = recompute_node_cid(&genesis_bytes).unwrap();

    // 攻撃者が偽 ciphertext の Node を正規版 CID を騙って返す
    let forged_bytes = make_node_bytes(b"forged-by-attacker", vec![], None);

    let _history_mock = mock_history(&mut server, &[&genesis_cid]).await;
    let _data_mock = mock_version_data(&mut server, &genesis_cid, &forged_bytes).await;

    let response = controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
            local_content_id: created.local_content_id.clone(),
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

/// KeyEnvelope は HPKE Auth モードでラップされており、受信者は送信者公開鍵で
/// unwrap する(成功 = その鍵の持ち主が作った証明)。
/// - 間違った送信者鍵での処理は復号自体が失敗する
/// - 一度正しい鍵で処理すると TOFU でピン留めされ、以後別の鍵を渡しても拒否される
#[tokio::test(flavor = "multi_thread")]
async fn envelope_sender_auth_rejects_wrong_sender_key() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());

    let created = create_and_share(&mut server, &creator, b"sender-auth-target").await;

    let recipient_controller = MonasController::with_urls(server.url(), server.url());
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

    // 1. 間違った送信者鍵(攻撃者の鍵)を渡して処理 → unwrap が失敗する
    let wrong_key = decrypt_with_sender(attacker.public_key.clone());
    assert!(!wrong_key.success, "wrong sender key must fail to unwrap");
    match wrong_key.error {
        Some(ApiError::Forbidden(msg)) => {
            assert!(msg.contains("unwrap"), "msg={msg}")
        }
        other => panic!("expected Forbidden(unwrap failure), got: {other:?}"),
    }

    // 2. 正しい送信者鍵で処理 → 成功し、TOFU でピン留めされる
    let correct = decrypt_with_sender(created.shared.sender_public_key.clone());
    assert!(correct.success, "{:?}", correct.error);

    // 3. ピン留め後に別の鍵を渡す → unwrap 以前にピン不一致で拒否される
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

/// 別デバイスの受信者が、共有後に owner が書いた版を読む。
///
/// 受信者の CEK は「共有された版の id」の下にある。owner が更新した版の平文
/// CID はそれと異なるので、厳密 read は ContentIdMismatch で拒否する(改ざんと
/// 区別できない)。`accept_any_version` なら復号し、平文が指す id を返す。
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_reads_a_version_written_after_the_share() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());

    let created = create_and_share(&mut server, &creator, b"first version").await;

    // 受信者は別インスタンス。envelope を処理して CEK を得る。
    let recipient_controller = MonasController::with_urls(server.url(), server.url());
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

    // owner が新しい版を書く(同じ CEK で再暗号化される)。新しい暗号文は、
    // もう一度 share したときの envelope から取り出す。
    let update_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .with_status(200)
        .create_async()
        .await;
    let updated = creator
        .update_content(
            monas_sdk::models::content::UpdateContentInput {
                local_content_id: created.local_content_id.clone(),
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

    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000001,"expires_at":1700003601,"jti":"jti-2"}"#,
        )
        .create_async()
        .await;
    // 共有し直すのは暗号文を取り出すためだけなので、送信者鍵も宛先も何でも
    // よい(この envelope を処理する受信者はいない)。ACL は編集後の版へ引き
    // 継がれているので、元の受信者への再 share は「共有済み」で拒否される —
    // 別の宛先を使う。
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
            content_id: updated.version_id.clone(),
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
    delegate_mock.assert();

    let v2_bytes = make_node_bytes(&new_ciphertext, vec![], None);
    let v2_cid = recompute_node_cid(&v2_bytes).unwrap();
    let _history = mock_history(&mut server, &[&v2_cid])
        .await
        .expect_at_least(1);
    let _data = mock_version_data(&mut server, &v2_cid, &v2_bytes)
        .await
        .expect_at_least(1);

    // 厳密 read: 共有された版の id を期待して読むと不一致で拒否される
    let strict = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
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

    // any-version read: 同じ CEK で復号でき、平文が指す id = owner 側の新しい版 id
    let lenient = recipient_controller.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: REMOTE_ID.into(),
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

/// 委譲 Token は State Node が知っている系列IDで発行される。ローカル版IDで
/// 発行した Token は `monas://content/<系列ID>` の照合で必ず落ちる。
#[tokio::test(flavor = "multi_thread")]
async fn delegated_token_is_issued_for_the_remote_content_id() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = MonasController::with_urls(server.url(), server.url());

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

    // The issuer must be asked for the *remote* id, never the local one.
    let delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .match_body(mockito::Matcher::PartialJson(
            serde_json::json!({ "content_id": REMOTE_ID }),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-r"}"#,
        )
        .create_async()
        .await;

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
        content_id: created.content_id.clone(),
        remote_content_id: Some(REMOTE_ID.into()),
        sender_public_key: sender.public_key,
        sender_private_key: sender.private_key,
        recipient_public_key: recipient.public_key,
        permissions: vec![Permission::Read],
    });
    assert!(shared.success, "{:?}", shared.error);
    delegate_mock.assert();

    cleanup_content_artifacts();
}

/// share 受信者としての read: 呼び出し側が委譲 Token を `Authorization: Bearer`
/// で渡し署名は渡さない場合、SDK は account 鍵で `read:<id>:<ts>` に署名しつつ
/// Token をそのまま残す。State Node は Token の `aud` 鍵で署名を検証する
/// ので、`user:` トークンに差し替えては通らない。
#[tokio::test(flavor = "multi_thread")]
async fn delegated_read_keeps_the_bearer_token_and_signs_with_the_account_key() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let controller = MonasController::with_urls(server.url(), server.url());

    let sign_mock = server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"P256"}"#,
        )
        .expect(1)
        .create_async()
        .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let history_mock = server
        .mock("GET", format!("/content/{REMOTE_ID}/history").as_str())
        .match_header("authorization", "Bearer delegated.jwt.token")
        .match_header("x-request-signature", "c2lnbmVk")
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
    sign_mock.assert();
    history_mock.assert();
}

/// 送信者ピン(鍵世代の記録)は系列IDに属する。版IDでピンすると、owner が
/// 編集して版IDが変わった後に revoke で世代が進んでも、編集前の版IDで作られた
/// 古い envelope は「その版IDには記録が無い」として受理され、rotation の
/// replay 防止が編集1回で素通りになる。
#[tokio::test(flavor = "multi_thread")]
async fn a_pre_rotation_envelope_for_an_older_version_id_is_still_refused() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());

    let _create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{REMOTE_ID}"}}"#))
        .create_async()
        .await;
    let _delegate_mock = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"delegated_token":"dummy.jwt.token","issued_at":1700000000,"expires_at":1700003600,"jti":"jti-1"}"#,
        )
        .expect_at_least(1)
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
                content_id: content_id.to_string(),
                remote_content_id: Some(REMOTE_ID.into()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Read],
            })
            .data
            .expect("share")
    };
    let bob_v1 = share(&created.content_id, &bob);

    // Bob (another device) processes the epoch-0 envelope for version 1.
    let bob_device = MonasController::with_urls(server.url(), server.url());
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
                local_content_id: created.content_id.clone(),
                remote_content_id: REMOTE_ID.into(),
                content: URL_SAFE_NO_PAD.encode(b"pin v2 after edit"),
                metadata: None,
            },
            None,
        )
        .data
        .expect("update");
    assert_ne!(updated.version_id, created.content_id);
    share(&updated.version_id, &carol);
    let revoked = creator
        .revoke_share(
            monas_sdk::models::share::RevokeShareInput {
                content_id: updated.version_id.clone(),
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

/// 共有を受けた側の write。受信者は content レコードを持たないので、送信者
/// ピンの CEK で新しい平文を暗号化し、owner の系列IDへ `Authorization: Bearer`
/// (委譲 Token)+ account 鍵の署名で PUT する。State Node に届いた暗号文は
/// owner が自分の CEK で復号でき、平文が指す id は返された `version_id`。
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_writes_a_new_version_with_the_delegated_token() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());
    let created = create_and_share(&mut server, &creator, b"owner's first version").await;

    let recipient = MonasController::with_urls(server.url(), server.url());
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
    let sign_mock = server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"P256"}"#,
        )
        .expect(1)
        .create_async()
        .await;
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = captured.clone();
    let put_mock = server
        .mock("PUT", format!("/content/{REMOTE_ID}").as_str())
        .match_header("authorization", "Bearer delegated.jwt.token")
        .match_header("x-request-signature", "c2lnbmVk")
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
    sign_mock.assert();
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
            local_content_id: created.local_content_id.clone(),
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
            local_content_id: written.version_id.clone(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(own_read.success, "{:?}", own_read.error);

    cleanup_content_artifacts();
}

/// 委譲 Token 無しでは State Node に届く前に拒否する。owner の write は
/// `update_content` の経路であり、`user:` でここに来るのは呼び出し側の誤り。
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_write_requires_a_bearer_token() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());
    let created = create_and_share(&mut server, &creator, b"owner's version").await;

    let recipient = MonasController::with_urls(server.url(), server.url());
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

/// share package を取り込んでいない系列には CEK が無いので書けない。
#[tokio::test(flavor = "multi_thread")]
async fn share_recipient_write_needs_an_imported_share() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let recipient = MonasController::with_urls(server.url(), server.url());
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

/// State Node の 4xx はそのステータスのまま呼び出し側へ届く。以前は ureq が
/// 非 2xx を transport error にしていたため、`try_state_node_http_error` に
/// 届く前に body ごと捨てられ、失効 Token の 403 が gateway から 500 に見えた。
#[tokio::test(flavor = "multi_thread")]
async fn a_state_node_refusal_keeps_its_status_and_reason() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let creator = MonasController::with_urls(server.url(), server.url());
    let created = create_and_share(&mut server, &creator, b"owner's version").await;

    let recipient = MonasController::with_urls(server.url(), server.url());
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

    let _sign = server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"P256"}"#,
        )
        .create_async()
        .await;
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
            local_content_id: created.local_content_id.clone(),
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

/// owner 側の pull と、revoke が受信者の版を巻き戻さないこと。
///
/// write を委譲した Bob が新しい版を書いた後、owner のローカルレコードは
/// head より古い。`pull_content_from_state_node` はその版を検証付き read で
/// 取り込み(ローカル版IDが Bob の版IDへ進む)、`revoke_share` は再暗号化の
/// 前に同じ取り込みを自分で行うので、ローテーション後の暗号文も、残存受信者へ
/// 再発行される envelope も Bob の版を運ぶ。
#[tokio::test(flavor = "multi_thread")]
async fn owner_pulls_a_recipients_version_and_revoke_rotates_that_version() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let owner = MonasController::with_urls(server.url(), server.url());
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
    let _delegate = server
        .mock("POST", "/issuer/delegate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"delegated_token":"dummy.jwt.token","issued_at":{},"expires_at":{},"jti":"jti-x"}}"#,
            now + 10,
            now + 3610
        ))
        .create_async()
        .await;
    let _sign = server
        .mock("POST", "/accounts/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"signature_base64":"c2lnbmVk","public_key_base64":"AQID","algorithm":"P256"}"#,
        )
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
                content_id: content_id.to_string(),
                remote_content_id: Some(REMOTE_ID.into()),
                sender_public_key: sender.public_key.clone(),
                sender_private_key: sender.private_key.clone(),
                recipient_public_key: recipient.public_key.clone(),
                permissions: vec![Permission::Read, Permission::Write],
            })
            .data
            .expect("share")
    };
    let bob_share = share(&created.content_id, &bob_key);

    // Bob (another device) imports and writes.
    let bob = MonasController::with_urls(server.url(), server.url());
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
                local_content_id: created.content_id.clone(),
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
            content_id: pulled.local_content_id.clone(),
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
                local_content_id: pulled.local_content_id.clone(),
            },
            None,
        )
        .data
        .expect("pull again");
    assert!(!again.adopted);
    assert_eq!(again.local_content_id, pulled.local_content_id);

    // The share ACL followed the adoption: sharing to carol from the pulled
    // id works, and revoking her re-wraps Bob (the surviving recipient).
    // Revoke pulls by itself, so a caller still holding the pre-pull id is
    // not a problem either — pass the ORIGINAL id here on purpose.
    share(&pulled.local_content_id, &carol_key);
    let owner_auth = monas_sdk::StateNodeAuthContext {
        authorization: None,
        request_signature: None,
        request_timestamp: Some(now),
    };
    let revoked = owner.revoke_share(
        monas_sdk::models::share::RevokeShareInput {
            content_id: created.content_id.clone(),
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
