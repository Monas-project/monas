// Integration tests intentionally use the test/dev-only `with_state_node_url` constructor.
#![allow(deprecated)]
//! A file's local identity must not be derived from its body alone.
//!
//! The owner's local records (content record, CEK, share ACL) used to be keyed
//! by the plainCid — the SHA-256 of the body. Two different files (different
//! Content Networks) whose bodies were ever identical then shared those
//! records, and a body edited back to an earlier text reused that text's old
//! records. These tests pin the per-file behaviour.

use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use mockito::{Server, ServerGuard};
use monas_content::infrastructure::node_verification::recompute_node_cid;
use monas_sdk::models::content::{
    ContentMetadata, CreateContentInput, CreateContentOutput, DeleteContentInput,
    UpdateContentInput,
};
use monas_sdk::models::keypair::{GenerateKeypairInput, GenerateKeypairOutput, KeyType};
use monas_sdk::models::share::{Permission, RevokeShareInput, ShareContentInput};
use monas_sdk::models::state::ReadContentFromStateNodeInput;
use monas_sdk::{ApiError, MonasConfig, MonasController, StateNodeAuthContext};
use std::time::Duration;

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts, node_mirror::make_node_bytes};

fn controller(state_node_url: String) -> MonasController {
    let config = MonasConfig::new(state_node_url)
        .with_request_timestamp_skew(Duration::from_secs(60 * 60 * 24 * 365 * 100));
    let controller = MonasController::with_config(config).expect("with_config");
    controller
        .create_signing_account()
        .data
        .expect("create signing account");
    controller
}

fn owner_auth() -> StateNodeAuthContext {
    StateNodeAuthContext {
        authorization: Some("Bearer owner".to_string()),
        request_signature: Some("caller-signature".into()),
        request_timestamp: Some(1_717_171_717),
    }
}

fn keypair(controller: &MonasController) -> GenerateKeypairOutput {
    controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("keypair")
}

fn key_id_of(kp: &GenerateKeypairOutput) -> String {
    use sha2::{Digest, Sha256};
    let pk = URL_SAFE_NO_PAD.decode(&kp.public_key).unwrap();
    URL_SAFE_NO_PAD.encode(&Sha256::digest(&pk)[..16])
}

/// Mocks everything the state node is asked for one Content Network.
async fn network(server: &mut ServerGuard, remote: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    server
        .mock("PUT", format!("/content/{remote}").as_str())
        .with_status(200)
        .create_async()
        .await;
    server
        .mock("DELETE", format!("/content/{remote}").as_str())
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"delete failed"}"#)
        .create_async()
        .await;
    server
        .mock(
            "POST",
            format!("/content/{remote}/access/invalidate").as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"content_id":"{remote}","new_min_valid_issued_at":{now}}}"#
        ))
        .create_async()
        .await;
}

/// Creates a file whose Content Network is `remote`.
async fn create(
    server: &mut ServerGuard,
    controller: &MonasController,
    remote: &str,
    body: &[u8],
) -> CreateContentOutput {
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"content_id":"{remote}"}}"#))
        .create_async()
        .await;
    network(server, remote).await;
    let created = controller
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(body),
                metadata: Some(ContentMetadata {
                    name: Some(format!("{remote}.txt")),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    create_mock.assert_async().await;
    create_mock.remove_async().await;
    created
}

fn edit(controller: &MonasController, handle: &str, remote: &str, body: &[u8]) -> String {
    let r = controller.update_content(
        UpdateContentInput {
            file_id: handle.to_string(),
            remote_content_id: remote.to_string(),
            content: URL_SAFE_NO_PAD.encode(body),
            metadata: None,
        },
        Some(&owner_auth()),
    );
    assert!(r.success, "update: {:?}", r.error);
    r.data.unwrap().version_id
}

fn share(
    controller: &MonasController,
    handle: &str,
    remote: &str,
    sender: &GenerateKeypairOutput,
    to: &GenerateKeypairOutput,
) -> monas_sdk::ApiResponse<monas_sdk::models::share::ShareContentOutput> {
    controller.share_content(ShareContentInput {
        file_id: handle.to_string(),
        remote_content_id: Some(remote.to_string()),
        sender_public_key: sender.public_key.clone(),
        sender_private_key: sender.private_key.clone(),
        recipient_public_key: to.public_key.clone(),
        permissions: vec![Permission::Read],
    })
}

fn revoke(
    controller: &MonasController,
    handle: &str,
    remote: &str,
    sender: &GenerateKeypairOutput,
    who: &GenerateKeypairOutput,
) -> monas_sdk::models::share::RevokeShareOutput {
    let r = controller.revoke_share(
        RevokeShareInput {
            file_id: handle.to_string(),
            remote_content_id: Some(remote.to_string()),
            sender_public_key: sender.public_key.clone(),
            sender_private_key: sender.private_key.clone(),
            recipient_public_key: who.public_key.clone(),
        },
        Some(&owner_auth()),
    );
    assert!(r.success, "revoke: {:?}", r.error);
    r.data.unwrap()
}

/// Two files (two Content Networks) created from the same template text keep
/// separate share settings. Revoking Carol on B must not produce a key or a
/// token for Bob, who was only ever given A.
#[tokio::test(flavor = "multi_thread")]
async fn two_files_with_the_same_initial_body_keep_separate_share_settings() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let c = controller(server.url());
    let (alice, bob, carol) = (keypair(&c), keypair(&c), keypair(&c));

    let a = create(&mut server, &c, "file-a", b"same template").await;
    edit(&c, &a.file_id, "file-a", b"A after edit");
    assert!(share(&c, &a.file_id, "file-a", &alice, &bob).success);

    let b = create(&mut server, &c, "file-b", b"same template").await;
    edit(&c, &b.file_id, "file-b", b"B after edit");
    assert!(share(&c, &b.file_id, "file-b", &alice, &carol).success);

    let out = revoke(&c, &b.file_id, "file-b", &alice, &carol);
    let reissued: Vec<_> = out
        .reissued_envelopes
        .iter()
        .map(|e| e.recipient_key_id.clone())
        .collect();
    assert!(
        !reissued.contains(&key_id_of(&bob)),
        "bob was never given file B; reissued to {reissued:?}"
    );
    cleanup_content_artifacts();
}

/// Creating a second file with the same body must not replace the first
/// file's content key: the owner still decrypts the first file's ciphertext.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_file_with_the_same_body_leaves_the_first_readable() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let c = controller(server.url());
    let (alice, bob) = (keypair(&c), keypair(&c));

    let a = create(&mut server, &c, "file-a", b"same body").await;
    // The share envelope is the public way to get the stored ciphertext out.
    let shared = share(&c, &a.file_id, "file-a", &alice, &bob)
        .data
        .expect("share a");
    let a_ciphertext = URL_SAFE_NO_PAD
        .decode(&shared.key_envelope.ciphertext)
        .unwrap();
    let _b = create(&mut server, &c, "file-b", b"same body").await;

    let node = make_node_bytes(&a_ciphertext, vec![], None);
    let cid = recompute_node_cid(&node).unwrap();
    server
        .mock("GET", "/content/file-a/history")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({"content_id": "file-a", "versions": [cid]}).to_string())
        .create_async()
        .await;
    server
        .mock("GET", format!("/content/file-a/version/{cid}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::json!({"content_id": "file-a", "data": BASE64_STANDARD.encode(&node), "version": cid})
                .to_string(),
        )
        .create_async()
        .await;

    let read = c.read_content_from_state_node(
        ReadContentFromStateNodeInput {
            content_id: "file-a".into(),
            file_id: Some(a.file_id.clone()),
            local_content_id: String::new(),
            version: None,
            accept_any_version: false,
        },
        None,
    );
    assert!(read.success, "the owner reads file A: {:?}", read.error);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(read.data.unwrap().content).unwrap(),
        b"same body"
    );
    cleanup_content_artifacts();
}

/// A delete the state node refuses is rolled back locally without losing the
/// file's share settings: sharing again to an existing recipient is still a
/// conflict, not a new share.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_delete_keeps_the_files_share_settings() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let c = controller(server.url());
    let (alice, bob) = (keypair(&c), keypair(&c));

    let f = create(&mut server, &c, "file-d", b"before delete v1").await;
    edit(&c, &f.file_id, "file-d", b"before delete v2");
    assert!(share(&c, &f.file_id, "file-d", &alice, &bob).success);

    let deleted = c.delete_content(
        DeleteContentInput {
            file_id: f.file_id.clone(),
            remote_content_id: "file-d".into(),
        },
        Some(&owner_auth()),
    );
    assert!(!deleted.success, "the state node refuses the delete");

    let again = share(&c, &f.file_id, "file-d", &alice, &bob);
    assert!(
        matches!(again.error, Some(ApiError::Conflict(_))),
        "bob is still a recipient after the rollback: {:?}",
        again.error
    );
    cleanup_content_artifacts();
}

/// After an edit and a revoke (which rotates the key), a new share carries
/// the current ciphertext — the one the surviving recipient was re-wrapped
/// for — not an earlier version's.
#[tokio::test(flavor = "multi_thread")]
async fn a_share_after_an_edit_and_a_revoke_wraps_the_current_version() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let c = controller(server.url());
    let (alice, bob, carol, dave) = (keypair(&c), keypair(&c), keypair(&c), keypair(&c));

    let f = create(&mut server, &c, "file-r", b"rotate v1").await;
    assert!(share(&c, &f.file_id, "file-r", &alice, &bob).success);
    let now = edit(&c, &f.file_id, "file-r", b"rotate v2");
    assert!(share(&c, &f.file_id, "file-r", &alice, &carol).success);
    let out = revoke(&c, &f.file_id, "file-r", &alice, &carol);
    assert_eq!(out.content_id, now, "re-wrapped for the current version");
    let bob_current = out
        .reissued_envelopes
        .iter()
        .find(|e| e.recipient_key_id == key_id_of(&bob))
        .expect("bob is re-wrapped")
        .key_envelope
        .clone();

    // A tab opened before the edit still holds the same file id (it does not
    // change on edits), so its share to Dave carries the current version.
    let pkg = share(&c, &f.file_id, "file-r", &alice, &dave)
        .data
        .expect("share to dave");
    assert_eq!(pkg.content_id, now);
    assert_eq!(
        pkg.key_envelope.ciphertext, bob_current.ciphertext,
        "a new share must carry the current version's ciphertext"
    );
    assert_eq!(pkg.key_envelope.key_epoch, bob_current.key_epoch);
    cleanup_content_artifacts();
}

/// The file key is device-local: it is never sent to the state node nor put
/// in a token. A file not registered on the state node (no
/// `remote_content_id`) gets no token, and its revoke contacts nobody.
#[tokio::test(flavor = "multi_thread")]
async fn the_file_key_never_leaves_the_device() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let c = controller(server.url());
    let (alice, bob, carol) = (keypair(&c), keypair(&c), keypair(&c));
    // Only the create is mocked; any other request to the state node fails
    // the `expect(0)` below.
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"content_id":"file-local"}"#)
        .create_async()
        .await;
    let f = c
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"local only"),
                metadata: Some(ContentMetadata {
                    name: Some("local.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    create_mock.remove_async().await;
    let anything = server
        .mock("ANY", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;

    let to_bob = c
        .share_content(ShareContentInput {
            file_id: f.file_id.clone(),
            remote_content_id: None,
            sender_public_key: alice.public_key.clone(),
            sender_private_key: alice.private_key.clone(),
            recipient_public_key: bob.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .data
        .expect("share");
    assert!(to_bob.delegated_access.is_none());
    assert_eq!(
        to_bob.content_id, f.content_id,
        "the package names the plainCid"
    );
    assert!(
        c.share_content(ShareContentInput {
            file_id: f.file_id.clone(),
            remote_content_id: None,
            sender_public_key: alice.public_key.clone(),
            sender_private_key: alice.private_key.clone(),
            recipient_public_key: carol.public_key.clone(),
            permissions: vec![Permission::Read],
        })
        .success
    );
    let out = c.revoke_share(
        RevokeShareInput {
            file_id: f.file_id.clone(),
            remote_content_id: None,
            sender_public_key: alice.public_key.clone(),
            sender_private_key: alice.private_key.clone(),
            recipient_public_key: carol.public_key.clone(),
        },
        Some(&owner_auth()),
    );
    assert!(out.success, "{:?}", out.error);
    assert!(out.data.unwrap().reissued_envelopes[0]
        .delegated_access
        .is_none());
    anything.assert_async().await;
    cleanup_content_artifacts();
}

/// A tiny state-node stand-in whose FIRST `PUT /content/race-remote` is held
/// until the test releases it, then answered 500. Every other request
/// succeeds. mockito answers immediately, so it cannot hold one request
/// while another one runs.
mod held_put {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex};

    pub struct HeldPut {
        pub url: String,
        pub arrived: Receiver<()>,
        pub release: Sender<()>,
    }

    fn respond(stream: &mut TcpStream, status: &str, body: &str) {
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
    }

    fn serve(
        stream: TcpStream,
        first: Arc<AtomicBool>,
        arrived: Sender<()>,
        release: Arc<Mutex<Receiver<()>>>,
    ) {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut length = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h == "\r\n" {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            if line.starts_with("POST /content ") {
                respond(&mut writer, "200 OK", r#"{"content_id":"race-remote"}"#);
            } else if line.starts_with("PUT /content/race-remote ")
                && first.swap(false, Ordering::SeqCst)
            {
                arrived.send(()).unwrap();
                release.lock().unwrap().recv().unwrap();
                respond(
                    &mut writer,
                    "500 Internal Server Error",
                    r#"{"error":"held"}"#,
                );
            } else {
                respond(&mut writer, "200 OK", "");
            }
        }
    }

    pub fn start() -> HeldPut {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (arrived_tx, arrived) = channel();
        let (release, release_rx) = channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let first = Arc::new(AtomicBool::new(true));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (first, arrived_tx, release_rx) =
                    (first.clone(), arrived_tx.clone(), release_rx.clone());
                std::thread::spawn(move || serve(stream, first, arrived_tx, release_rx));
            }
        });
        HeldPut {
            url,
            arrived,
            release,
        }
    }
}

/// Two tabs edit one file. Tab A's save is still waiting for the state node
/// when tab B's save goes through; then A's save fails. Rolling A back must
/// not undo B: the local record and its CEK are one per file, so restoring
/// the snapshot A took before saving would put the pre-A body back over B's.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_save_does_not_undo_a_save_that_succeeded_meanwhile() {
    let _guard = acquire_test_lock();
    let stub = held_put::start();
    let c = std::sync::Arc::new(controller(stub.url.clone()));
    let f = c
        .create_content(
            CreateContentInput {
                content: URL_SAFE_NO_PAD.encode(b"v1"),
                metadata: Some(ContentMetadata {
                    name: Some("race.txt".to_string()),
                    content_type: Some("text/plain".to_string()),
                    created_at: None,
                    updated_at: None,
                }),
            },
            None,
        )
        .data
        .expect("create");
    let save = |body: &'static [u8]| {
        let (c, file_id) = (c.clone(), f.file_id.clone());
        let rt = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let _rt = rt.enter();
            c.update_content(
                UpdateContentInput {
                    file_id,
                    remote_content_id: "race-remote".into(),
                    content: URL_SAFE_NO_PAD.encode(body),
                    metadata: None,
                },
                Some(&owner_auth()),
            )
            .success
        })
    };

    let a = save(b"tab A");
    stub.arrived
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("A reached the state node");
    let b = save(b"tab B");
    std::thread::sleep(std::time::Duration::from_millis(500));
    stub.release.send(()).unwrap();
    assert!(!a.join().unwrap(), "A's save fails");
    assert!(b.join().unwrap(), "B's save succeeds");

    let now = c
        .get_content(monas_sdk::models::content::GetContentInput {
            file_id: f.file_id.clone(),
        })
        .data
        .expect("get");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(now.content).unwrap(),
        b"tab B",
        "B's successful save must survive A's rollback"
    );
    cleanup_content_artifacts();
}
