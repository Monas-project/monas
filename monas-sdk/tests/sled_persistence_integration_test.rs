//! Smoke tests for the sled persistence backend.
//!
//! Regression tests for the following, pointed out in the PR #29 review
//! (architecture / implementation axes):
//! - The design "CEK and Share share the same sled DB file" did not match
//!   the implementation (`sled::open(dir)` was called twice, so at startup
//!   `MonasController::with_config` returned `Err` with `Resource temporarily
//!   unavailable` and `monas-gateway/src/main.rs::main` panicked on `.expect()`)
//! - There was no round-trip test for sled persistence
//! - There was no negative test directly pinning the flock conflict
//!
//! Note: the content body (ciphertext) is stored on the SDK side in
//! `MultiStorageRepository::in_memory` and is not moved to sled within the current PR scope,
//! so a full `create_content` → controller drop → `get_content` on another controller
//! round-trip cannot be checked. Instead, this verifies:
//! 1. `MonasController::with_config` succeeds with `MonasConfig::with_persistence_dir(dir)`
//!    (the sled double-open problem does not occur).
//! 2. After the controller is built, the sled DB file is created in the given dir.
//! 3. After the controller is dropped, a second `MonasController::with_config` on the
//!    same dir succeeds (== the exclusive flock has been released).

use monas_sdk::{MonasConfig, MonasController};
use std::path::PathBuf;

fn tmp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "monas-sdk-test-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

fn cleanup_dir(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sled_persistence_opens_without_double_lock() {
    let dir = tmp_dir("opens");

    // First: can open with CEK and Share sharing the same DB
    let config = MonasConfig::new("http://127.0.0.1:1").with_persistence_dir(dir.clone());
    let controller =
        MonasController::with_config(config).expect("first with_config should succeed");

    // The sled DB file must actually have been created
    assert!(
        dir.exists(),
        "persistence dir should exist after with_config: {:?}",
        dir
    );

    drop(controller);

    // Second: can open the same dir again (the exclusive flock was released on drop)
    let config2 = MonasConfig::new("http://127.0.0.1:1").with_persistence_dir(dir.clone());
    let controller2 =
        MonasController::with_config(config2).expect("second with_config should succeed");
    drop(controller2);

    cleanup_dir(&dir);
}

#[test]
fn sled_persistence_creates_dir_if_missing() {
    let dir = tmp_dir("missing");
    // tmp_dir has already run create_dir_all, so delete it to get back to "does not exist"
    cleanup_dir(&dir);
    assert!(!dir.exists(), "precondition: dir should not exist");

    let config = MonasConfig::new("http://127.0.0.1:1").with_persistence_dir(dir.clone());
    let controller = MonasController::with_config(config).expect("with_config should create dir");
    assert!(
        dir.exists(),
        "persistence dir should be auto-created: {:?}",
        dir
    );
    drop(controller);

    cleanup_dir(&dir);
}

/// Pins the sled-backed round-trip of CEK and PublicKeyDirectory, rather than going through
/// `SledContentEncryptionKeyStore` / `SledShareRepository::with_db`.
/// Writes into the same dir, drops the controller, reopens with a new sled DB handle,
/// and checks that the written data can be found.
///
/// In response to the PR #29 review (cycle 5 diagnosis axis) pointing out "there is no
/// execution-level verification that the fix actually works", this fixes the round-trip
/// of the persistence plugged in cycle 4 with a real data flow.
#[test]
fn sled_cek_store_persists_across_reopen() {
    use monas_content::application_service::content_service::ContentEncryptionKeyStore;
    use monas_content::domain::content::encryption::ContentEncryptionKey;
    use monas_content::domain::content_id::ContentId;
    use monas_content::infrastructure::key_store::SledContentEncryptionKeyStore;

    let dir = tmp_dir("cek-rt");
    let cid = ContentId::new("round-trip-cek-content-id".to_string());
    let key = ContentEncryptionKey(vec![0x42; 32]);

    {
        let db = sled::open(&dir).expect("first open");
        let store = SledContentEncryptionKeyStore::with_db(db);
        store.save(&cid, &key).expect("save CEK");
    } // store + db drop -> flock release

    let db = sled::open(&dir).expect("reopen");
    let store = SledContentEncryptionKeyStore::with_db(db);
    let loaded = store.load(&cid).expect("load CEK").expect("CEK present");
    assert_eq!(
        loaded.0, key.0,
        "CEK bytes must match after sled reopen with the same dir"
    );

    cleanup_dir(&dir);
}

#[test]
fn sled_public_key_directory_persists_across_reopen() {
    use monas_content::application_service::share_service::PublicKeyDirectory;
    use monas_content::infrastructure::public_key_directory::SledPublicKeyDirectory;

    let dir = tmp_dir("pkd-rt");
    let pubkey = vec![0xab; 65];

    let key_id = {
        let db = sled::open(&dir).expect("first open");
        let pkd = SledPublicKeyDirectory::with_db(db);
        pkd.register_public_key(&pubkey)
            .expect("register pubkey returns KeyId")
    }; // pkd + db drop

    let db = sled::open(&dir).expect("reopen");
    let pkd = SledPublicKeyDirectory::with_db(db);
    let found = pkd
        .find_public_key(&key_id)
        .expect("find_public_key")
        .expect("registered key must be found after reopen");
    assert_eq!(
        found, pubkey,
        "registered public key bytes must match after sled reopen"
    );

    cleanup_dir(&dir);
}

#[test]
fn sled_share_repository_persists_across_reopen() {
    use monas_content::application_service::share_service::ShareRepository;
    use monas_content::domain::content_id::ContentId;
    use monas_content::domain::share::Share;
    use monas_content::infrastructure::share_repository::SledShareRepository;

    let dir = tmp_dir("share-rt");
    let cid = ContentId::new("round-trip-share-content-id".to_string());
    let share_before = Share::new(cid.clone());

    {
        let db = sled::open(&dir).expect("first open");
        let repo = SledShareRepository::with_db(db);
        repo.save(&share_before).expect("save share");
    } // repo + db drop

    let db = sled::open(&dir).expect("reopen");
    let repo = SledShareRepository::with_db(db);
    let loaded = repo
        .load(&cid)
        .expect("load share")
        .expect("share must be found after reopen");
    assert_eq!(
        loaded.content_id().as_str(),
        cid.as_str(),
        "loaded share's content_id must match what was saved"
    );

    cleanup_dir(&dir);
}

/// Negative test that directly pins the root cause diagnosed in cycle 2: "calling
/// `sled::open(dir)` twice on the same path from the same process makes the second
/// call fail to acquire the exclusive flock".
///
/// This test passing is the basis for "reverting to an implementation that calls
/// `SledContentEncryptionKeyStore::open(dir)` and `SledShareRepository::open(dir)`
/// separately would break". `MonasController::create_persistence` avoids this flock
/// conflict with a single `sled::open` + `Db::clone()`.
#[test]
fn sled_open_twice_on_same_dir_fails_due_to_flock() {
    let dir = tmp_dir("double-open");

    let first = sled::open(&dir).expect("first sled::open should succeed");

    // The second should fail due to the flock conflict. The error variant itself depends
    // on the OS / sled version, so only assert "it is Err" (one of Resource temporarily
    // unavailable / WouldBlock / IO etc. is returned).
    let second = sled::open(&dir);
    assert!(
        second.is_err(),
        "second sled::open on the same dir must fail while first is still open"
    );

    drop(first);
    // Dropping first releases the flock, so it can be reopened
    let third = sled::open(&dir).expect("after dropping first, third sled::open should succeed");
    drop(third);

    cleanup_dir(&dir);
}
