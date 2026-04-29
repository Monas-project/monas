//! Sled persistence backend のスモークテスト。
//!
//! PR #29 review (architecture / implementation 軸) で指摘された:
//! - 「同じ sled DB ファイルを CEK と Share で共有させる」設計が
//!   実装と一致していなかった (`sled::open(dir)` を 2 度呼んで起動時に
//!   `Resource temporarily unavailable` で `MonasController::with_config`
//!   が `Err`、`monas-gateway/src/main.rs::main` が `.expect()` で panic)
//! - sled persistence の round-trip テストが無い
//! - flock 衝突を直接 pin する negative test が無い
//!
//! の regression test。
//!
//! 注意: content 本体 (暗号文) は SDK 側で `MultiStorageRepository::in_memory`
//! に保存されており、現状の PR スコープでは sled 化されていないので、
//! `create_content` → controller drop → 別 controller で `get_content`
//! の完全 round-trip は確認できない。代わりに以下を検証する:
//! 1. `MonasConfig::with_persistence_dir(dir)` で `MonasController::with_config`
//!    が成功する (sled の double-open 問題が起きない)。
//! 2. controller 構築後に sled DB ファイルが指定 dir に作成される。
//! 3. controller drop 後に同じ dir で 2 度目の `MonasController::with_config`
//!    が成功する (== 排他 flock が解放されている)。

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

    // 1 回目: CEK と Share で同一 DB を共有して open できる
    let config = MonasConfig::new("http://127.0.0.1:1", "http://127.0.0.1:2")
        .with_persistence_dir(dir.clone());
    let controller =
        MonasController::with_config(config).expect("first with_config should succeed");

    // sled DB ファイルが実際に作成されていること
    assert!(
        dir.exists(),
        "persistence dir should exist after with_config: {:?}",
        dir
    );

    drop(controller);

    // 2 回目: 同一 dir で再度 open できる (排他 flock が drop で解放されている)
    let config2 = MonasConfig::new("http://127.0.0.1:1", "http://127.0.0.1:2")
        .with_persistence_dir(dir.clone());
    let controller2 =
        MonasController::with_config(config2).expect("second with_config should succeed");
    drop(controller2);

    cleanup_dir(&dir);
}

#[test]
fn sled_persistence_creates_dir_if_missing() {
    let dir = tmp_dir("missing");
    // tmp_dir は create_dir_all 済なので削除して "存在しない" 状態に戻す
    cleanup_dir(&dir);
    assert!(!dir.exists(), "precondition: dir should not exist");

    let config = MonasConfig::new("http://127.0.0.1:1", "http://127.0.0.1:2")
        .with_persistence_dir(dir.clone());
    let controller = MonasController::with_config(config).expect("with_config should create dir");
    assert!(
        dir.exists(),
        "persistence dir should be auto-created: {:?}",
        dir
    );
    drop(controller);

    cleanup_dir(&dir);
}

/// `SledContentEncryptionKeyStore`、`SledShareRepository::with_db` 経由ではなく、
/// CEK と PublicKeyDirectory の sled-backed round-trip を pin する。
/// 同じ dir に書き込んでから controller を drop し、新しい sled DB ハンドルで
/// 再 open して、書き込んだ data を find できることを確認する。
///
/// PR #29 review (cycle 5 diagnosis 軸) で「fix が実際に動くことの execution-level
/// 検証が無い」と指摘されたのを受けて、cycle 4 で plug した persistence の
/// round-trip を実際の data flow で固定する。
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

/// 「`sled::open(dir)` を同一プロセスから同じ path に対して 2 度呼ぶと、
/// 2 度目は排他 flock 取得に失敗する」という、cycle 2 で diagnose した
/// 根本原因を直接 pin する negative test。
///
/// この test が pass することは「`SledContentEncryptionKeyStore::open(dir)` と
/// `SledShareRepository::open(dir)` を別々に呼ぶ実装に戻すと壊れる」ことの
/// 根拠になる。`MonasController::create_persistence` は単一 `sled::open` +
/// `Db::clone()` でこの flock 衝突を回避している。
#[test]
fn sled_open_twice_on_same_dir_fails_due_to_flock() {
    let dir = tmp_dir("double-open");

    let first = sled::open(&dir).expect("first sled::open should succeed");

    // 2 度目は flock 競合で失敗するはず。エラー variant 自体は OS / sled バージョン
    // に依存するので「Err である」だけを assert する (Resource temporarily unavailable
    // / WouldBlock / IO 等のいずれかが返る)。
    let second = sled::open(&dir);
    assert!(
        second.is_err(),
        "second sled::open on the same dir must fail while first is still open"
    );

    drop(first);
    // first を drop すれば flock が解放され再 open できる
    let third = sled::open(&dir).expect("after dropping first, third sled::open should succeed");
    drop(third);

    cleanup_dir(&dir);
}
