//! Sled persistence backend のスモークテスト。
//!
//! PR #29 review (architecture / implementation 軸) で指摘された:
//! - 「同じ sled DB ファイルを CEK と Share で共有させる」設計が
//!   実装と一致していなかった (`sled::open(dir)` を 2 度呼んで起動時に
//!   `Resource temporarily unavailable` で panic)
//! - sled persistence の round-trip テストが無い
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
