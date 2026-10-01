//! A delete is a crsl-lib `Delete` operation in the content's history. These
//! tests check that it travels between replicas like any other operation and
//! that "deleted" is simply "the history contains a delete" on every replica.

use monas_state_node::{
    infrastructure::crdt_repository::CrslCrdtRepository,
    port::content_repository::ContentRepository,
};
use tempfile::{tempdir, TempDir};

fn replica() -> (TempDir, CrslCrdtRepository) {
    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    (dir, repo)
}

async fn sync(from: &CrslCrdtRepository, to: &CrslCrdtRepository, genesis: &str) {
    let ops = from.get_operations(genesis, None).await.unwrap();
    to.apply_operations(&ops).await.unwrap();
}

#[tokio::test]
async fn delete_reaches_a_member_and_an_offline_member_via_sync() {
    let (_a_dir, a) = replica();
    let (_b_dir, b) = replica();
    let (_c_dir, c) = replica();
    let genesis = a
        .create_content(b"v1", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    a.update_content(&genesis, b"v2", "a", None).await.unwrap();
    sync(&a, &b, &genesis).await;
    sync(&a, &c, &genesis).await;

    a.delete_content(&genesis, "a").await.unwrap();
    assert!(a.is_deleted(&genesis).await.unwrap());
    assert!(!b.is_deleted(&genesis).await.unwrap());

    // The delete is exportable like any other operation.
    sync(&a, &b, &genesis).await;
    assert!(b.is_deleted(&genesis).await.unwrap());

    // `c` was offline; a later sync from either holder brings the delete.
    assert!(!c.is_deleted(&genesis).await.unwrap());
    sync(&b, &c, &genesis).await;
    assert!(c.is_deleted(&genesis).await.unwrap());

    // Re-exporting a history that contains a delete keeps working.
    let ops = c.get_operations(&genesis, None).await.unwrap();
    assert_eq!(a.apply_operations(&ops).await.unwrap(), ops.len());
}

#[tokio::test]
async fn a_write_after_the_delete_does_not_undo_it() {
    let (_a_dir, a) = replica();
    let (_b_dir, b) = replica();
    let genesis = a
        .create_content(b"v1", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    sync(&a, &b, &genesis).await;

    a.delete_content(&genesis, "a").await.unwrap();
    // `b` has not received the delete yet and accepts a write.
    b.update_content(&genesis, b"late", "b", None)
        .await
        .unwrap();

    sync(&a, &b, &genesis).await;
    sync(&b, &a, &genesis).await;

    // The last operation may well be the update; the delete is still in the
    // history, so both replicas treat the content as deleted.
    assert!(a.is_deleted(&genesis).await.unwrap());
    assert!(b.is_deleted(&genesis).await.unwrap());

    // Further exchanges keep succeeding.
    sync(&a, &b, &genesis).await;
    sync(&b, &a, &genesis).await;
    assert!(a.is_deleted(&genesis).await.unwrap());
    assert!(b.is_deleted(&genesis).await.unwrap());
}

#[tokio::test]
async fn deleting_unknown_content_fails() {
    let (_dir, a) = replica();
    let (_other_dir, other) = replica();
    let genesis = other
        .create_content(b"x", "o", None)
        .await
        .unwrap()
        .genesis_cid;
    assert!(a.delete_content(&genesis, "a").await.is_err());
    assert!(!a.is_deleted(&genesis).await.unwrap());
}
