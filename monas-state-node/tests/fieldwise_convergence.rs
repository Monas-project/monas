use monas_state_node::infrastructure::crdt_repository::CrslCrdtRepository;
use monas_state_node::{AccessPolicy, ContentId, ContentRepository, Identity};
use tempfile::tempdir;

#[tokio::test]
async fn newer_write_followed_by_policy_update_must_survive_older_remote_write() {
    let ta = tempdir().unwrap();
    let tb = tempdir().unwrap();
    let a = CrslCrdtRepository::open(ta.path()).unwrap();
    let b = CrslCrdtRepository::open(tb.path()).unwrap();
    let genesis = a
        .create_content(b"base", "alice", None)
        .await
        .unwrap()
        .genesis_cid;
    let policy = AccessPolicy::new(
        ContentId::new(genesis.clone()).unwrap(),
        Identity::user("alice".into()).unwrap(),
    );
    a.update_access_policy(&genesis, policy, "alice")
        .await
        .unwrap();
    b.apply_operations(&a.get_operations(&genesis, None).await.unwrap())
        .await
        .unwrap();

    b.update_content(&genesis, b"older remote write", "bob", None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    a.update_content(&genesis, b"newer owner write", "alice", None)
        .await
        .unwrap();
    let mut policy = a.get_access_policy(&genesis).await.unwrap().unwrap();
    policy.invalidate_tokens();
    a.update_access_policy(&genesis, policy, "alice")
        .await
        .unwrap();

    let oa = a.get_operations(&genesis, None).await.unwrap();
    let ob = b.get_operations(&genesis, None).await.unwrap();
    a.apply_operations(&ob).await.unwrap();
    b.apply_operations(&oa).await.unwrap();
    let actual_a = a.get_latest(&genesis).await.unwrap().unwrap();
    let actual_b = b.get_latest(&genesis).await.unwrap().unwrap();
    println!(
        "a={}, b={}",
        String::from_utf8_lossy(&actual_a),
        String::from_utf8_lossy(&actual_b)
    );
    assert!(
        a.get_access_policy(&genesis)
            .await
            .unwrap()
            .unwrap()
            .min_valid_issued_at()
            > 0
    );
    assert_eq!(
        actual_a, b"newer owner write",
        "policy-only head hid this branch's latest real write"
    );
    assert_eq!(actual_b, b"newer owner write");
}

async fn replicate(from: &CrslCrdtRepository, to: &CrslCrdtRepository, genesis: &str) {
    let operations = from.get_operations(genesis, None).await.unwrap();
    assert_eq!(
        to.apply_operations(&operations).await.unwrap(),
        operations.len()
    );
}

async fn body(repo: &CrslCrdtRepository, genesis: &str) -> Vec<u8> {
    repo.get_latest(genesis).await.unwrap().unwrap()
}

async fn raise_policy(repo: &CrslCrdtRepository, genesis: &str, cutoff: u64) {
    let mut policy = repo.get_access_policy(genesis).await.unwrap().unwrap();
    policy.raise_min_valid_issued_at(cutoff);
    repo.update_access_policy(genesis, policy, "alice")
        .await
        .unwrap();
}

async fn create(repo: &CrslCrdtRepository) -> String {
    let prepared = repo
        .prepare_create_operations(
            b"base",
            "alice",
            Some(Identity::user("alice".into()).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        repo.apply_operations(&prepared.operations).await.unwrap(),
        prepared.operations.len()
    );
    prepared.genesis_cid
}

#[tokio::test]
async fn two_policy_only_tips_keep_the_latest_body_not_the_latest_revoke() {
    let ta = tempdir().unwrap();
    let tb = tempdir().unwrap();
    let a = CrslCrdtRepository::open(ta.path()).unwrap();
    let b = CrslCrdtRepository::open(tb.path()).unwrap();
    let genesis = create(&a).await;
    replicate(&a, &b, &genesis).await;
    b.update_content(&genesis, b"old", "bob", None)
        .await
        .unwrap();
    a.update_content(&genesis, b"new", "alice", None)
        .await
        .unwrap();
    raise_policy(&a, &genesis, 1000).await;
    raise_policy(&b, &genesis, 2000).await;
    let oa = a.get_operations(&genesis, None).await.unwrap();
    let ob = b.get_operations(&genesis, None).await.unwrap();
    a.apply_operations(&ob).await.unwrap();
    b.apply_operations(&oa).await.unwrap();
    for repo in [&a, &b] {
        assert_eq!(body(repo, &genesis).await, b"new");
        assert_eq!(
            repo.get_access_policy(&genesis)
                .await
                .unwrap()
                .unwrap()
                .min_valid_issued_at(),
            2000
        );
    }
}

#[tokio::test]
async fn repeated_merges_and_delayed_delivery_keep_original_write_order_after_restart() {
    let ta = tempdir().unwrap();
    let tb = tempdir().unwrap();
    let tc = tempdir().unwrap();
    let a = CrslCrdtRepository::open(ta.path()).unwrap();
    let b = CrslCrdtRepository::open(tb.path()).unwrap();
    let c = CrslCrdtRepository::open(tc.path()).unwrap();
    let genesis = create(&a).await;
    replicate(&a, &b, &genesis).await;
    replicate(&a, &c, &genesis).await;
    b.update_content(&genesis, b"Z oldest", "bob", None)
        .await
        .unwrap();
    c.update_content(&genesis, b"Y delayed", "carol", None)
        .await
        .unwrap();
    a.update_content(&genesis, b"X newest", "alice", None)
        .await
        .unwrap();
    let oa = a.get_operations(&genesis, None).await.unwrap();
    let ob = b.get_operations(&genesis, None).await.unwrap();
    a.apply_operations(&ob).await.unwrap();
    b.apply_operations(&oa).await.unwrap();
    assert_eq!(body(&a, &genesis).await, b"X newest");
    assert_eq!(body(&b, &genesis).await, b"X newest");
    // Both replicas mint their own merge of the same concurrent writes.
    // Exchange those nodes, then merge the merge nodes before Y arrives.
    let ma = a.get_operations(&genesis, None).await.unwrap();
    let mb = b.get_operations(&genesis, None).await.unwrap();
    a.apply_operations(&mb).await.unwrap();
    b.apply_operations(&ma).await.unwrap();
    assert_eq!(body(&a, &genesis).await, b"X newest");
    assert_eq!(body(&b, &genesis).await, b"X newest");
    drop(a);
    let a = CrslCrdtRepository::open(ta.path()).unwrap();
    // No policy changes here: an older delayed write must not beat an
    // equal-body merge-of-merges, even after its origin is only on disk.
    replicate(&c, &a, &genesis).await;
    replicate(&c, &b, &genesis).await;
    assert_eq!(body(&a, &genesis).await, b"X newest");
    assert_eq!(body(&b, &genesis).await, b"X newest");
    replicate(&a, &c, &genesis).await;
    assert_eq!(body(&c, &genesis).await, b"X newest");
    // A subsequent real write must win, not the freshly timestamped merges.
    c.update_content(&genesis, b"final explicit write", "carol", None)
        .await
        .unwrap();
    replicate(&c, &a, &genesis).await;
    replicate(&c, &b, &genesis).await;
    for repo in [&a, &b, &c] {
        assert_eq!(body(repo, &genesis).await, b"final explicit write");
    }
}
