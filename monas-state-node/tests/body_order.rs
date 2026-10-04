use crsl_lib::{
    convergence::metadata::ContentMetadata,
    crdt::operation::{Operation, OperationType},
    dasl::node::Node,
};
use monas_state_node::{
    domain::{access_policy::AccessPolicy, identity::Identity},
    infrastructure::crdt_repository::{ContentPayload, CrslCrdtRepository},
    port::content_repository::ContentRepository,
};
use tempfile::tempdir;

async fn payload(repo: &CrslCrdtRepository, genesis: &str) -> ContentPayload {
    let (bytes, _) = repo
        .get_latest_node_bytes_with_version(genesis)
        .await
        .unwrap()
        .unwrap();
    Node::<ContentPayload, ContentMetadata>::from_bytes(&bytes)
        .unwrap()
        .payload
}

#[tokio::test]
async fn a_write_advances_past_an_imported_future_stamp_after_restart() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let source = CrslCrdtRepository::open(source_dir.path()).unwrap();
    let genesis = source
        .create_content(b"base", "owner", None)
        .await
        .unwrap()
        .genesis_cid;
    source
        .update_content(&genesis, b"zzz future", "owner", None)
        .await
        .unwrap();
    let mut ops = source.get_operations(&genesis, None).await.unwrap();
    let last = ops.last_mut().unwrap();
    let mut op: Operation<cid::Cid, ContentPayload> = serde_json::from_slice(&last.data).unwrap();
    let OperationType::Update(body) = &mut op.kind else {
        panic!("expected a write")
    };
    let future = u64::MAX / 2;
    body.body_updated_at = future;
    last.data = serde_json::to_vec(&op).unwrap();
    {
        let target = CrslCrdtRepository::open(target_dir.path()).unwrap();
        target.apply_operations(&ops).await.unwrap();
        assert_eq!(payload(&target, &genesis).await.body_updated_at, future);
    }
    let target = CrslCrdtRepository::open(target_dir.path()).unwrap();
    target
        .update_content(&genesis, b"aaa newer", "owner", None)
        .await
        .unwrap();
    let latest = payload(&target, &genesis).await;
    assert!(latest.body_updated_at > future);
    assert_eq!(latest.data, b"aaa newer");
    let third_dir = tempdir().unwrap();
    let third = CrslCrdtRepository::open(third_dir.path()).unwrap();
    third
        .apply_operations(&target.get_operations(&genesis, None).await.unwrap())
        .await
        .unwrap();
    assert_eq!(payload(&third, &genesis).await, latest);
}

#[tokio::test]
async fn stale_explicit_policies_cannot_lower_the_observed_boundary() {
    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let prepared = repo
        .prepare_create_operations(
            b"base",
            "owner",
            Some(Identity::user("owner".into()).unwrap()),
        )
        .await
        .unwrap();
    repo.apply_operations(&prepared.operations).await.unwrap();
    let genesis = prepared.genesis_cid;
    let stale = repo.get_access_policy(&genesis).await.unwrap().unwrap();
    let original = payload(&repo, &genesis).await;
    let mut newer = stale.clone();
    newer.raise_min_valid_issued_at(100);
    repo.update_access_policy(&genesis, newer, "owner")
        .await
        .unwrap();
    repo.update_access_policy(&genesis, stale.clone(), "owner")
        .await
        .unwrap();
    let policy_only = payload(&repo, &genesis).await;
    assert_eq!(policy_only.data, original.data);
    assert_eq!(policy_only.body_updated_at, original.body_updated_at);
    assert_eq!(
        policy_only.access_policy.unwrap().min_valid_issued_at(),
        100
    );
    repo.update_content(&genesis, b"new", "owner", Some(stale))
        .await
        .unwrap();
    let written = payload(&repo, &genesis).await;
    assert_eq!(written.data, b"new");
    assert!(written.body_updated_at > original.body_updated_at);
    assert_eq!(written.access_policy.unwrap().min_valid_issued_at(), 100);
}

#[tokio::test]
async fn create_and_initial_policy_share_body_order_and_missing_order_is_rejected() {
    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let prepared = repo
        .prepare_create_operations(
            b"base",
            "owner",
            Some(Identity::user("owner".into()).unwrap()),
        )
        .await
        .unwrap();
    let ops = prepared.operations;
    let first: Operation<cid::Cid, ContentPayload> = serde_json::from_slice(&ops[0].data).unwrap();
    let second: Operation<cid::Cid, ContentPayload> = serde_json::from_slice(&ops[1].data).unwrap();
    let OperationType::Create(created) = first.kind else {
        panic!("expected create")
    };
    let OperationType::Update(policy) = second.kind else {
        panic!("expected policy")
    };
    assert_eq!(created.body_updated_at, policy.body_updated_at);
    let mut legacy_json: serde_json::Value = serde_json::from_slice(&ops[0].data).unwrap();
    legacy_json["kind"]["Create"]
        .as_object_mut()
        .unwrap()
        .remove("body_updated_at");
    let err =
        serde_json::from_value::<Operation<cid::Cid, ContentPayload>>(legacy_json).unwrap_err();
    assert!(err.to_string().contains("body_updated_at"));

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct LegacyPayload {
        data: Vec<u8>,
        access_policy: Option<AccessPolicy>,
    }
    let legacy = Node::new_genesis(
        LegacyPayload {
            data: b"base".to_vec(),
            access_policy: None,
        },
        1,
        ContentMetadata::default(),
    );
    assert!(
        Node::<ContentPayload, ContentMetadata>::from_bytes(&legacy.to_bytes().unwrap()).is_err()
    );
}
