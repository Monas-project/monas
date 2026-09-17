use cid::Cid;
use crsl_lib::{
    convergence::metadata::ContentMetadata,
    crdt::operation::{Operation, OperationType},
    dasl::node::Node,
};
use monas_state_node::{
    infrastructure::crdt_repository::{ContentPayload, CrslCrdtRepository},
    port::content_repository::{ContentRepository, SerializedOperation},
};
use tempfile::tempdir;

// Check the actual DAG CID and bytes, not just payload convergence: a wrong
// timestamp can appear to converge while silently creating a different node.
async fn verify_export(
    repo: &CrslCrdtRepository,
    genesis: &str,
    ops: &[SerializedOperation],
) -> Vec<String> {
    let mut cids = Vec::new();
    for wire in ops {
        let op: Operation<Cid, ContentPayload> = serde_json::from_slice(&wire.data).unwrap();
        let node = match op.kind {
            OperationType::Create(payload) => {
                Node::new_genesis(payload, wire.node_timestamp, ContentMetadata::default())
            }
            OperationType::Update(payload) | OperationType::Merge(payload) => {
                let bytes = repo
                    .get_version_node_bytes(genesis, &op.parents[0].to_string())
                    .await
                    .unwrap()
                    .unwrap();
                let parent = Node::<ContentPayload, ContentMetadata>::from_bytes(&bytes).unwrap();
                Node::new_child(
                    payload,
                    op.parents,
                    op.genesis,
                    wire.node_timestamp,
                    parent.metadata,
                )
            }
            OperationType::Delete => panic!("fixture does not delete"),
        };
        let cid = node.content_id().unwrap().to_string();
        assert_eq!(
            repo.get_version_node_bytes(genesis, &cid).await.unwrap(),
            Some(node.to_bytes().unwrap())
        );
        cids.push(cid);
    }
    cids
}

#[tokio::test]
async fn ambiguous_unstamped_nodes_fail_closed() {
    use crsl_lib::{
        graph::storage::{LeveldbNodeStorage, NodeStorage},
        storage::SharedLeveldb,
    };

    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let genesis = repo
        .create_content(b"base", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    let tip = repo
        .update_content(&genesis, b"updated", "a", None)
        .await
        .unwrap()
        .version_cid;
    let bytes = repo
        .get_version_node_bytes(&genesis, &tip)
        .await
        .unwrap()
        .unwrap();
    drop(repo);

    // Simulate a damaged store with an extra indistinguishable local node.
    // Neither operation time nor storage ordering justifies choosing a stamp.
    {
        let db = SharedLeveldb::open(dir.path().join("crdt_db")).unwrap();
        let store = LeveldbNodeStorage::<ContentPayload, ContentMetadata>::new(db);
        let mut duplicate = Node::<ContentPayload, ContentMetadata>::from_bytes(&bytes).unwrap();
        duplicate.timestamp += 1;
        store.put(&duplicate).unwrap();
    }
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let err = repo.get_operations(&genesis, None).await.unwrap_err();
    assert!(err.to_string().contains("2 candidates"), "{err}");
}

#[tokio::test]
async fn since_a_branch_tip_exports_siblings_and_merge_but_not_ancestors() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let a = CrslCrdtRepository::open(a_dir.path()).unwrap();
    let b = CrslCrdtRepository::open(b_dir.path()).unwrap();
    let genesis = a
        .create_content(b"base", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    b.apply_operations(&a.get_operations(&genesis, None).await.unwrap())
        .await
        .unwrap();
    let a_tip = a
        .update_content(&genesis, b"a", "a", None)
        .await
        .unwrap()
        .version_cid;
    let b_tip = b
        .update_content(&genesis, b"b", "b", None)
        .await
        .unwrap()
        .version_cid;
    a.apply_operations(&b.get_operations(&genesis, None).await.unwrap())
        .await
        .unwrap();

    // Even before a read triggers auto-merge, the sibling must be exported.
    let tail = a.get_operations(&genesis, Some(&a_tip)).await.unwrap();
    assert_eq!(
        verify_export(&a, &genesis, &tail).await,
        vec![b_tip.clone()]
    );
    let (_, merge) = a.get_latest_with_version(&genesis).await.unwrap().unwrap();
    let tail = a.get_operations(&genesis, Some(&b_tip)).await.unwrap();
    assert_eq!(
        verify_export(&a, &genesis, &tail).await,
        vec![a_tip, merge.clone()]
    );
    assert_eq!(b.apply_operations(&tail).await.unwrap(), tail.len());
    assert_eq!(
        b.get_latest_with_version(&genesis)
            .await
            .unwrap()
            .unwrap()
            .1,
        merge
    );
    assert!(a
        .get_operations(&genesis, Some(&merge))
        .await
        .unwrap()
        .is_empty());

    let unrelated = a
        .create_content(b"unrelated", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    let full = a.get_operations(&genesis, None).await.unwrap();
    let fallback = a.get_operations(&genesis, Some(&unrelated)).await.unwrap();
    assert_eq!(
        verify_export(&a, &genesis, &fallback).await,
        verify_export(&a, &genesis, &full).await
    );
    assert_eq!(full.len(), 4);
}

#[tokio::test]
async fn forked_auto_merges_can_be_exported_and_replicated_repeatedly() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let a = CrslCrdtRepository::open(a_dir.path()).unwrap();
    let b = CrslCrdtRepository::open(b_dir.path()).unwrap();
    let genesis = a
        .create_content(b"base", "a", None)
        .await
        .unwrap()
        .genesis_cid;
    let base = a.get_operations(&genesis, None).await.unwrap();
    assert_eq!(b.apply_operations(&base).await.unwrap(), base.len());
    a.update_content(&genesis, b"a", "a", None).await.unwrap();
    b.update_content(&genesis, b"b", "b", None).await.unwrap();

    // Snapshot both exports before delivery, so both replicas independently
    // create an auto-merge with the same parents and payload but distinct CIDs.
    for _ in 0..3 {
        let a_ops = a.get_operations(&genesis, None).await.unwrap();
        let b_ops = b.get_operations(&genesis, None).await.unwrap();
        let a_cids = verify_export(&a, &genesis, &a_ops).await;
        let b_cids = verify_export(&b, &genesis, &b_ops).await;
        assert_eq!(b.apply_operations(&a_ops).await.unwrap(), a_ops.len());
        assert_eq!(a.apply_operations(&b_ops).await.unwrap(), b_ops.len());
        for cid in a_cids.iter().chain(&b_cids) {
            assert_eq!(
                a.get_version_node_bytes(&genesis, cid).await.unwrap(),
                b.get_version_node_bytes(&genesis, cid).await.unwrap()
            );
        }
        assert_eq!(a.get_latest(&genesis).await.unwrap(), Some(b"b".to_vec()));
        assert_eq!(b.get_latest(&genesis).await.unwrap(), Some(b"b".to_vec()));
    }

    // A fresh third replica must be able to replay the complete forked DAG in
    // one export, including merge nodes whose operation timestamp differs.
    let ops = a.get_operations(&genesis, None).await.unwrap();
    assert!(ops.iter().any(|wire| {
        let op: Operation<Cid, ContentPayload> = serde_json::from_slice(&wire.data).unwrap();
        matches!(op.kind, OperationType::Merge(_)) && op.timestamp != wire.node_timestamp
    }));
    let c_dir = tempdir().unwrap();
    let c = CrslCrdtRepository::open(c_dir.path()).unwrap();
    assert_eq!(c.apply_operations(&ops).await.unwrap(), ops.len());
    assert_eq!(c.apply_operations(&ops).await.unwrap(), ops.len());
    for cid in verify_export(&a, &genesis, &ops).await {
        assert_eq!(
            a.get_version_node_bytes(&genesis, &cid).await.unwrap(),
            c.get_version_node_bytes(&genesis, &cid).await.unwrap()
        );
    }
    assert_eq!(
        a.get_latest_with_version(&genesis).await.unwrap(),
        c.get_latest_with_version(&genesis).await.unwrap()
    );
}
