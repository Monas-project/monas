//! Encoded size of content on the way between members.
//!
//! Serde's default for `Vec<u8>` is one number per byte: ~3.6 JSON chars or
//! ~2 CBOR bytes per ciphertext byte. Operations nested that twice (number
//! arrays inside JSON, the JSON again as a number array inside the CBOR
//! request), so a 16 KB file became a ~237 KB push and anything past ~17 KB
//! failed to replicate. These tests pin the compact encodings.

use monas_state_node::{
    infrastructure::{
        crdt_repository::CrslCrdtRepository,
        network::protocol::{ContentRequest, ContentResponse},
    },
    port::content_repository::ContentRepository,
};
use tempfile::tempdir;

const BODY: usize = 64 * 1024;

fn random_body() -> Vec<u8> {
    // Ciphertext-like: every byte value, no structure.
    (0..BODY)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

#[tokio::test]
async fn an_operation_carries_its_ciphertext_as_base64() {
    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let body = random_body();
    let genesis = repo
        .create_content(&body, "owner", None)
        .await
        .unwrap()
        .genesis_cid;

    let ops = repo.get_operations(&genesis, None).await.unwrap();
    let op = &ops[0].data;
    // base64 is 4/3; leave room for the operation envelope only.
    assert!(
        op.len() < BODY * 4 / 3 + 2048,
        "operation is {} bytes for a {BODY}-byte body",
        op.len()
    );

    // And it still round-trips into a fresh replica byte for byte.
    let other_dir = tempdir().unwrap();
    let other = CrslCrdtRepository::open(other_dir.path()).unwrap();
    other.apply_operations(&ops).await.unwrap();
    assert_eq!(other.get_latest(&genesis).await.unwrap().unwrap(), body);
}

#[tokio::test]
async fn a_version_node_stores_its_ciphertext_as_a_byte_string() {
    let dir = tempdir().unwrap();
    let repo = CrslCrdtRepository::open(dir.path()).unwrap();
    let genesis = repo
        .create_content(&random_body(), "owner", None)
        .await
        .unwrap()
        .genesis_cid;
    let (node, _) = repo
        .get_latest_node_bytes_with_version(&genesis)
        .await
        .unwrap()
        .unwrap();
    assert!(
        node.len() < BODY + 2048,
        "node is {} bytes for a {BODY}-byte body",
        node.len()
    );
}

#[test]
fn a_push_sends_operations_as_byte_strings() {
    let op = random_body();
    let request = ContentRequest::PushOperations {
        genesis_cid: "g".into(),
        operations: vec![op.clone(), op.clone()],
        bootstrap: None,
    };
    let wire = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
    assert!(
        wire.len() < 2 * BODY + 256,
        "push is {} bytes for two {BODY}-byte operations",
        wire.len()
    );
    let back: ContentRequest = cbor4ii::serde::from_slice(&wire).unwrap();
    let ContentRequest::PushOperations { operations, .. } = back else {
        panic!("decoded into another variant")
    };
    assert_eq!(operations, vec![op.clone(), op.clone()]);

    let response = ContentResponse::OperationsData {
        genesis_cid: "g".into(),
        operations: vec![op.clone()],
    };
    let wire = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
    assert!(wire.len() < BODY + 256);
    let back: ContentResponse = cbor4ii::serde::from_slice(&wire).unwrap();
    let ContentResponse::OperationsData { operations, .. } = back else {
        panic!("decoded into another variant")
    };
    assert_eq!(operations, vec![op]);
}
