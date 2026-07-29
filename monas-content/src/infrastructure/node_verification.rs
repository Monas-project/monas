//! Verification of relay-read responses that carry a whole crsl-lib `Node`
//! (CBOR), rather than raw payload bytes.
//!
//! The state node returns the serialized `Node` for reads so a client can
//! recompute its CID and confirm the response was not tampered with — the CID
//! is the SHA-256 of the exact CBOR bytes, so a matching CID proves the bytes
//! (payload + parents + genesis + timestamp + metadata) are authentic. No
//! signature is needed for this check. See
//! `docs/design.md` §10「read応答の完全性検証」.
//!
//! This mirrors crsl-lib's `Node::content_id()`:
//! `CIDv1(codec=RAW=0x55, multihash=SHA2-256(sha256(serde_cbor(node))))`.
//! The `cid` / `multihash` / `serde_cbor` crate versions are pinned to match
//! crsl-lib so the recomputed CID string is byte-identical.

use cid::Cid;
use multihash::Multihash;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// multicodec code for SHA2-256 (multihash).
const SHA2_256_CODE: u64 = 0x12;
/// multicodec code for RAW (CIDv1 codec), matching crsl-lib.
const RAW_CODE: u64 = 0x55;

#[derive(Debug, thiserror::Error)]
pub enum NodeVerificationError {
    #[error("failed to decode node CBOR: {0}")]
    Decode(String),
    #[error("failed to compute node CID: {0}")]
    Cid(String),
    #[error("node CID mismatch: expected {expected}, recomputed {actual} (tampered response)")]
    CidMismatch { expected: String, actual: String },
}

/// A relay-read `Node` decoded enough to (a) extract the ciphertext payload and
/// (b) expose the parent version CIDs (part of the node, exposed for callers
/// that need the DAG shape).
///
/// Only the fields the client needs are decoded; the CID is recomputed from the
/// raw bytes (not from this struct) so decoding never has to round-trip
/// byte-identically.
#[derive(Debug)]
pub struct VerifiedNode {
    /// The ciphertext stored in the node payload (`payload.data`).
    pub ciphertext: Vec<u8>,
    /// Parent version CIDs (`parents`), as strings.
    pub parents: Vec<String>,
}

/// Minimal mirror of crsl-lib's `Node` for extraction. `payload` is decoded as
/// a CBOR value and its `data` field pulled out, so we don't depend on the
/// exact `ContentPayload` type. `parents` are decoded as CIDs.
#[derive(Deserialize)]
struct NodeMirror {
    payload: serde_cbor::Value,
    #[serde(default)]
    parents: Vec<Cid>,
}

/// Recompute the CID of `node_bytes` (the exact CBOR of a crsl-lib `Node`) and
/// return it as a string, matching `Cid::to_string()` in crsl-lib.
pub fn recompute_node_cid(node_bytes: &[u8]) -> Result<String, NodeVerificationError> {
    let digest = Sha256::digest(node_bytes);
    let mh = Multihash::<64>::wrap(SHA2_256_CODE, &digest)
        .map_err(|e| NodeVerificationError::Cid(e.to_string()))?;
    Ok(Cid::new_v1(RAW_CODE, mh).to_string())
}

/// Verify that `node_bytes` hashes to `expected_version_cid`, then extract the
/// ciphertext and parents. Returns an error (rejecting the response) on any
/// mismatch — this is what stops a relay peer from returning fabricated data.
pub fn verify_and_extract(
    node_bytes: &[u8],
    expected_version_cid: &str,
) -> Result<VerifiedNode, NodeVerificationError> {
    let actual = recompute_node_cid(node_bytes)?;
    if actual != expected_version_cid {
        return Err(NodeVerificationError::CidMismatch {
            expected: expected_version_cid.to_string(),
            actual,
        });
    }

    let mirror: NodeMirror = serde_cbor::from_slice(node_bytes)
        .map_err(|e| NodeVerificationError::Decode(e.to_string()))?;

    let ciphertext = extract_payload_data(&mirror.payload)?;
    let parents = mirror.parents.iter().map(|c| c.to_string()).collect();

    Ok(VerifiedNode {
        ciphertext,
        parents,
    })
}

/// Pull `data: Vec<u8>` out of the decoded payload value. The payload is
/// `ContentPayload { data, access_policy }`, CBOR-encoded as a map.
fn extract_payload_data(payload: &serde_cbor::Value) -> Result<Vec<u8>, NodeVerificationError> {
    use serde_cbor::Value;
    match payload {
        Value::Map(map) => {
            let key = Value::Text("data".to_string());
            match map.get(&key) {
                Some(Value::Bytes(b)) => Ok(b.clone()),
                // CBOR arrays of ints can also represent byte sequences
                Some(Value::Array(arr)) => arr
                    .iter()
                    .map(|v| match v {
                        Value::Integer(i) if *i >= 0 && *i <= 255 => Ok(*i as u8),
                        _ => Err(NodeVerificationError::Decode(
                            "payload.data array contains a non-byte element".to_string(),
                        )),
                    })
                    .collect(),
                Some(_) => Err(NodeVerificationError::Decode(
                    "payload.data is not a byte string".to_string(),
                )),
                None => Err(NodeVerificationError::Decode(
                    "payload has no `data` field".to_string(),
                )),
            }
        }
        _ => Err(NodeVerificationError::Decode(
            "payload is not a CBOR map".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    // A local mirror that serializes to the SAME CBOR shape as crsl-lib's
    // Node<ContentPayload, ContentMetadata>, so we can produce test vectors
    // without depending on crsl-lib. Field order/names must match.
    #[derive(Serialize)]
    struct TestPayload {
        data: Vec<u8>,
        access_policy: Option<()>,
    }
    #[derive(Serialize)]
    struct TestMetadata {
        policy_type: Option<String>,
    }
    #[derive(Serialize)]
    struct TestNode {
        payload: TestPayload,
        parents: Vec<Cid>,
        genesis: Option<Cid>,
        timestamp: u64,
        metadata: TestMetadata,
    }

    fn make_node(data: Vec<u8>, parents: Vec<Cid>) -> Vec<u8> {
        let node = TestNode {
            payload: TestPayload {
                data,
                access_policy: None,
            },
            parents,
            genesis: None,
            timestamp: 0,
            metadata: TestMetadata { policy_type: None },
        };
        serde_cbor::to_vec(&node).unwrap()
    }

    #[test]
    fn verify_accepts_matching_cid_and_extracts_data() {
        let bytes = make_node(b"ciphertext-bytes".to_vec(), vec![]);
        let cid = recompute_node_cid(&bytes).unwrap();

        let verified = verify_and_extract(&bytes, &cid).expect("should verify");
        assert_eq!(verified.ciphertext, b"ciphertext-bytes");
        assert!(verified.parents.is_empty());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let bytes = make_node(b"original".to_vec(), vec![]);
        let cid = recompute_node_cid(&bytes).unwrap();

        // Tamper: a different node claims the original's CID.
        let tampered = make_node(b"ATTACKER".to_vec(), vec![]);
        let err = verify_and_extract(&tampered, &cid).unwrap_err();
        assert!(matches!(err, NodeVerificationError::CidMismatch { .. }));
    }

    #[test]
    fn verify_exposes_parents() {
        let parent = recompute_node_cid(&make_node(b"v1".to_vec(), vec![])).unwrap();
        let parent_cid: Cid = parent.parse().unwrap();
        let bytes = make_node(b"v2".to_vec(), vec![parent_cid]);
        let cid = recompute_node_cid(&bytes).unwrap();

        let verified = verify_and_extract(&bytes, &cid).unwrap();
        assert_eq!(verified.parents, vec![parent]);
    }

    #[test]
    fn recompute_is_deterministic() {
        let bytes = make_node(b"x".to_vec(), vec![]);
        assert_eq!(
            recompute_node_cid(&bytes).unwrap(),
            recompute_node_cid(&bytes).unwrap()
        );
    }

    /// **Parity test** against the real crsl-lib. Builds an actual crsl-lib
    /// `Node`, serializes it with `to_bytes()`, and confirms our from-CBOR CID
    /// recompute equals `Node::content_id()` exactly. This is what guarantees a
    /// client's tamper check matches the version CID the state node advertises.
    #[test]
    fn recompute_matches_crsl_lib_node_cid() {
        use crsl_lib::dasl::node::Node;
        use std::collections::BTreeMap;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Payload {
            data: Vec<u8>,
            access_policy: Option<()>,
        }

        // genesis node
        let payload = Payload {
            data: b"real ciphertext".to_vec(),
            access_policy: None,
        };
        let node: Node<Payload, BTreeMap<String, String>> =
            Node::new_genesis(payload, 12345, BTreeMap::new());

        let crsl_cid = node.content_id().unwrap().to_string();
        let bytes = node.to_bytes().unwrap();

        // Our recompute must match crsl-lib's CID byte-for-byte.
        assert_eq!(recompute_node_cid(&bytes).unwrap(), crsl_cid);

        // And verify_and_extract must accept it and pull out the ciphertext.
        let verified = verify_and_extract(&bytes, &crsl_cid).unwrap();
        assert_eq!(verified.ciphertext, b"real ciphertext");
        assert!(verified.parents.is_empty());
    }

    /// Parity for a child node (has parents + genesis), covering the CBOR
    /// encoding of `Cid` fields.
    #[test]
    fn recompute_matches_crsl_lib_child_node() {
        use crsl_lib::dasl::node::Node;
        use std::collections::BTreeMap;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Payload {
            data: Vec<u8>,
            access_policy: Option<()>,
        }

        let genesis: Node<Payload, BTreeMap<String, String>> = Node::new_genesis(
            Payload {
                data: b"v1".to_vec(),
                access_policy: None,
            },
            1,
            BTreeMap::new(),
        );
        let genesis_cid = genesis.content_id().unwrap();

        let child: Node<Payload, BTreeMap<String, String>> = Node::new_child(
            Payload {
                data: b"v2".to_vec(),
                access_policy: None,
            },
            vec![genesis_cid],
            genesis_cid,
            2,
            BTreeMap::new(),
        );
        let child_cid = child.content_id().unwrap().to_string();
        let bytes = child.to_bytes().unwrap();

        assert_eq!(recompute_node_cid(&bytes).unwrap(), child_cid);

        let verified = verify_and_extract(&bytes, &child_cid).unwrap();
        assert_eq!(verified.ciphertext, b"v2");
        assert_eq!(verified.parents, vec![genesis_cid.to_string()]);
    }
}
