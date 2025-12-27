//! DHT placement utilities.
//!
//! This module contains infrastructure-level utilities for DHT key computation
//! and placement proofs. These are infrastructure concerns as they deal with
//! the specifics of how content is placed in the distributed hash table.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhtPlacementProof {
    pub closest_peers: Vec<String>,
    pub capacity_evidence: Vec<(String, u64)>, // (peer_id, reported_capacity)
}

/// DHT に投入するキー（Kademlia 検索キー）の決定論的生成（最小版）
/// - content_id から SHA-256 を計算し、32バイトを返す
pub fn compute_dht_key(content_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(content_id.as_bytes());
    let out = hasher.finalize();
    out[..32].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_dht_key_is_deterministic() {
        let k1 = compute_dht_key("cid-abc");
        let k2 = compute_dht_key("cid-abc");
        assert_eq!(k1, k2);
    }

    #[test]
    fn compute_dht_key_changes_with_content() {
        let a = compute_dht_key("cid-abc");
        let b = compute_dht_key("cid-def");
        assert_ne!(a, b);
    }
}
