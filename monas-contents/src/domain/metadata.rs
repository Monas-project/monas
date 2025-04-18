use crate::domain::state_nodes::StateNodes;
use chrono::{DateTime, Utc};
use crate::infrastructure::storage::StorageError;
use crate::domain::contents::ContentsError;

#[derive(Debug, Clone)]
pub struct Metadata {
    name: String,
    version: u32,
    path: String,
    nodes: StateNodes,
    hash: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Metadata {
    pub fn new(
        name: String,
        raw_contents: &[u8],
        path: String,
        nodes: StateNodes,
    ) -> Self {
        let now = Utc::now();
        Self {
            name,
            version: 1,
            path,
            nodes,
            hash: Self::calculate_hash(raw_contents),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn increment_version(&mut self) {
        self.version += 1;
        self.updated_at = Utc::now();
    }

    fn calculate_hash(raw_contents: &[u8]) -> String {
        // ハッシュ計算のダミー実装 (sha2 クレートを使う例)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw_contents);
        hex::encode(hasher.finalize())
    }

    // ゲッター
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn nodes(&self) -> &StateNodes {
        &self.nodes
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}
