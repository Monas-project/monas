//! Client-side store of the last version CID observed per (remote) content id,
//! backing the read monotonicity check (component B of
//! `docs/design/read-response-integrity.md`).
//!
//! A client records the newest CID-verified version it has accepted for each
//! content. On a later "latest" read it walks the returned node's verified
//! parent chain and rejects the response unless the recorded version is an
//! ancestor of (or equal to) the returned one — a regression means a relay is
//! serving a stale or rolled-back "latest".
//!
//! Keys are the *state-node* (remote) content id, because version CIDs live in
//! the state node's DAG, not the local plain-content-id space.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum LastSeenVersionStoreError {
    #[error("last-seen version store error: {0}")]
    Storage(String),
}

/// `remote_content_id -> last accepted version CID` の永続化ポート。
pub trait LastSeenVersionStore: Send + Sync {
    fn load(&self, remote_content_id: &str) -> Result<Option<String>, LastSeenVersionStoreError>;
    fn save(
        &self,
        remote_content_id: &str,
        version_cid: &str,
    ) -> Result<(), LastSeenVersionStoreError>;
}

/// プロセス内 `HashMap` 実装。テスト・開発用（再起動で揮発 = 毎回 TOFU に戻る）。
#[derive(Clone, Default)]
pub struct InMemoryLastSeenVersionStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl LastSeenVersionStore for InMemoryLastSeenVersionStore {
    fn load(&self, remote_content_id: &str) -> Result<Option<String>, LastSeenVersionStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))?;
        Ok(guard.get(remote_content_id).cloned())
    }

    fn save(
        &self,
        remote_content_id: &str,
        version_cid: &str,
    ) -> Result<(), LastSeenVersionStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))?;
        guard.insert(remote_content_id.to_string(), version_cid.to_string());
        Ok(())
    }
}

/// sled 実装。キーは `"last_seen:{remote_content_id}"`。
/// CEK / share / pubkey ストアと同じ `sled::Db` を共有できる
/// （プレフィックスでキー空間が分離される）。
pub struct SledLastSeenVersionStore {
    db: sled::Db,
}

impl SledLastSeenVersionStore {
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
    }

    fn sled_key(remote_content_id: &str) -> String {
        format!("last_seen:{remote_content_id}")
    }
}

impl LastSeenVersionStore for SledLastSeenVersionStore {
    fn load(&self, remote_content_id: &str) -> Result<Option<String>, LastSeenVersionStoreError> {
        let opt = self
            .db
            .get(Self::sled_key(remote_content_id))
            .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))?;
        opt.map(|ivec| {
            String::from_utf8(ivec.to_vec())
                .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))
        })
        .transpose()
    }

    fn save(
        &self,
        remote_content_id: &str,
        version_cid: &str,
    ) -> Result<(), LastSeenVersionStoreError> {
        self.db
            .insert(Self::sled_key(remote_content_id), version_cid.as_bytes())
            .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| LastSeenVersionStoreError::Storage(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(store: &dyn LastSeenVersionStore) {
        assert!(store.load("content-a").unwrap().is_none());

        store.save("content-a", "cid-v1").unwrap();
        assert_eq!(store.load("content-a").unwrap().as_deref(), Some("cid-v1"));

        // 上書き（版が進んだら更新される）
        store.save("content-a", "cid-v2").unwrap();
        assert_eq!(store.load("content-a").unwrap().as_deref(), Some("cid-v2"));

        // 別 content には影響しない
        assert!(store.load("content-b").unwrap().is_none());
    }

    #[test]
    fn in_memory_roundtrip() {
        roundtrip(&InMemoryLastSeenVersionStore::default());
    }

    #[test]
    fn sled_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        roundtrip(&SledLastSeenVersionStore::with_db(db));
    }
}
