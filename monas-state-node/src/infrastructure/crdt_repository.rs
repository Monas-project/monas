//! CRDT Repository implementation using crsl-lib.
//!
//! This module provides an implementation of ContentRepository
//! using crsl-lib for CRDT-based content versioning.

use crate::port::content_crdt::{CommitResult, ContentRepository, SerializedOperation};

use anyhow::{Context, Result};
use async_trait::async_trait;
use cid::Cid;
use crsl_lib::convergence::metadata::ContentMetadata;
use crsl_lib::crdt::crdt_state::CrdtState;
use crsl_lib::crdt::operation::{Operation, OperationType};
use crsl_lib::crdt::storage::LeveldbStorage;
use crsl_lib::graph::dag::DagGraph;
use crsl_lib::graph::storage::{LeveldbNodeStorage, NodeStorage};
use crsl_lib::repo::Repo;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// Payload type for content storage.
/// Using Vec<u8> for raw binary content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentPayload(pub Vec<u8>);

/// Type aliases for crsl-lib types.
type OpStore = LeveldbStorage<Cid, ContentPayload>;
type NodeStore = LeveldbNodeStorage<ContentPayload, ContentMetadata>;
type ContentRepo = Repo<OpStore, NodeStore, ContentPayload>;

/// CRDT Repository implementation using crsl-lib.
///
/// This implementation uses crsl-lib for:
/// - CRDT state management with automatic conflict resolution (LWW)
/// - DAG-based version history
/// - LevelDB persistence
pub struct CrslCrdtRepository {
    /// The crsl-lib repository wrapped in a Mutex for thread safety.
    /// Repo methods require &mut self, so we need interior mutability.
    repo: Mutex<ContentRepo>,
}

impl CrslCrdtRepository {
    /// Create a new CRDT repository with storage at the given path.
    pub fn open<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base = base_path.as_ref();
        std::fs::create_dir_all(base).context("Failed to create CRDT storage directory")?;

        let op_storage = LeveldbStorage::open(base.join("operations"))
            .map_err(|e| anyhow::anyhow!("Failed to open operation storage: {}", e))?;
        let node_storage = LeveldbNodeStorage::open(base.join("dag_nodes"));

        let state = CrdtState::new(op_storage);
        let dag = DagGraph::new(node_storage);
        let repo = Repo::new(state, dag);

        Ok(Self {
            repo: Mutex::new(repo),
        })
    }

    /// Generate a placeholder CID from content data.
    /// This is used as a seed for Create operations.
    fn generate_placeholder_cid(data: &[u8]) -> Cid {
        let mh = Code::Sha2_256.digest(data);
        Cid::new_v1(0x55, mh) // 0x55 = raw codec
    }

    /// Parse a CID from string.
    fn parse_cid(cid_str: &str) -> Result<Cid> {
        cid_str
            .parse()
            .with_context(|| format!("Invalid CID: {}", cid_str))
    }
}

#[async_trait]
impl ContentRepository for CrslCrdtRepository {
    async fn create_content(&self, data: &[u8], author: &str) -> Result<CommitResult> {
        let placeholder = Self::generate_placeholder_cid(data);
        let payload = ContentPayload(data.to_vec());

        let op = Operation::new(placeholder, OperationType::Create(payload), author.to_string());

        let genesis_cid = {
            let mut repo = self
                .repo
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            repo.commit_operation(op)
                .map_err(|e| anyhow::anyhow!("Failed to commit create operation: {}", e))?
        };

        Ok(CommitResult {
            genesis_cid: genesis_cid.to_string(),
            version_cid: genesis_cid.to_string(),
            is_new: true,
        })
    }

    async fn update_content(
        &self,
        genesis_cid: &str,
        data: &[u8],
        author: &str,
    ) -> Result<CommitResult> {
        let genesis = Self::parse_cid(genesis_cid)?;
        let payload = ContentPayload(data.to_vec());

        // Create update operation - parents will be auto-filled by crsl-lib
        let op = Operation::new(genesis, OperationType::Update(payload), author.to_string());

        let version_cid = {
            let mut repo = self
                .repo
                .lock()
                .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            repo.commit_operation(op)
                .map_err(|e| anyhow::anyhow!("Failed to commit update operation: {}", e))?
        };

        Ok(CommitResult {
            genesis_cid: genesis_cid.to_string(),
            version_cid: version_cid.to_string(),
            is_new: false,
        })
    }

    async fn get_latest(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        // Get the latest version CID
        match repo.latest(&genesis) {
            Some(latest_cid) => {
                // Get the node to retrieve payload
                match repo.dag.get_node(&latest_cid) {
                    Ok(Some(node)) => Ok(Some(node.payload().0.clone())),
                    Ok(None) => Ok(None),
                    Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_version(&self, version_cid: &str) -> Result<Option<Vec<u8>>> {
        let cid = Self::parse_cid(version_cid)?;

        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        match repo.dag.get_node(&cid) {
            Ok(Some(node)) => Ok(Some(node.payload().0.clone())),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
        }
    }

    async fn get_history(&self, genesis_cid: &str) -> Result<Vec<String>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        let path = repo
            .linear_history(&genesis)
            .map_err(|e| anyhow::anyhow!("Failed to get history: {}", e))?;

        Ok(path.iter().map(|cid| cid.to_string()).collect())
    }

    async fn get_operations(
        &self,
        genesis_cid: &str,
        _since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        let indexed_ops = repo
            .get_operations_with_index(&genesis)
            .map_err(|e| anyhow::anyhow!("Failed to get operations: {}", e))?;

        let mut operations = Vec::new();
        for (_, op) in indexed_ops {
            // Serialize the operation using serde_json for network transfer
            let serialized = serde_json::to_vec(&op)
                .map_err(|e| anyhow::anyhow!("Failed to serialize operation: {}", e))?;

            operations.push(SerializedOperation {
                data: serialized,
                genesis_cid: genesis_cid.to_string(),
                author: op.author.clone(),
                timestamp: op.timestamp,
            });
        }

        Ok(operations)
    }

    async fn apply_operations(&self, operations: &[SerializedOperation]) -> Result<usize> {
        let mut applied = 0;

        let mut repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        for serialized_op in operations {
            // Deserialize the operation
            let op: Operation<Cid, ContentPayload> = serde_json::from_slice(&serialized_op.data)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize operation: {}", e))?;

            // Apply the operation
            match repo.commit_operation(op) {
                Ok(_) => applied += 1,
                Err(e) => {
                    // Log but continue - operation might be duplicate or conflict
                    tracing::warn!("Failed to apply operation: {}", e);
                }
            }
        }

        Ok(applied)
    }

    async fn exists(&self, genesis_cid: &str) -> Result<bool> {
        let genesis = match Self::parse_cid(genesis_cid) {
            Ok(cid) => cid,
            Err(_) => return Ok(false),
        };

        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(repo.latest(&genesis).is_some())
    }

    async fn list_contents(&self) -> Result<Vec<String>> {
        let repo = self
            .repo
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        // Get all nodes and collect unique genesis CIDs
        let node_map = repo
            .dag
            .storage
            .get_node_map()
            .map_err(|e| anyhow::anyhow!("Failed to get node map: {}", e))?;

        let mut genesis_cids = std::collections::HashSet::new();
        for cid in node_map.keys() {
            // Try to get the genesis for each node
            if let Ok(genesis) = repo.get_genesis(cid) {
                genesis_cids.insert(genesis.to_string());
            }
        }

        Ok(genesis_cids.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_create_and_get_content() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Hello, CRDT!";
        let result = repo.create_content(data, "test-author").await.unwrap();

        assert!(result.is_new);
        assert!(!result.genesis_cid.is_empty());

        let retrieved = repo.get_latest(&result.genesis_cid).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_update_content() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let initial_data = b"Initial content";
        let result = repo.create_content(initial_data, "author1").await.unwrap();

        let updated_data = b"Updated content";
        let update_result = repo
            .update_content(&result.genesis_cid, updated_data, "author1")
            .await
            .unwrap();

        assert!(!update_result.is_new);
        assert_eq!(update_result.genesis_cid, result.genesis_cid);

        let retrieved = repo.get_latest(&result.genesis_cid).await.unwrap();
        assert_eq!(retrieved, Some(updated_data.to_vec()));
    }

    #[tokio::test]
    async fn test_content_exists() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Test content";
        let result = repo.create_content(data, "author").await.unwrap();

        assert!(repo.exists(&result.genesis_cid).await.unwrap());

        // Non-existent content should return false
        assert!(!repo
            .exists("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_get_history() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data1 = b"Version 1";
        let result = repo.create_content(data1, "author").await.unwrap();

        // Small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let data2 = b"Version 2";
        repo.update_content(&result.genesis_cid, data2, "author")
            .await
            .unwrap();

        let history = repo.get_history(&result.genesis_cid).await.unwrap();
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn test_get_version() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Test content";
        let result = repo.create_content(data, "author").await.unwrap();

        let retrieved = repo.get_version(&result.version_cid).await.unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_list_contents() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data1 = b"Content 1";
        let result1 = repo.create_content(data1, "author").await.unwrap();

        let data2 = b"Content 2";
        let result2 = repo.create_content(data2, "author").await.unwrap();

        let contents = repo.list_contents().await.unwrap();
        assert!(contents.contains(&result1.genesis_cid));
        assert!(contents.contains(&result2.genesis_cid));
    }

    #[tokio::test]
    async fn test_get_operations() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Test content";
        let result = repo.create_content(data, "author").await.unwrap();

        let operations = repo.get_operations(&result.genesis_cid, None).await.unwrap();
        assert!(!operations.is_empty());
        assert_eq!(operations[0].genesis_cid, result.genesis_cid);
    }
}
