//! CRDT Repository implementation using crsl-lib.
//!
//! This module provides an implementation of ContentRepository
//! using crsl-lib for CRDT-based content versioning.

use crate::domain::access_policy::AccessPolicy;
use crate::infrastructure::merge_policy::MonasMergePolicy;
use crate::port::content_repository::{
    CommitResult, ContentRepository, PreparedCreate, SerializedOperation,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use cid::Cid;
use crsl_lib::convergence::metadata::ContentMetadata;
use crsl_lib::crdt::crdt_state::CrdtState;
use crsl_lib::crdt::operation::{Operation, OperationType};
use crsl_lib::crdt::storage::LeveldbStorage;
use crsl_lib::crdt::timestamp::next_monotonic_timestamp;
use crsl_lib::graph::dag::DagGraph;
use crsl_lib::graph::storage::{LeveldbNodeStorage, NodeStorage};
use crsl_lib::repo::Repo;
use crsl_lib::storage::SharedLeveldb;
use multihash_codetable::{Code, MultihashDigest};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Payload type for content storage.
/// Contains raw binary content data and an optional access policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentPayload {
    pub data: Vec<u8>,
    /// Ordering of the last explicit body write, not of the containing node.
    /// Policy-only updates and merges MUST copy this together with `data`.
    /// Required on the wire: silently defaulting old data would invent a write
    /// order. Deploy this format to all members together with fresh stores.
    pub body_updated_at: u64,
    pub access_policy: Option<AccessPolicy>,
}

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

        // Use a single shared LevelDB instance for both operation and node storage
        // This is required for transactions to work correctly
        let shared_db = SharedLeveldb::open(base.join("crdt_db"))
            .map_err(|e| anyhow::anyhow!("Failed to open shared LevelDB: {}", e))?;

        let op_storage = LeveldbStorage::new(shared_db.clone());
        let node_storage = LeveldbNodeStorage::new(shared_db);

        let state = CrdtState::new(op_storage);
        let dag = DagGraph::new(node_storage);
        // Field-wise convergence: body is LWW, the access policy's cutoff is
        // a max. crsl-lib's default LWW over the whole payload lets a
        // concurrent write erase a revoke (see merge_policy.rs).
        let repo = Repo::new(state, dag).with_merge_policy(Box::new(MonasMergePolicy));

        Ok(Self {
            repo: Mutex::new(repo),
        })
    }

    /// The head of a content, after converging any concurrent heads.
    ///
    /// Every read of "the current version" goes through here. `Repo::latest`
    /// alone picks one concurrent head by timestamp; with a field-wise merge
    /// policy that is the wrong answer whenever the branches differ in
    /// different fields — a revoke on one, a write on the other — because
    /// the reader sees only one branch's fields. Merging first makes reads
    /// see what the policy decides, and makes a write that copies the head's
    /// policy (or a revoke that copies the head's body) start from the
    /// converged value instead of racing it.
    fn converged_head(repo: &mut ContentRepo, genesis: &Cid) -> Result<Option<Cid>> {
        repo.merge_heads(genesis)
            .map_err(|e| anyhow::anyhow!("Failed to merge concurrent heads: {}", e))
    }

    /// Check if the repository is healthy (can list contents).
    pub async fn health_check(&self) -> Result<()> {
        // A simple read operation to verify DB is responsive
        let _contents = self.list_contents().await?;
        Ok(())
    }

    /// Whether the node this operation produces is already in the DAG.
    ///
    /// The node CID is a function of the payload, parents, genesis and the
    /// stamped timestamp, so it can be recomputed from the operation alone —
    /// which is what lets a receiver tell "I already have this" apart from "I
    /// have a differently-stamped version of this". Metadata comes from the
    /// parent, mirroring how crsl-lib resolves it when committing.
    fn node_is_present(repo: &ContentRepo, op: &Operation<Cid, ContentPayload>) -> bool {
        use crsl_lib::dasl::node::Node;

        let Some(timestamp) = op.node_timestamp else {
            return false;
        };

        let node = match (&op.kind, op.parents.first()) {
            (OperationType::Create(payload), _) => {
                Node::<ContentPayload, ContentMetadata>::new_genesis(
                    payload.clone(),
                    timestamp,
                    ContentMetadata::default(),
                )
            }
            (OperationType::Update(payload), Some(parent))
            | (OperationType::Merge(payload), Some(parent)) => {
                let Ok(Some(parent_node)) = repo.dag.get_node(parent) else {
                    return false;
                };
                Node::new_child(
                    payload.clone(),
                    op.parents.clone(),
                    op.genesis,
                    timestamp,
                    parent_node.metadata().clone(),
                )
            }
            // Delete carries no payload of its own and parentless updates are
            // resolved at commit time; neither can be reconstructed here, so
            // fall back to committing and letting the DAG decide.
            _ => return false,
        };

        let Ok(cid) = node.content_id() else {
            return false;
        };
        matches!(repo.dag.get_node(&cid), Ok(Some(_)))
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
    async fn create_content(
        &self,
        data: &[u8],
        author: &str,
        access_policy: Option<AccessPolicy>,
    ) -> Result<CommitResult> {
        let placeholder = Self::generate_placeholder_cid(data);
        let payload = ContentPayload {
            data: data.to_vec(),
            body_updated_at: next_monotonic_timestamp(),
            access_policy,
        };

        let op = Operation::new(
            placeholder,
            OperationType::Create(payload),
            author.to_string(),
        );

        let genesis_cid = {
            let mut repo = self.repo.lock();
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
        access_policy: Option<AccessPolicy>,
    ) -> Result<CommitResult> {
        let genesis = Self::parse_cid(genesis_cid)?;

        // Read/derive/commit under one lock: a policy arriving between the
        // read and commit must not be overwritten by the policy we copied.
        let mut repo = self.repo.lock();
        let head = Self::converged_head(&mut repo, &genesis)?
            .ok_or_else(|| anyhow::anyhow!("Content not found: {genesis}"))?;
        let current = repo
            .dag
            .get_node(&head)?
            .ok_or_else(|| anyhow::anyhow!("Head node not found: {head}"))?;
        let current = current.payload();
        let mut policy = access_policy.or_else(|| current.access_policy.clone());
        if let (Some(policy), Some(previous)) = (&mut policy, &current.access_policy) {
            policy.raise_min_valid_issued_at(previous.min_valid_issued_at());
        }
        // Advance past an observed write even if this replica's wall clock
        // lags. Equal timestamps on independent replicas are broken by bytes
        // in MonasMergePolicy, never by storage/arrival order.
        let after_current = current
            .body_updated_at
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Body write timestamp exhausted"))?;
        let payload = ContentPayload {
            data: data.to_vec(),
            body_updated_at: next_monotonic_timestamp().max(after_current),
            access_policy: policy,
        };
        let op = Operation::new(genesis, OperationType::Update(payload), author.to_string());
        let version_cid = repo
            .commit_operation(op)
            .map_err(|e| anyhow::anyhow!("Failed to commit update operation: {}", e))?;

        Ok(CommitResult {
            genesis_cid: genesis_cid.to_string(),
            version_cid: version_cid.to_string(),
            is_new: false,
        })
    }

    async fn get_latest(&self, genesis_cid: &str) -> Result<Option<Vec<u8>>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let mut repo = self.repo.lock();

        // Get the latest version CID
        match Self::converged_head(&mut repo, &genesis)? {
            Some(latest_cid) => {
                // Get the node to retrieve payload (data part only)
                match repo.dag.get_node(&latest_cid) {
                    Ok(Some(node)) => Ok(Some(node.payload().data.clone())),
                    Ok(None) => Ok(None),
                    Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_latest_with_version(
        &self,
        genesis_cid: &str,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let mut repo = self.repo.lock();

        // Get the latest version CID
        match Self::converged_head(&mut repo, &genesis)? {
            Some(latest_cid) => {
                // Get the node to retrieve payload (data part only)
                match repo.dag.get_node(&latest_cid) {
                    Ok(Some(node)) => {
                        Ok(Some((node.payload().data.clone(), latest_cid.to_string())))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_version(&self, genesis_cid: &str, version_cid: &str) -> Result<Option<Vec<u8>>> {
        let genesis = Self::parse_cid(genesis_cid)?;
        let cid = Self::parse_cid(version_cid)?;

        let repo = self.repo.lock();

        // Scope the lookup to this content's DAG: read authorization is
        // granted per content, so serving a version from a different series
        // would be a cross-content read. Unknown nodes resolve to None.
        match repo.get_genesis(&cid) {
            Ok(g) if g == genesis => {}
            _ => return Ok(None),
        }

        match repo.dag.get_node(&cid) {
            Ok(Some(node)) => Ok(Some(node.payload().data.clone())),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
        }
    }

    async fn get_latest_node_bytes_with_version(
        &self,
        genesis_cid: &str,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let mut repo = self.repo.lock();

        match Self::converged_head(&mut repo, &genesis)? {
            Some(latest_cid) => match repo.dag.get_node(&latest_cid) {
                Ok(Some(node)) => {
                    let bytes = node
                        .to_bytes()
                        .map_err(|e| anyhow::anyhow!("Failed to serialize node: {}", e))?;
                    Ok(Some((bytes, latest_cid.to_string())))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
            },
            None => Ok(None),
        }
    }

    async fn get_version_node_bytes(
        &self,
        genesis_cid: &str,
        version_cid: &str,
    ) -> Result<Option<Vec<u8>>> {
        let genesis = Self::parse_cid(genesis_cid)?;
        let cid = Self::parse_cid(version_cid)?;

        let repo = self.repo.lock();

        // Same series-scoping guarantee as get_version: refuse to serve a
        // version that belongs to a different content series.
        match repo.get_genesis(&cid) {
            Ok(g) if g == genesis => {}
            _ => return Ok(None),
        }

        match repo.dag.get_node(&cid) {
            Ok(Some(node)) => {
                let bytes = node
                    .to_bytes()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize node: {}", e))?;
                Ok(Some(bytes))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
        }
    }

    async fn get_access_policy(&self, genesis_cid: &str) -> Result<Option<AccessPolicy>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let mut repo = self.repo.lock();

        match Self::converged_head(&mut repo, &genesis)? {
            Some(latest_cid) => match repo.dag.get_node(&latest_cid) {
                Ok(Some(node)) => Ok(node.payload().access_policy.clone()),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("Failed to get node: {}", e)),
            },
            None => Ok(None),
        }
    }

    async fn update_access_policy(
        &self,
        genesis_cid: &str,
        policy: AccessPolicy,
        author: &str,
    ) -> Result<CommitResult> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let mut repo = self.repo.lock();
        let head = Self::converged_head(&mut repo, &genesis)?
            .ok_or_else(|| anyhow::anyhow!("Content not found: {genesis}"))?;
        let current = repo
            .dag
            .get_node(&head)?
            .ok_or_else(|| anyhow::anyhow!("Head node not found: {head}"))?;
        let mut payload = current.payload().clone();
        let mut policy = policy;
        if let Some(previous) = &payload.access_policy {
            policy.raise_min_valid_issued_at(previous.min_valid_issued_at());
        }
        // Only the policy changed. Keep both the body and its original order.
        payload.access_policy = Some(policy);
        let op = Operation::new(genesis, OperationType::Update(payload), author.to_string());
        let version_cid = repo
            .commit_operation(op)
            .map_err(|e| anyhow::anyhow!("Failed to commit access policy update: {}", e))?;

        Ok(CommitResult {
            genesis_cid: genesis_cid.to_string(),
            version_cid: version_cid.to_string(),
            is_new: false,
        })
    }

    async fn get_history(&self, genesis_cid: &str) -> Result<Vec<String>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let repo = self.repo.lock();

        let path = repo
            .linear_history(&genesis)
            .map_err(|e| anyhow::anyhow!("Failed to get history: {}", e))?;

        Ok(path.iter().map(|cid| cid.to_string()).collect())
    }

    async fn get_operations(
        &self,
        genesis_cid: &str,
        since_version: Option<&str>,
    ) -> Result<Vec<SerializedOperation>> {
        let genesis = Self::parse_cid(genesis_cid)?;

        let repo = self.repo.lock();

        let indexed_ops = repo
            .get_operations_with_index(&genesis)
            .map_err(|e| anyhow::anyhow!("Failed to get operations: {}", e))?;

        use crsl_lib::dasl::node::Node;
        use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

        let node_cids = repo
            .dag
            .get_nodes_by_genesis(&genesis)
            .map_err(|e| anyhow::anyhow!("Failed to get DAG nodes: {}", e))?;
        let mut nodes = HashMap::new();
        for cid in node_cids {
            let node = repo
                .dag
                .get_node(&cid)?
                .ok_or_else(|| anyhow::anyhow!("Missing DAG node {cid}"))?;
            nodes.insert(cid, node);
        }

        // Local operations (including auto-merges) do not store their node
        // timestamp. Match the complete node structure with only that field
        // removed; operation timestamps and linear-history positions are NOT
        // node identities. Imported operations already carry an exact stamp.
        let mut by_structure: HashMap<Cid, Vec<Cid>> = HashMap::new();
        for (cid, node) in &nodes {
            let mut unstamped = node.clone();
            unstamped.timestamp = 0;
            by_structure
                .entry(unstamped.content_id()?)
                .or_default()
                .push(*cid);
        }

        let mut templates = Vec::new();
        for (_, op) in indexed_ops {
            let node = match &op.kind {
                OperationType::Create(payload) => {
                    Node::new_genesis(payload.clone(), 0, ContentMetadata::default())
                }
                OperationType::Update(payload) | OperationType::Merge(payload) => {
                    let parent = op
                        .parents
                        .first()
                        .and_then(|cid| nodes.get(cid))
                        .ok_or_else(|| anyhow::anyhow!("Missing parent for operation {}", op.id))?;
                    Node::new_child(
                        payload.clone(),
                        op.parents.clone(),
                        genesis,
                        0,
                        parent.metadata().clone(),
                    )
                }
                // Delete has no payload and the public content API does not
                // produce it. Do not guess its historical payload.
                OperationType::Delete => {
                    anyhow::bail!("Cannot pair delete operation {} with its DAG node", op.id)
                }
            };
            templates.push((op, node));
        }

        // Reserve exact imported matches first. Two replicas can independently
        // merge identical parents/payloads at different times. Once exchanged,
        // the imported stamp disambiguates the remaining local merge node.
        let mut claimed = HashSet::new();
        let mut paired = Vec::new();
        let mut local = Vec::new();
        for (op, mut node) in templates {
            if let Some(timestamp) = op.node_timestamp {
                node.timestamp = timestamp;
                let cid = node.content_id()?;
                anyhow::ensure!(
                    nodes.get(&cid) == Some(&node),
                    "Missing DAG node for operation {}",
                    op.id
                );
                claimed.insert(cid);
                paired.push((cid, op));
            } else {
                local.push((op, node));
            }
        }
        for (op, node) in local {
            let candidates: Vec<_> = by_structure
                .get(&node.content_id()?)
                .into_iter()
                .flatten()
                .filter(|cid| !claimed.contains(*cid))
                .copied()
                .collect();
            anyhow::ensure!(
                candidates.len() == 1,
                "Cannot uniquely pair operation {} with its DAG node: {} candidates",
                op.id,
                candidates.len()
            );
            let cid = candidates[0];
            claimed.insert(cid);
            paired.push((cid, op));
        }

        // A receiver holding one branch tip knows its ancestors, not sibling
        // branches. Unknown versions safely request the complete DAG.
        let mut known = HashSet::new();
        if let Some(since) = since_version {
            let since = Self::parse_cid(since)?;
            if nodes.contains_key(&since) {
                let mut pending = vec![since];
                while let Some(cid) = pending.pop() {
                    if known.insert(cid) {
                        let node = nodes
                            .get(&cid)
                            .ok_or_else(|| anyhow::anyhow!("Missing ancestor DAG node {cid}"))?;
                        pending.extend(node.parents().iter().copied());
                    }
                }
            }
        }

        // Emit parents before children even when operation clocks disagree.
        // BTreeMap makes the choice between ready siblings deterministic.
        let mut pending: BTreeMap<Cid, Vec<Operation<Cid, ContentPayload>>> = BTreeMap::new();
        for (cid, op) in paired {
            if !known.contains(&cid) {
                pending.entry(cid).or_default().push(op);
            }
        }
        let mut children: HashMap<Cid, Vec<Cid>> = HashMap::new();
        let mut remaining_parents = HashMap::new();
        let mut ready_nodes = BTreeSet::new();
        for cid in pending.keys() {
            let mut count = 0;
            for parent in nodes[cid].parents() {
                if !known.contains(parent) {
                    anyhow::ensure!(
                        pending.contains_key(parent),
                        "Missing parent operation for DAG node {parent}"
                    );
                    children.entry(*parent).or_default().push(*cid);
                    count += 1;
                }
            }
            remaining_parents.insert(*cid, count);
            if count == 0 {
                ready_nodes.insert(*cid);
            }
        }
        let mut operations = Vec::new();
        while let Some(ready) = ready_nodes.pop_first() {
            for op in pending.remove(&ready).expect("ready node is pending") {
                operations.push(SerializedOperation {
                    data: serde_json::to_vec(&op).context("Failed to serialize operation")?,
                    genesis_cid: genesis_cid.to_string(),
                    author: op.author.clone(),
                    timestamp: op.timestamp,
                    node_timestamp: nodes[&ready].timestamp(),
                });
            }
            if let Some(children) = children.get(&ready) {
                for child in children {
                    let remaining = remaining_parents.get_mut(child).expect("child is pending");
                    *remaining -= 1;
                    if *remaining == 0 {
                        ready_nodes.insert(*child);
                    }
                }
            }
        }
        anyhow::ensure!(
            pending.is_empty(),
            "Cannot export cyclic DAG for {genesis_cid}"
        );
        Ok(operations)
    }

    /// Applies operations, returning how many of them the store now accounts
    /// for — including ones it already held. This is a measure of coverage,
    /// not of new writes: a caller uses it to tell "the batch landed" from
    /// "some operations failed", and re-delivery is the normal case.
    async fn apply_operations(&self, operations: &[SerializedOperation]) -> Result<usize> {
        let mut applied = 0;

        let mut repo = self.repo.lock();

        for serialized_op in operations {
            // Deserialize the operation
            let mut op: Operation<Cid, ContentPayload> =
                serde_json::from_slice(&serialized_op.data)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize operation: {}", e))?;

            // Set node_timestamp for import mode to ensure CID consistency across replicas
            op.node_timestamp = Some(serialized_op.node_timestamp);

            // A pull-based sync re-sends everything it has, so most operations
            // in a steady-state cluster are ones we already hold. Committing
            // one again rebuilds the same node CID, which the DAG reports as a
            // cycle — an error for what is the expected case. Skip the ones we
            // know: the operation id is assigned by the author and travels
            // with it, so it identifies the operation across replicas.
            // Knowing the operation is not the same as holding the node it
            // produced. A replica damaged by the old pairing has the operation
            // id recorded but committed the node under a wrong CID, so skipping
            // on the id alone would leave it broken forever. Only skip when the
            // operation is known AND its node is present under the CID this
            // stamp implies.
            let known = matches!(repo.state.get_operation(&op.id), Ok(Some(_)));
            if known && Self::node_is_present(&repo, &op) {
                applied += 1;
                continue;
            }

            // Apply the operation
            match repo.commit_operation(op) {
                Ok(_) => applied += 1,
                Err(e) => {
                    // Log but continue - operation might be a genuine conflict.
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

        let repo = self.repo.lock();

        Ok(repo.latest(&genesis).is_some())
    }

    async fn has_genesis(&self, genesis_cid: &str) -> Result<bool> {
        let genesis = match Self::parse_cid(genesis_cid) {
            Ok(cid) => cid,
            Err(_) => return Ok(false),
        };

        let repo = self.repo.lock();

        // The genesis CID *is* a node CID, so look it up directly. Unlike
        // `latest`, this is only true when the genesis node itself is present —
        // not when we hold only later versions from a partial sync.
        Ok(matches!(repo.dag.get_node(&genesis), Ok(Some(_))))
    }

    async fn list_contents(&self) -> Result<Vec<String>> {
        let repo = self.repo.lock();

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

    async fn prepare_create_operations(
        &self,
        data: &[u8],
        author: &str,
        owner_identity: Option<crate::domain::identity::Identity>,
    ) -> Result<PreparedCreate> {
        use crsl_lib::crdt::timestamp::next_monotonic_timestamp;
        use crsl_lib::dasl::node::Node;

        let mut operations = Vec::new();

        // 1. Build the Create operation and compute genesis CID via pure math
        //    (Node serialization + SHA-256). No storage is touched.
        let placeholder = Self::generate_placeholder_cid(data);
        let body_updated_at = next_monotonic_timestamp();
        let create_payload = ContentPayload {
            data: data.to_vec(),
            body_updated_at,
            access_policy: None,
        };
        let create_op = Operation::new(
            placeholder,
            OperationType::Create(create_payload.clone()),
            author.to_string(),
        );
        let create_ts = next_monotonic_timestamp();
        let genesis_node = Node::<ContentPayload, ContentMetadata>::new_genesis(
            create_payload,
            create_ts,
            ContentMetadata::default(),
        );
        let genesis_cid = genesis_node
            .content_id()
            .map_err(|e| anyhow::anyhow!("Failed to compute genesis CID: {}", e))?;

        let create_op_serialized = serde_json::to_vec(&{
            let mut op = create_op;
            op.genesis = genesis_cid;
            op.node_timestamp = Some(create_ts);
            op
        })
        .context("Failed to serialize create operation")?;

        operations.push(SerializedOperation {
            data: create_op_serialized,
            genesis_cid: genesis_cid.to_string(),
            author: author.to_string(),
            timestamp: create_ts,
            node_timestamp: create_ts,
        });

        // 2. Optionally build an AccessPolicy Update operation
        if let Some(identity) = owner_identity {
            let content_id_vo =
                crate::domain::value_objects::ContentId::new(genesis_cid.to_string())
                    .map_err(|e| anyhow::anyhow!("invalid genesis_cid: {}", e))?;
            let policy = AccessPolicy::new(content_id_vo, identity);
            let update_payload = ContentPayload {
                data: data.to_vec(),
                body_updated_at,
                access_policy: Some(policy),
            };
            let update_op = Operation::new(
                genesis_cid,
                OperationType::Update(update_payload.clone()),
                author.to_string(),
            );
            let update_ts = next_monotonic_timestamp();
            let update_node = Node::<ContentPayload, ContentMetadata>::new_child(
                update_payload,
                vec![genesis_cid],
                genesis_cid,
                update_ts,
                ContentMetadata::default(),
            );
            let _update_cid = update_node
                .content_id()
                .map_err(|e| anyhow::anyhow!("Failed to compute update CID: {}", e))?;

            let update_op_serialized = serde_json::to_vec(&{
                let mut op = update_op;
                op.parents = vec![genesis_cid];
                op.node_timestamp = Some(update_ts);
                op
            })
            .context("Failed to serialize update operation")?;

            operations.push(SerializedOperation {
                data: update_op_serialized,
                genesis_cid: genesis_cid.to_string(),
                author: author.to_string(),
                timestamp: update_ts,
                node_timestamp: update_ts,
            });
        }

        Ok(PreparedCreate {
            genesis_cid: genesis_cid.to_string(),
            operations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Builds a content network with history and returns (repo, genesis_cid).
    async fn creator_with_three_versions() -> (CrslCrdtRepository, tempfile::TempDir, String) {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path().join("crdt")).unwrap();
        let created = repo.create_content(b"v1", "author-a", None).await.unwrap();
        repo.update_content(&created.genesis_cid, b"v2", "author-a", None)
            .await
            .unwrap();
        repo.update_content(&created.genesis_cid, b"v3", "author-a", None)
            .await
            .unwrap();
        (repo, tmp, created.genesis_cid)
    }

    /// A sync must reproduce the sender's history exactly.
    ///
    /// `get_operations` stamps each operation with the timestamp of the DAG
    /// node it belongs to, because the receiver recomputes node CIDs from it.
    /// Matching an operation to its node by "any node within ±1s" returns the
    /// *first* such node — the genesis — for every operation written in the
    /// same second, so v2 and v3 were both re-derived under the genesis
    /// timestamp, collapsed onto one CID, and the newest version was silently
    /// lost. Every content network created and edited in one session hits
    /// this, which is why nodes disagreed about `latest_version`.
    #[tokio::test]
    async fn syncing_preserves_every_version() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;

        let ops = creator.get_operations(&genesis_cid, None).await.unwrap();
        assert_eq!(ops.len(), 3, "create + 2 updates");

        // Each operation must carry its OWN node timestamp; sharing one means
        // the receiver cannot tell the versions apart.
        let stamps: std::collections::HashSet<u64> = ops.iter().map(|o| o.node_timestamp).collect();
        assert_eq!(
            stamps.len(),
            ops.len(),
            "each operation must map to a distinct DAG node timestamp"
        );

        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        assert_eq!(receiver.apply_operations(&ops).await.unwrap(), ops.len());

        assert_eq!(
            receiver.get_latest(&genesis_cid).await.unwrap().unwrap(),
            b"v3".to_vec(),
            "the receiver must end up on the creator's latest version"
        );
        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap().len(),
            creator.get_history(&genesis_cid).await.unwrap().len(),
            "the receiver must hold the same number of versions as the creator"
        );
    }

    /// Reproduces the production log flood: every periodic sync re-sends the
    /// same operations, and a node that already holds them logged
    /// "Failed to apply operation: graph error: cycle detected in graph" for
    /// each one (1048 times in 25 minutes on node1). Re-delivery is the normal
    /// steady state of a pull-based sync, so it must be a quiet no-op.
    #[tokio::test]
    async fn reapplying_known_operations_is_a_quiet_no_op() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;
        let ops = creator.get_operations(&genesis_cid, None).await.unwrap();

        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        receiver.apply_operations(&ops).await.unwrap();

        // The next periodic sync hands us the very same operations again.
        let reapplied = receiver.apply_operations(&ops).await.unwrap();

        assert_eq!(
            receiver.get_latest(&genesis_cid).await.unwrap().unwrap(),
            b"v3".to_vec(),
            "re-syncing known operations must not change the content"
        );
        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap().len(),
            3,
            "re-syncing must not duplicate or drop versions"
        );
        assert_eq!(
            reapplied,
            ops.len(),
            "operations we already hold count as applied, not as failures"
        );
    }

    /// Incremental sync: a node that already holds part of the history asks
    /// for "everything after version X". The operations it gets back must
    /// still carry their own node timestamps — the `since_version` filter
    /// must not shift them onto the wrong nodes.
    #[tokio::test]
    async fn incremental_sync_lands_on_the_same_history() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;

        // Receiver catches up to v1 only.
        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        let all = creator.get_operations(&genesis_cid, None).await.unwrap();
        receiver.apply_operations(&all[..1]).await.unwrap();
        assert_eq!(
            receiver.get_latest(&genesis_cid).await.unwrap().unwrap(),
            b"v1".to_vec()
        );

        // Now it asks only for what came after the genesis version.
        let tail = creator
            .get_operations(&genesis_cid, Some(&genesis_cid))
            .await
            .unwrap();
        assert_eq!(tail.len(), 2, "the two updates, not the create");
        receiver.apply_operations(&tail).await.unwrap();

        assert_eq!(
            receiver.get_latest(&genesis_cid).await.unwrap().unwrap(),
            b"v3".to_vec(),
            "an incremental catch-up must reach the creator's latest version"
        );
        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap(),
            creator.get_history(&genesis_cid).await.unwrap(),
            "incremental and full sync must produce the same history"
        );
    }

    /// `since_version` must mean "everything strictly after this version".
    ///
    /// Resolving it by "the last operation whose timestamp is <= the node's"
    /// is the same guess that broke node timestamps: versions written inside
    /// one second are indistinguishable that way, so a catch-up from v2 could
    /// return v2 again (re-delivering work) or skip v3 (losing it).
    #[tokio::test]
    async fn since_version_returns_exactly_the_newer_operations() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;

        let history = creator.get_history(&genesis_cid).await.unwrap();
        assert_eq!(history.len(), 3, "genesis + 2 updates");

        // Asking from the middle version must yield only the last update.
        let tail = creator
            .get_operations(&genesis_cid, Some(&history[1]))
            .await
            .unwrap();
        assert_eq!(
            tail.len(),
            1,
            "since=v2 must return only the operation that produced v3"
        );

        // And that one operation must carry v3's node timestamp, so a receiver
        // rebuilds the same node.
        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        let head = creator.get_operations(&genesis_cid, None).await.unwrap();
        receiver.apply_operations(&head[..2]).await.unwrap();
        receiver.apply_operations(&tail).await.unwrap();
        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap(),
            history,
            "catching up from the middle must rebuild the identical history"
        );

        // Asking from the newest version must yield nothing.
        let none = creator
            .get_operations(&genesis_cid, Some(&history[2]))
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "since=latest must return nothing, got {} operation(s)",
            none.len()
        );
    }

    /// A node that already synced under the old (broken) pairing holds a
    /// truncated history. Once the sender is fixed, the operations it sends
    /// carry correct node timestamps — so the stale receiver must be able to
    /// converge on the full history without being wiped first.
    ///
    /// This decides whether the deployed cluster needs its CRDT store cleared
    /// or heals on its own after a redeploy.
    #[tokio::test]
    async fn a_receiver_with_a_truncated_history_catches_up() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;
        let ops = creator.get_operations(&genesis_cid, None).await.unwrap();

        // Simulate the damaged state: the receiver got the create and one
        // update, and never received the newest version.
        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        receiver.apply_operations(&ops[..2]).await.unwrap();
        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap().len(),
            2,
            "precondition: the receiver is behind"
        );

        // The next periodic sync delivers the full, correctly-stamped set.
        receiver.apply_operations(&ops).await.unwrap();

        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap(),
            creator.get_history(&genesis_cid).await.unwrap(),
            "a stale replica must converge from an ordinary sync"
        );
        assert_eq!(
            receiver.get_latest(&genesis_cid).await.unwrap().unwrap(),
            b"v3".to_vec()
        );
    }

    /// The production failure mode, at the scale it actually happened.
    ///
    /// A member is asked to re-apply the same operations on every sync round
    /// and from every provider. node1 logged 1048 such failures in 25 minutes
    /// while pinning a core; each one is a full commit attempt that walks the
    /// DAG before failing. Repeated delivery must stay cheap and quiet.
    #[tokio::test]
    async fn repeated_delivery_never_errors() {
        let (creator, _creator_tmp, genesis_cid) = creator_with_three_versions().await;
        let ops = creator.get_operations(&genesis_cid, None).await.unwrap();

        let receiver_tmp = tempdir().unwrap();
        let receiver = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();

        // 20 sync rounds × 2 providers, the shape of a steady-state cluster.
        for _ in 0..20 {
            for _ in 0..2 {
                let applied = receiver.apply_operations(&ops).await.unwrap();
                assert_eq!(
                    applied,
                    ops.len(),
                    "every round must account for all operations; a shortfall is \
                     an operation that failed to apply"
                );
            }
        }

        assert_eq!(
            receiver.get_history(&genesis_cid).await.unwrap(),
            creator.get_history(&genesis_cid).await.unwrap(),
            "40 redeliveries must leave the history identical to the sender's"
        );
    }

    /// Export all branches using their actual DAG identities, never the
    /// positions in the single path returned by linear_history.
    #[tokio::test]
    async fn forked_operations_replay_with_their_actual_node_cids() {
        let (creator, _tmp, genesis_cid) = creator_with_three_versions().await;

        // Sanity: the linear case still works.
        assert_eq!(
            creator
                .get_operations(&genesis_cid, None)
                .await
                .unwrap()
                .len(),
            3
        );

        let genesis = CrslCrdtRepository::parse_cid(&genesis_cid).unwrap();
        let (ops_len, history_len) = {
            let repo = creator.repo.lock();
            (
                repo.get_operations_with_index(&genesis).unwrap().len(),
                repo.linear_history(&genesis).unwrap().len(),
            )
        };
        assert_eq!(
            ops_len, history_len,
            "precondition: a linear history pairs one-to-one"
        );

        // Now fork it. Two replicas edit independently and then exchange
        // operations, which is ordinary behaviour for a multi-writer network.
        let other_tmp = tempdir().unwrap();
        let other = CrslCrdtRepository::open(other_tmp.path().join("crdt")).unwrap();
        other
            .apply_operations(&creator.get_operations(&genesis_cid, None).await.unwrap())
            .await
            .unwrap();

        creator
            .update_content(&genesis_cid, b"from-creator", "author-a", None)
            .await
            .unwrap();
        other
            .update_content(&genesis_cid, b"from-other", "author-b", None)
            .await
            .unwrap();

        // Creator learns about the divergent branch.
        creator
            .apply_operations(&other.get_operations(&genesis_cid, None).await.unwrap())
            .await
            .unwrap();

        let (ops_len, history_len) = {
            let repo = creator.repo.lock();
            (
                repo.get_operations_with_index(&genesis).unwrap().len(),
                repo.linear_history(&genesis).unwrap().len(),
            )
        };

        assert!(ops_len > history_len, "fixture must contain a real fork");
        let operations = creator.get_operations(&genesis_cid, None).await.unwrap();
        assert_eq!(operations.len(), ops_len);
        let replica_tmp = tempdir().unwrap();
        let replica = CrslCrdtRepository::open(replica_tmp.path()).unwrap();
        assert_eq!(
            replica.apply_operations(&operations).await.unwrap(),
            ops_len
        );
        let expected_nodes = {
            let repo = creator.repo.lock();
            repo.dag.get_nodes_by_genesis(&genesis).unwrap()
        };
        for cid in expected_nodes {
            assert_eq!(
                replica
                    .get_version_node_bytes(&genesis_cid, &cid.to_string())
                    .await
                    .unwrap(),
                creator
                    .get_version_node_bytes(&genesis_cid, &cid.to_string())
                    .await
                    .unwrap(),
                "every branch node must retain its original CID"
            );
        }
    }

    /// A replica that committed a WRONG node CID under the old pairing must
    /// heal once the sender is fixed.
    ///
    /// This is the case the recovery claim turns on, and it is not the same as
    /// a truncated prefix. Under the old code a receiver could commit v2
    /// stamped with the genesis timestamp: a node at the wrong CID, with the
    /// operation id already recorded in state. Skipping on the operation id
    /// alone would leave that wrong node in place forever, so the skip also
    /// requires the node itself to be present.
    #[tokio::test]
    async fn a_replica_that_committed_a_wrong_cid_heals_from_an_ordinary_sync() {
        let (creator, _tmp, genesis_cid) = creator_with_three_versions().await;
        let correct = creator.get_operations(&genesis_cid, None).await.unwrap();

        // Reproduce the damage: same operations, but the updates carry the
        // genesis timestamp, which is exactly what the ±1s match produced.
        let genesis_ts = correct[0].node_timestamp;
        let damaged: Vec<SerializedOperation> = correct
            .iter()
            .map(|op| SerializedOperation {
                node_timestamp: genesis_ts,
                ..op.clone()
            })
            .collect();

        let victim_tmp = tempdir().unwrap();
        let victim = CrslCrdtRepository::open(victim_tmp.path().join("crdt")).unwrap();
        victim.apply_operations(&damaged).await.unwrap();

        let damaged_history = victim.get_history(&genesis_cid).await.unwrap();
        let healthy_history = creator.get_history(&genesis_cid).await.unwrap();
        assert_ne!(
            damaged_history, healthy_history,
            "precondition: the victim's history must actually be damaged"
        );

        // The sender is fixed now and re-sends correctly stamped operations,
        // repeatedly, as a periodic sync would.
        for _ in 0..5 {
            victim.apply_operations(&correct).await.unwrap();
        }

        let after = victim.get_history(&genesis_cid).await.unwrap();
        assert_eq!(
            after, healthy_history,
            "a replica damaged by the old pairing must converge once the sender \
             is fixed; if this fails, such replicas need their store cleared"
        );
    }

    #[tokio::test]
    async fn test_prepare_create_operations_is_deterministic_across_repos() {
        // Creator prepares operations without persisting to its own store.
        let creator_tmp = tempdir().unwrap();
        let creator_repo = CrslCrdtRepository::open(creator_tmp.path().join("crdt")).unwrap();

        let data = b"hello from creator";
        let prepared = creator_repo
            .prepare_create_operations(data, "author-a", None)
            .await
            .unwrap();

        // Creator's own repo must be untouched by prepare_create_operations.
        assert_eq!(
            creator_repo.list_contents().await.unwrap().len(),
            0,
            "prepare_create_operations must not persist to the creator's repo"
        );
        assert!(
            creator_repo
                .get_latest(&prepared.genesis_cid)
                .await
                .unwrap()
                .is_none(),
            "creator should not have data for the prepared genesis_cid"
        );
        assert!(
            !prepared.operations.is_empty(),
            "prepared.operations should contain at least the Create op"
        );

        // A receiver applies the operations and must end up with the same
        // genesis_cid and the same content data.
        let receiver_tmp = tempdir().unwrap();
        let receiver_repo = CrslCrdtRepository::open(receiver_tmp.path().join("crdt")).unwrap();
        let applied = receiver_repo
            .apply_operations(&prepared.operations)
            .await
            .unwrap();
        assert_eq!(applied, prepared.operations.len());

        let received_data = receiver_repo
            .get_latest(&prepared.genesis_cid)
            .await
            .unwrap();
        assert_eq!(
            received_data.as_deref(),
            Some(&data[..]),
            "receiver should end up with the creator's payload under the same genesis_cid"
        );
    }

    #[tokio::test]
    async fn test_create_and_get_content() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Hello, CRDT!";
        let result = repo
            .create_content(data, "test-author", None)
            .await
            .unwrap();

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
        let result = repo
            .create_content(initial_data, "author1", None)
            .await
            .unwrap();

        let updated_data = b"Updated content";
        let update_result = repo
            .update_content(&result.genesis_cid, updated_data, "author1", None)
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
        let result = repo.create_content(data, "author", None).await.unwrap();

        assert!(repo.exists(&result.genesis_cid).await.unwrap());

        // Non-existent content should return false
        assert!(!repo
            .exists("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_get_version_rejects_cross_content_lookup() {
        // Read authorization is granted per content, so a version CID from a
        // different series must not be readable through another genesis.
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let a = repo
            .create_content(b"content A", "author", None)
            .await
            .unwrap();
        let b = repo
            .create_content(b"content B", "author", None)
            .await
            .unwrap();

        // Sanity: within the right series the version resolves.
        assert!(repo
            .get_version(&a.genesis_cid, &a.version_cid)
            .await
            .unwrap()
            .is_some());

        // Cross-content: B's version through A's genesis must be None.
        assert!(repo
            .get_version(&a.genesis_cid, &b.version_cid)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_get_history() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data1 = b"Version 1";
        let result = repo.create_content(data1, "author", None).await.unwrap();

        // Small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let data2 = b"Version 2";
        repo.update_content(&result.genesis_cid, data2, "author", None)
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
        let result = repo.create_content(data, "author", None).await.unwrap();

        let retrieved = repo
            .get_version(&result.genesis_cid, &result.version_cid)
            .await
            .unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_list_contents() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data1 = b"Content 1";
        let result1 = repo.create_content(data1, "author", None).await.unwrap();

        let data2 = b"Content 2";
        let result2 = repo.create_content(data2, "author", None).await.unwrap();

        let contents = repo.list_contents().await.unwrap();
        assert!(contents.contains(&result1.genesis_cid));
        assert!(contents.contains(&result2.genesis_cid));
    }

    #[tokio::test]
    async fn test_get_operations() {
        let tmp = tempdir().unwrap();
        let repo = CrslCrdtRepository::open(tmp.path()).unwrap();

        let data = b"Test content";
        let result = repo.create_content(data, "author", None).await.unwrap();

        let operations = repo
            .get_operations(&result.genesis_cid, None)
            .await
            .unwrap();
        assert!(!operations.is_empty());
        assert_eq!(operations[0].genesis_cid, result.genesis_cid);
    }

    // ---- concurrent revoke × write across two replicas -------------------

    use crate::domain::identity::Identity;
    use crate::domain::value_objects::ContentId;

    fn owner_policy(genesis: &str) -> AccessPolicy {
        AccessPolicy::new(
            ContentId::new(genesis.to_string()).unwrap(),
            Identity::user("alice".to_string()).unwrap(),
        )
    }

    /// Two replicas holding the same content: `a` revokes, `b` (which has
    /// not seen the revoke) accepts a write. Then they sync both ways.
    ///
    /// Returns the replicas after convergence.
    async fn revoke_on_a_write_on_b(
        write_first: bool,
    ) -> (
        CrslCrdtRepository,
        CrslCrdtRepository,
        String,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let tmp_a = tempdir().unwrap();
        let tmp_b = tempdir().unwrap();
        let a = CrslCrdtRepository::open(tmp_a.path().join("crdt")).unwrap();
        let b = CrslCrdtRepository::open(tmp_b.path().join("crdt")).unwrap();

        // Shared base: created on a, replicated to b. The policy is set on
        // the first update so both replicas hold it under the genesis.
        let created = a.create_content(b"AB", "alice", None).await.unwrap();
        let genesis = created.genesis_cid.clone();
        a.update_access_policy(&genesis, owner_policy(&genesis), "alice")
            .await
            .unwrap();
        let base_ops = a.get_operations(&genesis, None).await.unwrap();
        b.apply_operations(&base_ops).await.unwrap();
        assert_eq!(b.get_latest(&genesis).await.unwrap().unwrap(), b"AB");

        // Concurrent: a revokes (policy-only), b takes a write. Order of the
        // two only decides which node carries the newer timestamp.
        async fn revoke(a: &CrslCrdtRepository, genesis: &str) {
            let mut p = a.get_access_policy(genesis).await.unwrap().unwrap();
            p.invalidate_tokens();
            a.update_access_policy(genesis, p, "alice").await.unwrap();
        }
        async fn write(b: &CrslCrdtRepository, genesis: &str) {
            b.update_content(genesis, b"ABC", "bob", None)
                .await
                .unwrap();
        }
        // `invalidate_tokens` stamps whole seconds; sleep past one so the
        // two nodes are distinguishable by timestamp.
        if write_first {
            write(&b, &genesis).await;
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            revoke(&a, &genesis).await;
        } else {
            revoke(&a, &genesis).await;
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            write(&b, &genesis).await;
        }

        // Sync both ways. Applying the other side's ops creates concurrent
        // heads on each replica; the head reads below converge them.
        let ops_a = a.get_operations(&genesis, None).await.unwrap();
        let ops_b = b.get_operations(&genesis, None).await.unwrap();
        b.apply_operations(&ops_a).await.unwrap();
        a.apply_operations(&ops_b).await.unwrap();
        // No commit needed to converge: every head read merges first.
        (a, b, genesis, tmp_a, tmp_b)
    }

    /// Write after revoke (the observed production case): the write wins the
    /// body, but the revoke must not be erased by it.
    #[tokio::test]
    async fn concurrent_write_after_revoke_keeps_cutoff_on_both_replicas() {
        let (a, b, genesis, _ta, _tb) = revoke_on_a_write_on_b(false).await;
        for (name, r) in [("a", &a), ("b", &b)] {
            let policy = r.get_access_policy(&genesis).await.unwrap().unwrap();
            assert!(
                policy.min_valid_issued_at() > 0,
                "replica {name}: the revoke was erased by the concurrent write"
            );
            assert_eq!(r.get_latest(&genesis).await.unwrap().unwrap(), b"ABC");
        }
        // Each replica mints its own merge node (its own timestamp), so the
        // head CIDs differ until the next sync merges the two merge nodes —
        // which, being equal in every field, converge on the same payload.
        // That was already true of the lazy merge; the guarantee here is
        // the payload, not the CID.
    }

    /// Revoke after write: the revoke is newer but did not write, so the
    /// write it never conflicted with must survive.
    #[tokio::test]
    async fn concurrent_revoke_after_write_keeps_write_on_both_replicas() {
        let (a, b, genesis, _ta, _tb) = revoke_on_a_write_on_b(true).await;
        for (name, r) in [("a", &a), ("b", &b)] {
            let policy = r.get_access_policy(&genesis).await.unwrap().unwrap();
            assert!(
                policy.min_valid_issued_at() > 0,
                "replica {name}: cutoff lost"
            );
            assert_eq!(
                r.get_latest(&genesis).await.unwrap().unwrap(),
                b"ABC",
                "replica {name}: a policy-only revoke overwrote a concurrent write"
            );
        }
    }
}
