//! Content Sync Service - Handles synchronization of CRDT content between nodes.

use crate::port::content_repository::ContentRepository;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::PersistentContentRepository;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result of a sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of operations applied from remote nodes.
    pub operations_applied: usize,
    /// Number of providers contacted.
    pub providers_contacted: usize,
    /// Any errors encountered during sync (non-fatal).
    pub errors: Vec<String>,
}

/// Result of a push operation.
#[derive(Debug, Clone)]
pub struct PushResult {
    /// Number of nodes successfully pushed to.
    pub nodes_pushed: usize,
    /// Number of operations sent.
    pub operations_sent: usize,
    /// Any errors encountered during push (non-fatal).
    pub errors: Vec<String>,
}

/// Service for synchronizing CRDT content between nodes.
///
/// This service handles:
/// - Fetching operations from other nodes (pull-based sync)
/// - Pushing operations to other nodes (push-based sync)
/// - Periodic background synchronization
pub struct ContentSyncService<P, R, C>
where
    P: PeerNetwork,
    R: ContentRepository,
    C: PersistentContentRepository,
{
    peer_network: Arc<P>,
    crdt_repo: Arc<R>,
    content_network_repo: Arc<RwLock<C>>,
    local_node_id: String,
}

impl<P, R, C> ContentSyncService<P, R, C>
where
    P: PeerNetwork,
    R: ContentRepository,
    C: PersistentContentRepository,
{
    /// Create a new ContentSyncService.
    pub fn new(
        peer_network: Arc<P>,
        crdt_repo: Arc<R>,
        content_network_repo: Arc<RwLock<C>>,
        local_node_id: String,
    ) -> Self {
        Self {
            peer_network,
            crdt_repo,
            content_network_repo,
            local_node_id,
        }
    }

    /// Sync content from other nodes (pull-based).
    ///
    /// This fetches operations from content providers and applies them locally.
    pub async fn sync_from_peers(&self, genesis_cid: &str) -> Result<SyncResult> {
        let mut result = SyncResult {
            operations_applied: 0,
            providers_contacted: 0,
            errors: Vec::new(),
        };

        // 1. Find providers for this content
        let providers = match self.peer_network.find_content_providers(genesis_cid).await {
            Ok(p) => p,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to find providers: {}", e));
                return Ok(result);
            }
        };

        if providers.is_empty() {
            tracing::debug!("No providers found for content {}", genesis_cid);
            return Ok(result);
        }

        // 2. Get local version to request only newer operations
        let local_version = self
            .crdt_repo
            .get_history(genesis_cid)
            .await
            .ok()
            .and_then(|h| h.last().cloned());

        // 3. Fetch operations from each provider
        for provider in providers {
            if provider == self.local_node_id {
                continue; // Skip self
            }

            result.providers_contacted += 1;

            match self
                .peer_network
                .fetch_operations(&provider, genesis_cid, local_version.as_deref())
                .await
            {
                Ok(ops) => {
                    if ops.is_empty() {
                        continue;
                    }

                    // Apply operations to local CRDT repository
                    match self.crdt_repo.apply_operations(&ops).await {
                        Ok(applied) => {
                            result.operations_applied += applied;
                            tracing::debug!(
                                "Applied {} operations from {} for content {}",
                                applied,
                                provider,
                                genesis_cid
                            );
                        }
                        Err(e) => {
                            result.errors.push(format!(
                                "Failed to apply operations from {}: {}",
                                provider, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to fetch from {}: {}", provider, e));
                }
            }
        }

        Ok(result)
    }

    /// Push local operations to other nodes.
    ///
    /// This sends operations to all member nodes in the content network.
    pub async fn push_to_peers(&self, genesis_cid: &str) -> Result<PushResult> {
        let mut result = PushResult {
            nodes_pushed: 0,
            operations_sent: 0,
            errors: Vec::new(),
        };

        // 1. Get the content network to find member nodes
        let network = match self
            .content_network_repo
            .read()
            .await
            .get_content_network(genesis_cid)
            .await
        {
            Ok(Some(n)) => n,
            Ok(None) => {
                result
                    .errors
                    .push(format!("Content network not found: {}", genesis_cid));
                return Ok(result);
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to get content network: {}", e));
                return Ok(result);
            }
        };

        // 2. Get all local operations
        let operations = match self.crdt_repo.get_operations(genesis_cid, None).await {
            Ok(ops) => ops,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to get local operations: {}", e));
                return Ok(result);
            }
        };

        if operations.is_empty() {
            return Ok(result);
        }

        // 3. Push to each member node
        for node_id in network.member_nodes {
            if node_id == self.local_node_id {
                continue; // Skip self
            }

            match self
                .peer_network
                .push_operations(&node_id, genesis_cid, &operations)
                .await
            {
                Ok(accepted) => {
                    result.nodes_pushed += 1;
                    result.operations_sent += accepted;
                    tracing::debug!(
                        "Pushed {} operations to {} for content {}",
                        accepted,
                        node_id,
                        genesis_cid
                    );
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to push to {}: {}", node_id, e));
                }
            }
        }

        Ok(result)
    }

    /// Sync all content that this node is a member of.
    ///
    /// This is useful for periodic background synchronization.
    pub async fn sync_all_content(&self) -> Result<Vec<(String, SyncResult)>> {
        let mut results = Vec::new();

        // Get all content networks
        let content_ids = self
            .content_network_repo
            .read()
            .await
            .list_content_networks()
            .await?;

        for content_id in content_ids {
            // Check if we're a member
            if let Ok(Some(network)) = self
                .content_network_repo
                .read()
                .await
                .get_content_network(&content_id)
                .await
            {
                if network.member_nodes.contains(&self.local_node_id) {
                    match self.sync_from_peers(&content_id).await {
                        Ok(result) => {
                            results.push((content_id, result));
                        }
                        Err(e) => {
                            tracing::warn!("Failed to sync content {}: {}", content_id, e);
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Broadcast a new operation to all peers.
    ///
    /// This is called after a local update to notify other nodes.
    pub async fn broadcast_operation(
        &self,
        genesis_cid: &str,
        operation: &crate::port::content_repository::SerializedOperation,
    ) -> Result<()> {
        self.peer_network
            .broadcast_operation(genesis_cid, operation)
            .await
    }
}

impl<P, R, C> Clone for ContentSyncService<P, R, C>
where
    P: PeerNetwork,
    R: ContentRepository,
    C: PersistentContentRepository,
{
    fn clone(&self) -> Self {
        Self {
            peer_network: self.peer_network.clone(),
            crdt_repo: self.crdt_repo.clone(),
            content_network_repo: self.content_network_repo.clone(),
            local_node_id: self.local_node_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests would go here with mock implementations
}

