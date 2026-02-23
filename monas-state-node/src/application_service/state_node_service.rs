//! State Node Service - Application layer for managing state nodes.

use crate::domain::access_control::{
    AccessControlError, AccessControlUpdate, ContentAccessControl,
};
use crate::domain::access_policy::AccessPolicy;
use crate::domain::auth_capability::AuthCapability;
use crate::domain::content_network::ContentNetwork;
use crate::domain::errors::{CrdtError, NetworkError, StateNodeError};
use crate::domain::events::{current_timestamp, Event};
use crate::domain::identity::Identity;
use crate::domain::state_node::{self, NodeSnapshot};
use crate::domain::value_objects::ContentId;
use crate::infrastructure::crypto::verify_p256_signature;
use crate::infrastructure::placement::compute_dht_key;
use crate::port::auth_token::{AuthToken, RequestMetadata};
use crate::port::authentication_service::AuthenticationService;
use crate::port::authorization_service::{AuthorizationRequest, AuthorizationService};
use crate::port::content_repository::ContentRepository;
use crate::port::event_publisher::EventPublisher;
use crate::port::extended_public_key_registry::ExtendedPublicKeyRegistry;
use crate::port::peer_network::PeerNetwork;
use crate::port::persistence::{
    PersistentAccessControlRepository, PersistentContentRepository, PersistentNodeRegistry,
};
use anyhow::Result;
use std::sync::Arc;

/// Result of applying an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Event was applied, no further action needed.
    Applied,
    /// Event was ignored (not relevant to this node).
    Ignored,
    /// Event was applied and content sync is needed for the given content_id.
    /// The node should call sync_from_peers for this content.
    NeedsSync { content_id: String },
}

/// Configuration for StateNodeService redundancy management.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Minimum number of member nodes for redundancy.
    pub min_replication_factor: usize,
    /// Capacity threshold in bytes below which a node is considered low on storage.
    pub capacity_threshold_bytes: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            min_replication_factor: 3,
            capacity_threshold_bytes: 1_073_741_824, // 1GB
        }
    }
}

// ============================================================================
// StateNodeService - Structured service with dependency injection
// ============================================================================

/// State Node Service with injected dependencies.
///
/// This service provides high-level operations for managing state nodes,
/// content networks, and event publishing.
pub struct StateNodeService<N, C, P, E, R, A = NoOpAccessControlRepository>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
    R: ContentRepository,
    A: PersistentAccessControlRepository,
{
    node_registry: Arc<tokio::sync::RwLock<N>>,
    content_repo: Arc<tokio::sync::RwLock<C>>,
    peer_network: Arc<P>,
    event_publisher: Arc<E>,
    crdt_repo: Arc<R>,
    access_control_repo: Option<Arc<tokio::sync::RwLock<A>>>,
    /// Authentication service for DID-based authentication
    auth_service: Option<Arc<dyn AuthenticationService>>,
    /// Authorization service for capability-based authorization
    authz_service: Option<Arc<dyn AuthorizationService>>,
    /// Extended public key registry for key registration
    extended_key_registry: Option<Arc<dyn ExtendedPublicKeyRegistry>>,
    local_node_id: String,
    /// Minimum number of member nodes for redundancy.
    min_replication_factor: usize,
    /// Capacity threshold in bytes below which a node is considered low on storage.
    capacity_threshold_bytes: u64,
}

/// No-op access control repository for backward compatibility.
pub struct NoOpAccessControlRepository;

#[async_trait::async_trait]
impl PersistentAccessControlRepository for NoOpAccessControlRepository {
    async fn get_access_control(&self, _content_id: &str) -> Result<Option<ContentAccessControl>> {
        Ok(None)
    }
    async fn save_access_control(&self, _access_control: &ContentAccessControl) -> Result<()> {
        Ok(())
    }
    async fn delete_access_control(&self, _content_id: &str) -> Result<()> {
        Ok(())
    }
    async fn list_access_controls(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

impl<N, C, P, E, R, A> StateNodeService<N, C, P, E, R, A>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
    P: PeerNetwork,
    E: EventPublisher,
    R: ContentRepository,
    A: PersistentAccessControlRepository,
{
    /// Create a new StateNodeService.
    ///
    /// The `peer_network` is passed as an `Arc` to allow sharing with other components
    /// (e.g., GossipsubEventPublisher).
    /// The `content_repo` is passed as `Arc<RwLock<C>>` to allow sharing with ContentSyncService.
    pub fn new(
        node_registry: N,
        content_repo: Arc<tokio::sync::RwLock<C>>,
        peer_network: Arc<P>,
        event_publisher: E,
        crdt_repo: Arc<R>,
        local_node_id: String,
    ) -> Self {
        Self::with_config(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            local_node_id,
            ServiceConfig::default(),
        )
    }

    /// Create a new StateNodeService with custom configuration.
    pub fn with_config(
        node_registry: N,
        content_repo: Arc<tokio::sync::RwLock<C>>,
        peer_network: Arc<P>,
        event_publisher: E,
        crdt_repo: Arc<R>,
        local_node_id: String,
        config: ServiceConfig,
    ) -> Self {
        Self {
            node_registry: Arc::new(tokio::sync::RwLock::new(node_registry)),
            content_repo,
            peer_network,
            event_publisher: Arc::new(event_publisher),
            crdt_repo,
            access_control_repo: None,
            auth_service: None,
            authz_service: None,
            extended_key_registry: None,
            local_node_id,
            min_replication_factor: config.min_replication_factor,
            capacity_threshold_bytes: config.capacity_threshold_bytes,
        }
    }

    /// Set the access control repository (builder pattern).
    ///
    /// This method allows adding access control support after construction.
    pub fn with_access_control_repo(mut self, access_control_repo: A) -> Self {
        self.access_control_repo = Some(Arc::new(tokio::sync::RwLock::new(access_control_repo)));
        self
    }

    /// Set the authentication service (builder pattern).
    ///
    /// This method allows adding authentication support after construction.
    pub fn with_authentication_service(
        mut self,
        auth_service: impl AuthenticationService + 'static,
    ) -> Self {
        self.auth_service = Some(Arc::new(auth_service));
        self
    }

    /// Set the authorization service (builder pattern).
    ///
    /// This method allows adding authorization support after construction.
    pub fn with_authorization_service(
        mut self,
        authz_service: impl AuthorizationService + 'static,
    ) -> Self {
        self.authz_service = Some(Arc::new(authz_service));
        self
    }

    /// Set the extended public key registry (builder pattern).
    ///
    /// This method allows registering public keys for key_id-based authentication.
    pub fn with_extended_key_registry(
        mut self,
        registry: Arc<dyn ExtendedPublicKeyRegistry>,
    ) -> Self {
        self.extended_key_registry = Some(registry);
        self
    }

    /// Register a public key for a key_id in the extended public key registry.
    pub async fn register_public_key_for_key_id(
        &self,
        key_id: String,
        public_key: Vec<u8>,
    ) -> Result<(), StateNodeError> {
        let registry = self.extended_key_registry.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration(
                "Extended public key registry not configured".to_string(),
            )
        })?;
        registry
            .register_public_key_for_key_id(key_id, public_key)
            .await
            .map_err(|e| StateNodeError::Internal(e.to_string()))
    }

    /// Get the CRDT repository.
    pub fn crdt_repo(&self) -> &Arc<R> {
        &self.crdt_repo
    }

    /// Get the authorization service (if configured).
    pub fn authz_service(&self) -> Option<&Arc<dyn AuthorizationService>> {
        self.authz_service.as_ref()
    }

    /// Authenticate a caller for read operations.
    ///
    /// Returns the authenticated identity on success.
    pub async fn authenticate_for_read(
        &self,
        token: &AuthToken,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<Identity, StateNodeError> {
        let auth_service = self.auth_service.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
        })?;

        let identity = auth_service
            .authenticate(token, None)
            .await
            .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

        // Verify caller signature:
        // - JWT tokens: verify JWT's own P-256 signature
        // - type:id tokens: verify request signature (mandatory)
        let sig = if token.as_str().contains('.') {
            // JWT: signature is inside the token itself, pass empty slice
            &[] as &[u8]
        } else {
            request_signature.ok_or_else(|| {
                StateNodeError::AuthenticationFailed(
                    "Request signature is required for non-JWT tokens".to_string(),
                )
            })?
        };
        self.verify_caller_signature(
            auth_service.as_ref(),
            token,
            sig,
            "read",
            "content",
            timestamp,
            None,
        )
        .await?;

        Ok(identity)
    }

    /// Verify the caller's request signature.
    ///
    /// For JWT tokens (containing `.`), verifies the JWT's own P-256 signature
    /// via `AuthenticationService::verify_jwt_signature`. JWT tokens contain
    /// operation/resource/timestamp in their payload, so no separate request
    /// body signature is needed.
    ///
    /// For `type:id` tokens (e.g., `user:alice`), constructs a signing message
    /// and delegates to `AuthenticationService::verify_request_signature`:
    /// - If `request_body` is `Some(body)`: signs `hex(sha256(body + timestamp_be_bytes))`
    /// - If `request_body` is `None`: signs `{operation}:{resource}:{timestamp}`
    #[allow(clippy::too_many_arguments)]
    async fn verify_caller_signature(
        &self,
        auth_service: &dyn AuthenticationService,
        token: &AuthToken,
        signature: &[u8],
        operation: &str,
        resource: &str,
        timestamp: Option<u64>,
        request_body: Option<&[u8]>,
    ) -> Result<(), StateNodeError> {
        // JWT tokens: verify the JWT's own signature
        if token.as_str().contains('.') {
            return auth_service.verify_jwt_signature(token).await.map_err(|e| {
                StateNodeError::AuthenticationFailed(format!(
                    "JWT signature verification failed: {}",
                    e
                ))
            });
        }

        // non-JWT tokens: verify request signature
        let ts = timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let message = if let Some(body) = request_body {
            // Body-based signing: hex(sha256(body + timestamp_be_bytes))
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(body);
            hasher.update(ts.to_be_bytes());
            hex::encode(hasher.finalize())
        } else {
            // Metadata-based signing: {operation}:{resource}:{timestamp}
            let metadata = RequestMetadata {
                timestamp: ts,
                operation: operation.to_string(),
                resource: resource.to_string(),
            };
            metadata.signing_message()
        };

        auth_service
            .verify_request_signature(token, signature, &message, timestamp)
            .await
            .map_err(|e| {
                StateNodeError::AuthenticationFailed(format!(
                    "Signature verification failed: {}",
                    e
                ))
            })
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// Get the addresses this node is listening on.
    pub async fn listen_addrs(&self) -> Vec<String> {
        self.peer_network.listen_addrs().await
    }

    /// Classify a relay error message into the appropriate StateNodeError.
    ///
    /// When a member node returns an error during relay, the error message is
    /// wrapped in P2P protocol layers. This method parses the message to
    /// preserve the original error semantics (e.g., 403 vs 500).
    fn classify_relay_error(message: String) -> StateNodeError {
        if message.contains("Authorization failed") {
            StateNodeError::AuthorizationFailed(message)
        } else if message.contains("Authentication failed") {
            StateNodeError::AuthenticationFailed(message)
        } else {
            StateNodeError::NetworkError(NetworkError::ConnectionFailed(message))
        }
    }

    /// Register a new node.
    ///
    /// This publishes the NodeCreated event both locally and to the network.
    pub async fn register_node(
        &self,
        total_capacity: u64,
    ) -> Result<(NodeSnapshot, Vec<Event>), StateNodeError> {
        let (snapshot, events) =
            state_node::create_node(self.local_node_id.clone(), total_capacity);

        self.node_registry
            .write()
            .await
            .upsert_node(&snapshot)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

        // Publish events both locally and to the network
        for event in &events {
            self.event_publisher.publish_all(event).await.map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
            })?;
        }

        Ok((snapshot, events))
    }

    /// Create new content and assign it to nodes.
    ///
    /// The content will be assigned to other nodes in the network (not the creator).
    /// At least one member node must be available for the content to be created.
    ///
    /// The caller must provide an authentication token and request signature.
    /// The state node authenticates with monas-account and authorizes via UCAN,
    /// then creates an access policy with the authenticated identity as owner.
    pub async fn create_content(
        &self,
        data: &[u8],
        token: Option<&AuthToken>,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<Event, StateNodeError> {
        let token = token.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Authentication token is required".to_string())
        })?;
        let request_signature = request_signature.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Request signature is required".to_string())
        })?;
        let auth_service = self.auth_service.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
        })?;

        // 1. Authenticate caller
        let owner_identity = auth_service
            .authenticate(token, None)
            .await
            .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

        // 1.5. Verify request signature
        self.verify_caller_signature(
            auth_service.as_ref(),
            token,
            request_signature,
            "create",
            "content",
            timestamp,
            Some(data),
        )
        .await?;

        // 2. Skip authorization for content creation
        // New content doesn't have an access policy yet, so authorization would always fail.
        // The authenticated user becomes the owner with full permissions.

        // 3. Save content to CRDT repository first (without access policy; policy is added after genesis_cid is known)
        let commit_result = self
            .crdt_repo
            .create_content(data, &self.local_node_id, None)
            .await
            .map_err(|e| StateNodeError::CrdtError(CrdtError::StorageError(e.to_string())))?;
        let content_id = commit_result.genesis_cid;

        // 4. Find closest peers for content placement
        let key = compute_dht_key(&content_id);
        let k = 3usize;
        let closest = self
            .peer_network
            .find_closest_peers(key, k)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ConnectionFailed(e.to_string()))
            })?;
        let caps = self
            .peer_network
            .query_node_capacity_batch(&closest)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ConnectionFailed(e.to_string()))
            })?;

        // Select nodes with highest capacity, excluding the creator
        let mut scored: Vec<(u64, String)> = closest
            .into_iter()
            .filter(|peer| peer != &self.local_node_id) // Exclude creator
            .map(|peer| (caps.get(&peer).cloned().unwrap_or(0), peer))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        let selected: Vec<String> = scored.into_iter().take(k).map(|(_, pid)| pid).collect();

        // Validate that we have at least one member node
        if selected.is_empty() {
            return Err(StateNodeError::NoAvailableMembers);
        }

        // 5. Create content network with PeerId-based NodeIds
        let first_node = crate::domain::value_objects::NodeId::from_string(selected[0].clone())?;
        let mut network = ContentNetwork::new(
            crate::domain::value_objects::ContentId::new(content_id.clone())?,
            first_node,
        )?;

        // Add remaining members
        for node_id in selected.iter().skip(1) {
            let node_id_vo = crate::domain::value_objects::NodeId::from_string(node_id.clone())?;
            network.add_member(node_id_vo);
        }

        if let Err(e) = self
            .content_repo
            .write()
            .await
            .save_content_network(network)
            .await
        {
            // Rollback: CRDT content was created but network save failed.
            // Log the orphaned CRDT entry for cleanup. The CRDT data is append-only
            // so we can't delete it, but without a ContentNetwork it won't be served.
            tracing::error!(
                "Failed to save content network for {}, CRDT entry orphaned: {}",
                content_id,
                e
            );
            return Err(StateNodeError::StorageError(e.to_string()));
        }

        // 7. Create access policy for authenticated owner and embed in CRDT
        if let Err(e) = async {
            let content_id_vo = ContentId::new(content_id.clone())?;
            let policy = AccessPolicy::new(content_id_vo, owner_identity);
            self.crdt_repo
                .update_access_policy(&content_id, policy, &self.local_node_id)
                .await
                .map_err(|e| StateNodeError::CrdtError(CrdtError::StorageError(e.to_string())))
        }
        .await
        {
            // Rollback: remove the content network since access policy failed
            if let Err(cleanup_err) = self
                .content_repo
                .write()
                .await
                .delete_content_network(&content_id)
                .await
            {
                tracing::error!(
                    "Failed to rollback content network for {}: {}",
                    content_id,
                    cleanup_err
                );
            }
            return Err(e);
        }

        // 7.5. Push CRDT operations (including AccessPolicy) to member nodes
        // This ensures members have the data before the Gossipsub event triggers relay requests
        {
            let operations = self
                .crdt_repo
                .get_operations(&content_id, None)
                .await
                .map_err(|e| StateNodeError::CrdtError(CrdtError::StorageError(e.to_string())))?;

            if !operations.is_empty() {
                for member_id in &selected {
                    if let Err(e) = self
                        .peer_network
                        .push_operations(member_id, &content_id, &operations)
                        .await
                    {
                        tracing::warn!(
                            "Failed to push CRDT operations to member {}: {} (will rely on Gossipsub sync)",
                            member_id, e
                        );
                    }
                }
            }
        }

        // 8. Create and publish event both locally and to the network
        let event = Event::ContentCreated {
            content_id,
            creator_node_id: self.local_node_id.clone(),
            content_size: data.len() as u64,
            member_nodes: selected,
            timestamp: current_timestamp(),
        };

        self.event_publisher
            .publish_all(&event)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
            })?;

        Ok(event)
    }

    /// Delete content.
    ///
    /// This method:
    /// 1. Verifies the content network exists
    /// 2. If local node is a member: authenticates, authorizes, and deletes locally
    /// 3. If not a member: relays to a member node (authorization delegated to member)
    ///
    /// Note: The CRDT history and CID are preserved for:
    /// - Offline nodes to receive deletion notification via event
    /// - Historical record keeping
    ///
    /// The caller must provide an authentication token and request signature.
    /// Non-member nodes delegate authorization to the member node via relay,
    /// since access policy updates are only stored on member nodes.
    pub async fn delete_content(
        &self,
        content_id: &str,
        token: Option<&AuthToken>,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<Event, StateNodeError> {
        let token = token.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Authentication token is required".to_string())
        })?;
        let request_signature = request_signature.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Request signature is required".to_string())
        })?;

        // 1. Verify content network exists
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        // 2. Check if local node is a member
        if network.has_member_str(&self.local_node_id) {
            // Local delete path: we are a member node
            // Authenticate and authorize locally (we have the up-to-date access policy)
            let auth_service = self.auth_service.as_ref().ok_or_else(|| {
                StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
            })?;
            let authz_service = self.authz_service.as_ref().ok_or_else(|| {
                StateNodeError::InvalidConfiguration("Authorization not configured".to_string())
            })?;

            let identity = auth_service
                .authenticate(token, None)
                .await
                .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

            // Verify request signature
            self.verify_caller_signature(
                auth_service.as_ref(),
                token,
                request_signature,
                "delete",
                content_id,
                timestamp,
                None,
            )
            .await?;

            let authz_request = AuthorizationRequest {
                identity,
                resource: content_id_vo.clone(),
                capability: AuthCapability::DeleteContent,
                token: Some(token.clone()),
                request_signature: Some(request_signature.to_vec()),
            };

            let authz_result = authz_service
                .authorize(&authz_request)
                .await
                .map_err(|e| StateNodeError::AuthorizationFailed(e.to_string()))?;

            if authz_result.is_denied() {
                return Err(StateNodeError::AuthorizationFailed(
                    authz_result
                        .denial_reason()
                        .unwrap_or("Access denied")
                        .to_string(),
                ));
            }

            // 3. Delete the ContentNetwork
            self.content_repo
                .write()
                .await
                .delete_content_network(content_id)
                .await
                .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

            // 4. Create and publish ContentDeleted event
            let event = Event::ContentDeleted {
                content_id: content_id.to_string(),
                deleted_by_node_id: self.local_node_id.clone(),
                timestamp: current_timestamp(),
            };

            self.event_publisher
                .publish_all(&event)
                .await
                .map_err(|e| {
                    StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
                })?;

            Ok(event)
        } else {
            // Relay path: we are not a member, relay to a member node.
            // Authorization is delegated to the member node which has the up-to-date
            // access policy (including any grants made via invalidate_tokens).
            let members = network.member_nodes_as_strings();
            if members.is_empty() {
                return Err(StateNodeError::NoAvailableMembers);
            }

            let target_peer = &members[0];
            let success = self
                .peer_network
                .relay_delete_content(
                    target_peer,
                    content_id,
                    token.as_str(),
                    request_signature,
                    timestamp,
                )
                .await
                .map_err(|e| Self::classify_relay_error(e.to_string()))?;

            if !success {
                return Err(StateNodeError::Internal(
                    "Relay delete to member node failed".to_string(),
                ));
            }

            Ok(Event::ContentDeleted {
                content_id: content_id.to_string(),
                deleted_by_node_id: self.local_node_id.clone(),
                timestamp: current_timestamp(),
            })
        }
    }

    /// Update existing content.
    ///
    /// The caller must provide an authentication token and request signature.
    /// The state node authenticates with monas-account and authorizes via UCAN
    /// before updating content.
    ///
    /// Non-member nodes delegate authorization to the member node via relay,
    /// since access policy updates (e.g., invalidate_tokens) are only stored on member nodes.
    pub async fn update_content(
        &self,
        content_id: &str,
        data: &[u8],
        token: Option<&AuthToken>,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<Event, StateNodeError> {
        let token = token.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Authentication token is required".to_string())
        })?;
        let request_signature = request_signature.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Request signature is required".to_string())
        })?;

        // 1. Verify content network exists
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        // 2. Check if local node is a member
        if network.has_member_str(&self.local_node_id) {
            // Local update path: we are a member node
            // Authenticate and authorize locally (we have the up-to-date access policy)
            let auth_service = self.auth_service.as_ref().ok_or_else(|| {
                StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
            })?;
            let authz_service = self.authz_service.as_ref().ok_or_else(|| {
                StateNodeError::InvalidConfiguration("Authorization not configured".to_string())
            })?;

            let identity = auth_service
                .authenticate(token, None)
                .await
                .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

            // Verify request signature
            self.verify_caller_signature(
                auth_service.as_ref(),
                token,
                request_signature,
                "update",
                content_id,
                timestamp,
                Some(data),
            )
            .await?;

            let authz_request = AuthorizationRequest {
                identity,
                resource: content_id_vo.clone(),
                capability: AuthCapability::WriteContent,
                token: Some(token.clone()),
                request_signature: Some(request_signature.to_vec()),
            };

            let authz_result = authz_service
                .authorize(&authz_request)
                .await
                .map_err(|e| StateNodeError::AuthorizationFailed(e.to_string()))?;

            if authz_result.is_denied() {
                return Err(StateNodeError::AuthorizationFailed(
                    authz_result
                        .denial_reason()
                        .unwrap_or("Access denied")
                        .to_string(),
                ));
            }

            // 3. Update content in CRDT repository (access_policy: None preserves existing policy)
            self.crdt_repo
                .update_content(content_id, data, &self.local_node_id, None)
                .await
                .map_err(|e| StateNodeError::CrdtError(CrdtError::StorageError(e.to_string())))?;

            // 4. Create and publish update event both locally and to the network
            let event = Event::ContentUpdated {
                content_id: content_id.to_string(),
                updated_node_id: self.local_node_id.clone(),
                timestamp: current_timestamp(),
            };

            self.event_publisher
                .publish_all(&event)
                .await
                .map_err(|e| {
                    StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
                })?;

            // 5. Check and maintain redundancy (best effort - don't fail update if this fails)
            if let Err(e) = self.check_and_maintain_redundancy(content_id).await {
                tracing::warn!(
                    "Failed to check/maintain redundancy for content {}: {}",
                    content_id,
                    e
                );
            }

            Ok(event)
        } else {
            // Relay path: we are not a member, relay to a member node.
            // Authorization is delegated to the member node which has the up-to-date
            // access policy (including any grants made via invalidate_tokens).
            let members = network.member_nodes_as_strings();
            if members.is_empty() {
                return Err(StateNodeError::NoAvailableMembers);
            }

            let target_peer = &members[0];
            let success = self
                .peer_network
                .relay_update_content(
                    target_peer,
                    content_id,
                    data,
                    token.as_str(),
                    request_signature,
                    timestamp,
                )
                .await
                .map_err(|e| Self::classify_relay_error(e.to_string()))?;

            if !success {
                return Err(StateNodeError::Internal(
                    "Relay update to member node failed".to_string(),
                ));
            }

            Ok(Event::ContentUpdated {
                content_id: content_id.to_string(),
                updated_node_id: self.local_node_id.clone(),
                timestamp: current_timestamp(),
            })
        }
    }

    /// Invalidate all AuthTokens for a content by updating min_valid_issued_at.
    ///
    /// This method allows the owner of content to invalidate all previously issued
    /// AuthTokens. After invalidation, only tokens issued after the new timestamp
    /// will be accepted.
    ///
    /// # Arguments
    ///
    /// * `content_id` - The content to invalidate tokens for
    /// * `token` - Authentication token of the caller (must be owner)
    /// * `request_signature` - Optional request signature
    ///
    /// # Returns
    ///
    /// The new min_valid_issued_at timestamp on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails
    /// - Caller is not the owner of the content
    /// - Content not found
    pub async fn invalidate_tokens(
        &self,
        content_id: &str,
        token: &AuthToken,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<u64, StateNodeError> {
        // 1. Ensure auth services are configured
        let auth_service = self.auth_service.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
        })?;

        // 2. Authenticate caller
        let caller_identity = auth_service
            .authenticate(token, None)
            .await
            .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

        // 2.5. Verify request signature
        if let Some(sig) = request_signature {
            self.verify_caller_signature(
                auth_service.as_ref(),
                token,
                sig,
                "invalidate",
                content_id,
                timestamp,
                None,
            )
            .await?;
        }

        // 3. Check if this node is a member
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        if network.has_member_str(&self.local_node_id) {
            // Local path: we are a member node
            // 4. Get access policy from CRDT
            let mut policy = self
                .crdt_repo
                .get_access_policy(content_id)
                .await
                .map_err(|e| StateNodeError::StorageError(e.to_string()))?
                .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

            // 5. Verify caller is owner
            if !policy.is_owner(&caller_identity) {
                return Err(StateNodeError::AuthorizationFailed(
                    "Only the owner can invalidate tokens".to_string(),
                ));
            }

            // 6. Invalidate tokens
            let new_min = policy.invalidate_tokens();

            // 7. Save updated policy via CRDT
            self.crdt_repo
                .update_access_policy(content_id, policy, &self.local_node_id)
                .await
                .map_err(|e| StateNodeError::CrdtError(CrdtError::StorageError(e.to_string())))?;

            // 8. Sync to SledAccessControlRepository if available
            //    Use transient lock pattern: acquire → read → release → modify → re-acquire → write
            if let Some(access_control_repo) = &self.access_control_repo {
                let mut ac = {
                    let ac_repo = access_control_repo.read().await;
                    ac_repo
                        .get_access_control(content_id)
                        .await
                        .unwrap_or(None)
                        .unwrap_or_else(|| ContentAccessControl::new(content_id.to_string()))
                }; // lock released here

                if let Err(e) = ac.invalidate_before(new_min) {
                    tracing::warn!("Failed to sync invalidation to access control repo: {}", e);
                } else {
                    let ac_repo = access_control_repo.read().await;
                    if let Err(e) = ac_repo.save_access_control(&ac).await {
                        tracing::warn!("Failed to save access control to Sled: {}", e);
                    }
                }
            }

            // 9. Push CRDT operations to other member nodes
            {
                let operations = self
                    .crdt_repo
                    .get_operations(content_id, None)
                    .await
                    .map_err(|e| {
                        StateNodeError::CrdtError(CrdtError::StorageError(e.to_string()))
                    })?;

                if !operations.is_empty() {
                    let members = network.member_nodes_as_strings();
                    for member_id in &members {
                        if member_id == &self.local_node_id {
                            continue;
                        }
                        if let Err(e) = self
                            .peer_network
                            .push_operations(member_id, content_id, &operations)
                            .await
                        {
                            tracing::warn!(
                                "Failed to push invalidation operations to member {}: {} (will rely on sync)",
                                member_id, e
                            );
                        }
                    }
                }
            }

            Ok(new_min)
        } else {
            // Relay path: we are not a member, relay to a member node
            let members = network.member_nodes_as_strings();
            if members.is_empty() {
                return Err(StateNodeError::NoAvailableMembers);
            }

            let target_peer = &members[0];

            let success = self
                .peer_network
                .relay_invalidate_tokens(
                    target_peer,
                    content_id,
                    token.as_str(),
                    request_signature.unwrap_or(&[]),
                    timestamp,
                )
                .await
                .map_err(|e| Self::classify_relay_error(e.to_string()))?;

            if !success {
                return Err(StateNodeError::Internal(
                    "Relay invalidate_tokens to member node failed".to_string(),
                ));
            }

            // For relay path, we don't know the exact new_min_valid_issued_at
            // Return current timestamp as approximate value
            Ok(crate::domain::events::current_timestamp())
        }
    }

    /// Add new member nodes to a content network.
    ///
    /// This uses the same node selection pattern as create_content:
    /// find closest peers via DHT and select by capacity.
    /// Only existing members can add new members.
    /// The caller must provide an authentication token and request signature.
    pub async fn add_member_to_content(
        &self,
        content_id: &str,
        count: usize,
        token: Option<&AuthToken>,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<Event, StateNodeError> {
        let token = token.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Authentication token is required".to_string())
        })?;
        let request_signature = request_signature.ok_or_else(|| {
            StateNodeError::AuthenticationFailed("Request signature is required".to_string())
        })?;
        let auth_service = self.auth_service.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration("Authentication not configured".to_string())
        })?;
        let authz_service = self.authz_service.as_ref().ok_or_else(|| {
            StateNodeError::InvalidConfiguration("Authorization not configured".to_string())
        })?;

        // 1. Get content network
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        // 2. Verify caller is a member
        if !network.has_member_str(&self.local_node_id) {
            return Err(StateNodeError::NotAMember {
                node_id: self.local_node_id.clone(),
                content_id: content_id_vo,
            });
        }

        // 3. Authenticate and authorize
        let identity = auth_service
            .authenticate(token, None)
            .await
            .map_err(|e| StateNodeError::AuthenticationFailed(e.to_string()))?;

        // Verify request signature
        self.verify_caller_signature(
            auth_service.as_ref(),
            token,
            request_signature,
            "manage",
            content_id,
            timestamp,
            None,
        )
        .await?;

        let authz_request = AuthorizationRequest {
            identity,
            resource: content_id_vo.clone(),
            capability: AuthCapability::ManageMembers,
            token: Some(token.clone()),
            request_signature: Some(request_signature.to_vec()),
        };
        let authz_result = authz_service
            .authorize(&authz_request)
            .await
            .map_err(|e| StateNodeError::AuthorizationFailed(e.to_string()))?;
        if authz_result.is_denied() {
            return Err(StateNodeError::AuthorizationFailed(
                authz_result
                    .denial_reason()
                    .unwrap_or("Access denied")
                    .to_string(),
            ));
        }

        self.add_member_to_content_internal(content_id, count).await
    }

    async fn add_member_to_content_internal(
        &self,
        content_id: &str,
        count: usize,
    ) -> Result<Event, StateNodeError> {
        // 1. Get content network
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        // 2. Verify caller is a member
        if !network.has_member_str(&self.local_node_id) {
            return Err(StateNodeError::NotAMember {
                node_id: self.local_node_id.clone(),
                content_id: content_id_vo,
            });
        }

        // 3. Find closest peers (same pattern as create_content)
        let key = compute_dht_key(content_id);
        let k = count + network.member_count(); // Request more to filter
        let closest = self
            .peer_network
            .find_closest_peers(key, k)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ConnectionFailed(e.to_string()))
            })?;
        let caps = self
            .peer_network
            .query_node_capacity_batch(&closest)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ConnectionFailed(e.to_string()))
            })?;

        // 4. Select nodes: exclude existing members, sort by capacity
        let mut scored: Vec<(u64, String)> = closest
            .into_iter()
            .filter(|peer| !network.has_member_str(peer)) // Exclude existing members
            .map(|peer| (caps.get(&peer).cloned().unwrap_or(0), peer))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        let selected: Vec<String> = scored.into_iter().take(count).map(|(_, pid)| pid).collect();

        if selected.is_empty() {
            return Err(StateNodeError::NoAvailableMembers);
        }

        // 5. Add each node using PeerId-based NodeId
        let mut updated_network = network;
        let mut last_event = None;
        for node_id_str in &selected {
            let node_id_vo =
                crate::domain::value_objects::NodeId::from_string(node_id_str.clone())?;
            let (net, events) =
                crate::domain::content_network::add_member_node(updated_network, node_id_vo)?;
            updated_network = net;
            // Publish each event
            for event in events {
                self.event_publisher
                    .publish_all(&event)
                    .await
                    .map_err(|e| {
                        StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
                    })?;
                last_event = Some(event);
            }
        }

        // 6. Save updated network
        self.content_repo
            .write()
            .await
            .save_content_network(updated_network)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

        last_event.ok_or_else(|| StateNodeError::Internal("No events generated".to_string()))
    }

    /// Check and maintain redundancy for a content network.
    ///
    /// This method:
    /// 1. Queries capacity of all member nodes
    /// 2. Identifies nodes with low capacity (below threshold)
    /// 3. Adds new members if healthy member count < min_replication_factor
    /// 4. Removes low-capacity members after new members are added
    ///
    /// Called automatically after content updates.
    pub async fn check_and_maintain_redundancy(
        &self,
        content_id: &str,
    ) -> Result<(), StateNodeError> {
        use crate::domain::content_network::remove_member_node;

        // 1. Get content network
        let content_id_vo = ContentId::new(content_id.to_string())?;
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        // Only check if we're a member
        if !network.has_member_str(&self.local_node_id) {
            return Ok(());
        }

        // 2. Query capacity of all member nodes
        let member_list: Vec<String> = network.member_nodes_as_strings();
        let capacities = self
            .peer_network
            .query_node_capacity_batch(&member_list)
            .await
            .map_err(|e| {
                StateNodeError::NetworkError(NetworkError::ConnectionFailed(e.to_string()))
            })?;

        // 3. Identify low-capacity nodes
        let mut low_capacity_nodes: Vec<String> = Vec::new();
        let mut healthy_count = 0usize;

        for node_id in &member_list {
            let available = capacities.get(node_id).cloned().unwrap_or(0);
            if available < self.capacity_threshold_bytes {
                low_capacity_nodes.push(node_id.clone());
                tracing::info!(
                    "Node {} has low capacity ({} bytes < {} threshold)",
                    node_id,
                    available,
                    self.capacity_threshold_bytes
                );
            } else {
                healthy_count += 1;
            }
        }

        // 4. Add new members if needed
        let needed = self.min_replication_factor.saturating_sub(healthy_count);

        if needed > 0 {
            tracing::info!(
                "Content {} has {} healthy members, need {} more (min: {})",
                content_id,
                healthy_count,
                needed,
                self.min_replication_factor
            );

            // Try to add new members (ignore errors - best effort)
            match self
                .add_member_to_content_internal(content_id, needed)
                .await
            {
                Ok(event) => {
                    tracing::info!("Added new members to content {}: {:?}", content_id, event);
                }
                Err(e) => {
                    tracing::warn!("Failed to add new members to content {}: {}", content_id, e);
                }
            }
        }

        // 5. Remove low-capacity nodes (after adding new ones)
        // Re-fetch network to get updated member list
        let network = self
            .content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?
            .ok_or_else(|| StateNodeError::ContentNotFound(content_id_vo.clone()))?;

        let mut updated_network = network;
        for node_id in low_capacity_nodes {
            // Don't remove ourselves
            if node_id == self.local_node_id {
                continue;
            }

            // Don't remove if it would drop below minimum
            if updated_network.member_count() <= self.min_replication_factor {
                tracing::info!(
                    "Skipping removal of {} - would drop below minimum replication factor",
                    node_id
                );
                break;
            }

            let node_id_vo = crate::domain::value_objects::NodeId::from_string(node_id.clone())?;
            let (net, events) =
                remove_member_node(updated_network, node_id_vo, "low_capacity".to_string());
            updated_network = net;

            for event in events {
                self.event_publisher
                    .publish_all(&event)
                    .await
                    .map_err(|e| {
                        StateNodeError::NetworkError(NetworkError::ProtocolError(e.to_string()))
                    })?;
                tracing::info!(
                    "Removed low-capacity member {} from content {}",
                    node_id,
                    content_id
                );
            }
        }

        // 6. Save updated network
        self.content_repo
            .write()
            .await
            .save_content_network(updated_network)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Verify that the event's claimed node ID matches the source peer ID.
    /// Returns an error if there is a mismatch.
    fn verify_source_peer_id(
        source_peer_id: Option<&str>,
        claimed_node_id: &str,
    ) -> Result<(), StateNodeError> {
        if let Some(source) = source_peer_id {
            if source != claimed_node_id {
                tracing::warn!(
                    "Source PeerID mismatch: event claims node_id={}, but source={}",
                    claimed_node_id,
                    source
                );
                return Err(StateNodeError::Internal(format!(
                    "Source PeerID mismatch: claimed={}, actual={}",
                    claimed_node_id, source
                )));
            }
        }
        Ok(())
    }

    /// Handle a sync event from another node.
    ///
    /// The `source_peer_id` parameter is used to verify that events claiming
    /// to be from a particular node actually came from that peer's PeerID.
    ///
    /// Returns `ApplyOutcome::NeedsSync` when the caller should perform content
    /// synchronization (e.g., call `ContentSyncService::sync_from_peers`).
    pub async fn handle_sync_event(
        &self,
        event: &Event,
        source_peer_id: Option<&str>,
    ) -> Result<ApplyOutcome, StateNodeError> {
        match event {
            Event::ContentUpdated {
                content_id,
                updated_node_id,
                ..
            } => {
                // Verify source PeerID matches claimed node ID
                Self::verify_source_peer_id(source_peer_id, updated_node_id)?;

                // Skip if we sent this update ourselves
                if updated_node_id == &self.local_node_id {
                    return Ok(ApplyOutcome::Ignored);
                }

                // Ensure content network exists
                let network = self
                    .content_repo
                    .read()
                    .await
                    .get_content_network(content_id)
                    .await
                    .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

                match network {
                    Some(net) => {
                        // If we're a member of this content network, we need to sync
                        if net.has_member_str(&self.local_node_id) {
                            Ok(ApplyOutcome::NeedsSync {
                                content_id: content_id.clone(),
                            })
                        } else {
                            // We're not a member, just acknowledge
                            Ok(ApplyOutcome::Applied)
                        }
                    }
                    None => {
                        // Network doesn't exist locally = we're not a member
                        // Don't create empty network, just ignore this event
                        // We'll receive ContentCreated or ContentNetworkManagerAdded
                        // when we actually become a member
                        Ok(ApplyOutcome::Ignored)
                    }
                }
            }

            Event::ContentNetworkManagerAdded {
                content_id,
                member_nodes,
                ..
            } => {
                // When handling sync events, we create network with NodeIds directly
                let content_id_vo = ContentId::new(content_id.clone())?;

                let first_node =
                    crate::domain::value_objects::NodeId::from_string(member_nodes[0].clone())?;
                let mut network = ContentNetwork::new(content_id_vo, first_node)?;

                for node_id in member_nodes.iter().skip(1) {
                    let node_id_vo =
                        crate::domain::value_objects::NodeId::from_string(node_id.clone())?;
                    network.add_member(node_id_vo);
                }
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await
                    .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

                // If we're now a member, we need to sync the content
                if member_nodes.contains(&self.local_node_id) {
                    Ok(ApplyOutcome::NeedsSync {
                        content_id: content_id.clone(),
                    })
                } else {
                    Ok(ApplyOutcome::Applied)
                }
            }

            Event::ContentNetworkManagerRemoved {
                content_id,
                member_nodes,
                removed_node_id,
                ..
            } => {
                // Update local network with new member list
                // When handling sync events, we create network with NodeIds directly
                let content_id_vo = ContentId::new(content_id.clone())?;

                let first_node =
                    crate::domain::value_objects::NodeId::from_string(member_nodes[0].clone())?;
                let mut network = ContentNetwork::new(content_id_vo, first_node)?;

                for node_id in member_nodes.iter().skip(1) {
                    let node_id_vo =
                        crate::domain::value_objects::NodeId::from_string(node_id.clone())?;
                    network.add_member(node_id_vo);
                }
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await
                    .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

                // If we were removed, log it
                if removed_node_id == &self.local_node_id {
                    tracing::info!(
                        "This node was removed from content network {}: removed_node_id={}",
                        content_id,
                        removed_node_id
                    );
                }

                Ok(ApplyOutcome::Applied)
            }

            Event::ContentCreated {
                content_id,
                member_nodes,
                ..
            } => {
                // When handling sync events, we create network with NodeIds directly
                let content_id_vo = ContentId::new(content_id.clone())?;

                let first_node =
                    crate::domain::value_objects::NodeId::from_string(member_nodes[0].clone())?;
                let mut network = ContentNetwork::new(content_id_vo, first_node)?;

                for node_id in member_nodes.iter().skip(1) {
                    let node_id_vo =
                        crate::domain::value_objects::NodeId::from_string(node_id.clone())?;
                    network.add_member(node_id_vo);
                }
                self.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await
                    .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

                // If we're a member of this new content, we need to sync it
                if member_nodes.contains(&self.local_node_id) {
                    Ok(ApplyOutcome::NeedsSync {
                        content_id: content_id.clone(),
                    })
                } else {
                    Ok(ApplyOutcome::Applied)
                }
            }

            Event::NodeCreated {
                node_id,
                total_capacity,
                available_capacity,
                ..
            } => {
                let snapshot = NodeSnapshot {
                    node_id: node_id.clone(),
                    total_capacity: *total_capacity,
                    available_capacity: *available_capacity,
                };
                self.node_registry
                    .write()
                    .await
                    .upsert_node(&snapshot)
                    .await
                    .map_err(|e| StateNodeError::StorageError(e.to_string()))?;
                Ok(ApplyOutcome::Applied)
            }

            Event::ContentDeleted {
                content_id,
                deleted_by_node_id,
                ..
            } => {
                // Verify source PeerID matches claimed node ID
                Self::verify_source_peer_id(source_peer_id, deleted_by_node_id)?;

                // Skip if we initiated the deletion
                if deleted_by_node_id == &self.local_node_id {
                    return Ok(ApplyOutcome::Ignored);
                }

                // Delete the local ContentNetwork if it exists
                // This handles the case where an offline node receives the deletion event
                // NOTE: We acquire read and write locks separately to avoid holding the
                // read guard across the write acquisition, which would deadlock since
                // tokio::sync::RwLock is non-reentrant.
                let exists = self
                    .content_repo
                    .read()
                    .await
                    .get_content_network(content_id)
                    .await
                    .ok()
                    .flatten()
                    .is_some();

                if exists {
                    self.content_repo
                        .write()
                        .await
                        .delete_content_network(content_id)
                        .await
                        .map_err(|e| StateNodeError::StorageError(e.to_string()))?;
                    tracing::info!(
                        "Content {} deleted by node {}, removed local ContentNetwork",
                        content_id,
                        deleted_by_node_id
                    );
                }

                Ok(ApplyOutcome::Applied)
            }

            _ => Ok(ApplyOutcome::Ignored),
        }
    }

    /// Get node info.
    pub async fn get_node(&self, node_id: &str) -> Result<Option<NodeSnapshot>, StateNodeError> {
        self.node_registry
            .read()
            .await
            .get_node(node_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))
    }

    /// List all nodes.
    pub async fn list_nodes(&self) -> Result<Vec<String>, StateNodeError> {
        self.node_registry
            .read()
            .await
            .list_nodes()
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))
    }

    /// List all content networks.
    pub async fn list_content_networks(&self) -> Result<Vec<String>, StateNodeError> {
        self.content_repo
            .read()
            .await
            .list_content_networks()
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))
    }

    /// Get content network info (test-only).
    ///
    /// This method is only available in tests to verify internal state.
    /// It is not exposed via HTTP API to prevent information leakage.
    #[cfg(test)]
    pub(crate) async fn get_content_network_for_test(
        &self,
        content_id: &str,
    ) -> Result<Option<ContentNetwork>> {
        self.content_repo
            .read()
            .await
            .get_content_network(content_id)
            .await
    }

    // ========================================================================
    // Access Control Methods (AuthToken support)
    // ========================================================================

    /// Verify if a AuthToken is valid for accessing content.
    ///
    /// This method checks:
    /// 1. The token's issued_at (iat) is >= min_valid_issued_at for the content
    /// 2. The content exists
    ///
    /// Returns Ok(true) if access is allowed, Ok(false) if denied.
    pub async fn verify_access(
        &self,
        content_id: &str,
        token_iat: u64,
    ) -> Result<bool, StateNodeError> {
        let ac_repo = match &self.access_control_repo {
            Some(repo) => repo,
            None => {
                // No access control repository configured, allow all access
                return Ok(true);
            }
        };

        // Get access control state
        let access_control = ac_repo
            .read()
            .await
            .get_access_control(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

        match access_control {
            Some(ac) => {
                // Check if token is valid
                Ok(ac.is_token_valid(token_iat))
            }
            None => {
                // No access control state = no restrictions
                Ok(true)
            }
        }
    }

    /// Get access control state for a content.
    pub async fn get_access_control(
        &self,
        content_id: &str,
    ) -> Result<Option<ContentAccessControl>, StateNodeError> {
        let ac_repo = match &self.access_control_repo {
            Some(repo) => repo,
            None => return Ok(None),
        };

        ac_repo
            .read()
            .await
            .get_access_control(content_id)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))
    }

    /// Update access control for a content.
    ///
    /// This method:
    /// 1. Verifies the signature on the update request (monas-account/P256)
    /// 2. Authenticates and authorizes via UCAN
    /// 3. Applies the update if valid
    /// 4. Persists the new state
    pub async fn update_access_control(
        &self,
        update: &AccessControlUpdate,
        token: Option<&AuthToken>,
        request_signature: Option<&[u8]>,
        timestamp: Option<u64>,
    ) -> Result<ContentAccessControl, AccessControlError> {
        let ac_repo = match &self.access_control_repo {
            Some(repo) => repo,
            None => {
                return Err(AccessControlError::ContentNotFound);
            }
        };

        let token = token.ok_or(AccessControlError::InvalidSignature)?;
        let request_signature = request_signature.ok_or(AccessControlError::InvalidSignature)?;
        let auth_service = self
            .auth_service
            .as_ref()
            .ok_or(AccessControlError::NotAuthorized)?;
        let authz_service = self
            .authz_service
            .as_ref()
            .ok_or(AccessControlError::NotAuthorized)?;

        if update.signature().is_empty() || update.signer_public_key().is_empty() {
            return Err(AccessControlError::InvalidSignature);
        }

        verify_p256_signature(
            update.signing_message().as_slice(),
            update.signature(),
            update.signer_public_key(),
        )
        .map_err(|_| AccessControlError::InvalidSignature)?;

        let identity = auth_service
            .authenticate(token, None)
            .await
            .map_err(|_| AccessControlError::NotAuthorized)?;

        // Verify request signature
        self.verify_caller_signature(
            auth_service.as_ref(),
            token,
            request_signature,
            "revoke",
            &update.content_id,
            timestamp,
            None,
        )
        .await
        .map_err(|_| AccessControlError::InvalidSignature)?;

        let content_id_vo = ContentId::new(update.content_id.clone())
            .map_err(|_| AccessControlError::NotAuthorized)?;
        let authz_request = AuthorizationRequest {
            identity,
            resource: content_id_vo,
            capability: AuthCapability::RevokeAccess,
            token: Some(token.clone()),
            request_signature: Some(request_signature.to_vec()),
        };
        let authz_result = authz_service
            .authorize(&authz_request)
            .await
            .map_err(|_| AccessControlError::NotAuthorized)?;
        if authz_result.is_denied() {
            return Err(AccessControlError::NotAuthorized);
        }

        // 1. Get or create access control state
        let mut access_control = ac_repo
            .read()
            .await
            .get_access_control(&update.content_id)
            .await
            .map_err(|_| AccessControlError::ContentNotFound)?
            .unwrap_or_else(|| ContentAccessControl::new(update.content_id.clone()));

        // 3. Apply the update
        access_control.invalidate_before(update.new_min_valid_issued_at)?;

        // 4. Persist the new state
        ac_repo
            .write()
            .await
            .save_access_control(&access_control)
            .await
            .map_err(|_| AccessControlError::ContentNotFound)?;

        Ok(access_control)
    }

    /// Initialize access control for a new content.
    ///
    /// Called when content is created to set up initial access control state.
    pub async fn init_access_control(
        &self,
        content_id: &str,
    ) -> Result<ContentAccessControl, StateNodeError> {
        let ac_repo = match &self.access_control_repo {
            Some(repo) => repo,
            None => {
                // Return a default state if no repo is configured
                return Ok(ContentAccessControl::new(content_id.to_string()));
            }
        };

        let access_control = ContentAccessControl::new(content_id.to_string());
        ac_repo
            .write()
            .await
            .save_access_control(&access_control)
            .await
            .map_err(|e| StateNodeError::StorageError(e.to_string()))?;

        Ok(access_control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::authentication_service::AuthenticationService;
    use crate::port::authorization_service::{AuthorizationResult, AuthorizationService};
    use crate::test_utils::{
        create_test_network, MockContentNetworkRepository, MockContentRepository,
        MockEventPublisher, MockNodeRegistry, MockPeerNetwork,
    };
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    struct TestAuthService;

    #[async_trait::async_trait]
    impl AuthenticationService for TestAuthService {
        async fn authenticate(
            &self,
            token: &AuthToken,
            _context: Option<&crate::port::auth_token::AuthContext>,
        ) -> Result<Identity> {
            Identity::user(token.as_str().to_string()).map_err(|e| anyhow::anyhow!(e.to_string()))
        }

        async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
            Ok(!token.is_empty())
        }

        async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
            Ok(Some(
                Identity::user(token.as_str().to_string())
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            ))
        }
    }

    struct AllowAllAuthorizationService;

    #[async_trait::async_trait]
    impl AuthorizationService for AllowAllAuthorizationService {
        async fn authorize(&self, _request: &AuthorizationRequest) -> Result<AuthorizationResult> {
            Ok(AuthorizationResult::Granted)
        }
    }

    fn test_token() -> AuthToken {
        AuthToken::new("test-user".to_string())
    }

    fn test_request_signature() -> Vec<u8> {
        vec![0x01]
    }

    type TestService = StateNodeService<
        MockNodeRegistry,
        MockContentNetworkRepository,
        MockPeerNetwork,
        MockEventPublisher,
        MockContentRepository,
        NoOpAccessControlRepository,
    >;

    fn create_test_service(local_node_id: &str) -> TestService {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(MockContentNetworkRepository::new()));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id(local_node_id));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            local_node_id.to_string(),
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService)
    }

    fn create_service_with_peers(
        local_node_id: &str,
        peers: Vec<String>,
        capacities: HashMap<String, u64>,
    ) -> TestService {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(MockContentNetworkRepository::new()));
        let peer_network = Arc::new(
            MockPeerNetwork::new()
                .with_local_peer_id(local_node_id)
                .with_closest_peers(peers)
                .with_capacities(capacities),
        );
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            local_node_id.to_string(),
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService)
    }

    #[tokio::test]
    async fn test_local_node_id() {
        let service = create_test_service("node-1");
        assert_eq!(service.local_node_id(), "node-1");
    }

    #[tokio::test]
    async fn test_register_node() {
        let service = create_test_service("node-1");

        let (snapshot, events) = service.register_node(1000).await.unwrap();

        assert_eq!(snapshot.node_id, "node-1");
        assert_eq!(snapshot.total_capacity, 1000);
        assert_eq!(snapshot.available_capacity, 1000);
        assert_eq!(events.len(), 1);

        // Verify node was stored
        let stored_node = service.get_node("node-1").await.unwrap();
        assert!(stored_node.is_some());
        assert_eq!(stored_node.unwrap().total_capacity, 1000);
    }

    #[tokio::test]
    async fn test_register_node_publishes_event() {
        let service = create_test_service("node-1");

        let (_, events) = service.register_node(1000).await.unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::NodeCreated {
                node_id,
                total_capacity,
                available_capacity,
                ..
            } => {
                assert_eq!(node_id, "node-1");
                assert_eq!(*total_capacity, 1000);
                assert_eq!(*available_capacity, 1000);
            }
            _ => panic!("Expected NodeCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_with_peers() {
        let mut capacities = HashMap::new();
        capacities.insert("peer-1".to_string(), 500);
        capacities.insert("peer-2".to_string(), 1000);

        let service = create_service_with_peers(
            "node-1",
            vec!["peer-1".to_string(), "peer-2".to_string()],
            capacities,
        );

        let event = service
            .create_content(
                b"test data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await
            .unwrap();

        match event {
            Event::ContentCreated {
                creator_node_id,
                member_nodes,
                content_size,
                ..
            } => {
                assert_eq!(creator_node_id, "node-1");
                assert!(!member_nodes.is_empty());
                assert_eq!(content_size, 9); // "test data" length
            }
            _ => panic!("Expected ContentCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_excludes_creator() {
        let mut capacities = HashMap::new();
        capacities.insert("node-1".to_string(), 1000); // Creator
        capacities.insert("peer-1".to_string(), 500);

        let service = create_service_with_peers(
            "node-1",
            vec!["node-1".to_string(), "peer-1".to_string()],
            capacities,
        );

        let event = service
            .create_content(
                b"test data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await
            .unwrap();

        match event {
            Event::ContentCreated { member_nodes, .. } => {
                // Creator should be excluded from members
                assert!(!member_nodes.contains(&"node-1".to_string()));
                assert!(member_nodes.contains(&"peer-1".to_string()));
            }
            _ => panic!("Expected ContentCreated event"),
        }
    }

    #[tokio::test]
    async fn test_create_content_fails_without_peers() {
        let service = create_test_service("node-1");

        let result = service
            .create_content(
                b"test data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No available member nodes found"));
    }

    #[tokio::test]
    async fn test_update_content_success() {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        // Pre-populate CRDT repo
        crdt_repo
            .contents
            .lock()
            .await
            .insert("content-1".to_string(), b"old data".to_vec());

        let service: TestService = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService);

        let event = service
            .update_content(
                "content-1",
                b"new data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await
            .unwrap();

        match event {
            Event::ContentUpdated {
                content_id,
                updated_node_id,
                ..
            } => {
                assert_eq!(content_id, "content-1");
                assert_eq!(updated_node_id, "node-1");
            }
            _ => panic!("Expected ContentUpdated event"),
        }
    }

    #[tokio::test]
    async fn test_update_content_relay_when_not_member() {
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-2", "node-3"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service: TestService = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        )
        .with_authentication_service(TestAuthService)
        .with_authorization_service(AllowAllAuthorizationService);

        // When not a member, the update should be relayed to a member node
        let result = service
            .update_content(
                "content-1",
                b"new data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await;

        // Should succeed via relay
        assert!(result.is_ok());
        match result.unwrap() {
            Event::ContentUpdated {
                content_id,
                updated_node_id,
                ..
            } => {
                assert_eq!(content_id, "content-1");
                assert_eq!(updated_node_id, "node-1");
            }
            _ => panic!("Expected ContentUpdated event"),
        }
    }

    #[tokio::test]
    async fn test_update_content_fails_if_network_not_found() {
        let service = create_test_service("node-1");

        let result = service
            .update_content(
                "nonexistent",
                b"data",
                Some(&test_token()),
                Some(&test_request_signature()),
                None,
            )
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Content not found"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_node_created() {
        let service = create_test_service("node-1");

        let event = Event::NodeCreated {
            node_id: "node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 1500,
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);

        // Verify node was stored
        let stored = service.get_node("node-2").await.unwrap().unwrap();
        assert_eq!(stored.total_capacity, 2000);
        assert_eq!(stored.available_capacity, 1500);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_created_as_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-2".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );

        // Verify content network was stored
        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert!(network.has_member_str("node-1"));
        assert!(network.has_member_str("node-2"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_created_not_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-2".to_string(),
            content_size: 100,
            member_nodes: vec!["node-2".to_string(), "node-3".to_string()], // node-1 not included
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is NOT a member, so just Applied
        assert_eq!(outcome, ApplyOutcome::Applied);

        // Verify content network was stored
        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert!(!network.has_member_str("node-1"));
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_ignores_unknown_network() {
        let service = create_test_service("node-1");

        // ContentUpdated for a content we don't know about
        let event = Event::ContentUpdated {
            content_id: "new-content".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // Network doesn't exist locally = we're not a member, just ignore
        assert_eq!(outcome, ApplyOutcome::Ignored);

        // Verify network was NOT created
        let network = service
            .get_content_network_for_test("new-content")
            .await
            .unwrap();
        assert!(network.is_none());
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_as_member_needs_sync() {
        // Create service with pre-existing content network where node-1 is a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service: TestService = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        // ContentUpdated from another node
        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_ignores_self() {
        // Create service with pre-existing content network where node-1 is a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-1", "node-2"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service: TestService = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        // ContentUpdated from ourselves - should be ignored
        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-1".to_string(), // Same as local node
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // Should be ignored since we sent it
        assert_eq!(outcome, ApplyOutcome::Ignored);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_updated_not_member() {
        // Create service with pre-existing content network where node-1 is NOT a member
        let node_registry = MockNodeRegistry::new();
        let content_repo = Arc::new(RwLock::new(
            MockContentNetworkRepository::new()
                .with_network(create_test_network("content-1", vec!["node-2", "node-3"])),
        ));
        let peer_network = Arc::new(MockPeerNetwork::new().with_local_peer_id("node-1"));
        let event_publisher = MockEventPublisher::new();
        let crdt_repo = Arc::new(MockContentRepository::new());

        let service: TestService = StateNodeService::new(
            node_registry,
            content_repo,
            peer_network,
            event_publisher,
            crdt_repo,
            "node-1".to_string(),
        );

        let event = Event::ContentUpdated {
            content_id: "content-1".to_string(),
            updated_node_id: "node-2".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is NOT a member, so just Applied (no sync needed)
        assert_eq!(outcome, ApplyOutcome::Applied);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_network_manager_added_as_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentNetworkManagerAdded {
            content_id: "content-1".to_string(),
            added_node_id: "node-3".to_string(),
            member_nodes: vec![
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string(),
            ],
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is a member, so it should need sync
        assert_eq!(
            outcome,
            ApplyOutcome::NeedsSync {
                content_id: "content-1".to_string()
            }
        );

        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(network.member_count(), 3);
    }

    #[tokio::test]
    async fn test_handle_sync_event_content_network_manager_added_not_member() {
        let service = create_test_service("node-1");

        let event = Event::ContentNetworkManagerAdded {
            content_id: "content-1".to_string(),
            added_node_id: "node-3".to_string(),
            member_nodes: vec!["node-2".to_string(), "node-3".to_string()], // node-1 not included
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        // node-1 is NOT a member
        assert_eq!(outcome, ApplyOutcome::Applied);

        let network = service
            .get_content_network_for_test("content-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(network.member_count(), 2);
    }

    #[tokio::test]
    async fn test_handle_sync_event_unknown_event_ignored() {
        let service = create_test_service("node-1");

        let event = Event::AssignmentDecided {
            assigning_node_id: "node-1".to_string(),
            assigned_node_id: "node-2".to_string(),
            content_id: "content-1".to_string(),
            timestamp: 12345,
        };

        let outcome = service.handle_sync_event(&event, None).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Ignored);
    }

    #[tokio::test]
    async fn test_list_nodes() {
        let service = create_test_service("node-1");

        // Register some nodes
        service.register_node(1000).await.unwrap();

        // Handle sync event to add another node
        let event = Event::NodeCreated {
            node_id: "node-2".to_string(),
            total_capacity: 2000,
            available_capacity: 2000,
            timestamp: 12345,
        };
        service.handle_sync_event(&event, None).await.unwrap();

        let nodes = service.list_nodes().await.unwrap();
        assert!(nodes.contains(&"node-1".to_string()));
        assert!(nodes.contains(&"node-2".to_string()));
    }

    #[tokio::test]
    async fn test_list_content_networks() {
        let service = create_test_service("node-1");

        // Add content networks via sync events
        let event1 = Event::ContentCreated {
            content_id: "content-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12345,
        };
        let event2 = Event::ContentCreated {
            content_id: "content-2".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 200,
            member_nodes: vec!["node-1".to_string()],
            timestamp: 12346,
        };

        service.handle_sync_event(&event1, None).await.unwrap();
        service.handle_sync_event(&event2, None).await.unwrap();

        let networks = service.list_content_networks().await.unwrap();
        assert!(networks.contains(&"content-1".to_string()));
        assert!(networks.contains(&"content-2".to_string()));
    }

    #[tokio::test]
    async fn test_get_content_network_not_found() {
        let service = create_test_service("node-1");

        let result = service
            .get_content_network_for_test("nonexistent")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_not_found() {
        let service = create_test_service("node-1");

        let result = service.get_node("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
