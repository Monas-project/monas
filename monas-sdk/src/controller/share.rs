use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::common::{
    decode_base64url, encode_base64url, generate_trace_id, ApiError, ApiResponse,
    StateNodeAuthContext,
};
use crate::models::share::{
    DecryptSharedContentInput, DecryptSharedContentOutput, DelegatedAccessToken, KeyEnvelope,
    Permission, ReissuedDelegatedToken, ReissuedKeyEnvelope, RevokeShareInput, RevokeShareOutput,
    ShareContentInput, ShareContentOutput, UpdateSharePermissionInput, UpdateSharePermissionOutput,
    UpdateSharedContentInput, UpdateSharedContentOutput,
};
use crate::models::state_node::StateNodeUpdateContentRequest;

use monas_account::application_service::{IssueDelegatedTokenError, IssueDelegatedTokenRequest};
use monas_account::domain::delegation::DelegatedCapability;

use monas_content::application_service::content_service::{
    ContentEncryptionKeyStore, ContentRepository, DecryptWithCekError, ReencryptContentCommand,
    ReencryptError,
};
use monas_content::application_service::share_service::{
    GrantShareCommand, RevokeShareCommand, ShareApplicationError, ShareRepository, ShareService,
    UpdateSharePermissionCommand,
};
use monas_content::domain::content::{Content, ContentEncryptionKey};
use monas_content::domain::content_id::ContentId;
use monas_content::domain::share::{
    key_envelope::{KeyEnvelope as DomainKeyEnvelope, KeyWrapAlgorithm, WrappedRecipientKey},
    KeyId, Permission as DomainPermission, Share,
};
use monas_content::infrastructure::{key_wrapping::HpkeV1KeyWrapping, MultiStorageRepository};

use super::MonasController;

const DEFAULT_DELEGATION_TTL_SECS: u64 = 3600;

/// Type alias for ShareService (for readability).
///
/// The share repository / CEK store / public key directory take `Arc<dyn …>`, so persistence
/// backends such as in-memory / sled can be switched at runtime.
pub(super) type ShareServiceInstance = ShareService<
    DynShareRepository,
    MultiStorageRepository,
    super::content::DynCekStore,
    DynPublicKeyDirectory,
    HpkeV1KeyWrapping,
>;

/// Dynamic type of the share repository used by the SDK.
pub(super) type DynShareRepository = std::sync::Arc<
    dyn monas_content::application_service::share_service::ShareRepository + Send + Sync,
>;

/// Dynamic type of the PublicKeyDirectory used by the SDK.
pub(super) type DynPublicKeyDirectory = std::sync::Arc<
    dyn monas_content::application_service::share_service::PublicKeyDirectory + Send + Sync,
>;

#[derive(Clone)]
struct RevokeShareLocalSnapshot {
    share: Share,
    content: Content,
    cek: ContentEncryptionKey,
}

impl MonasController {
    fn map_reencrypt_error(e: ReencryptError) -> ApiError {
        match e {
            ReencryptError::ContentNotFound => ApiError::NotFound("Content not found".into()),
            ReencryptError::ContentDeleted => ApiError::NotFound("Content is deleted".into()),
            ReencryptError::MissingContentEncryptionKey => {
                ApiError::Internal("Missing content encryption key".into())
            }
            ReencryptError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            ReencryptError::ContentRepository(err) => {
                ApiError::Internal(format!("Content repository error: {err}"))
            }
            ReencryptError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
            ReencryptError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
        }
    }

    fn validate_non_empty(field: &'static str, value: &str) -> Result<(), ApiError> {
        if value.is_empty() {
            return Err(ApiError::Validation(format!("{field} must not be empty")));
        }
        Ok(())
    }

    fn decode_base64url_field(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
        decode_base64url(value)
            .map_err(|e| ApiError::Validation(format!("Invalid {field} base64url: {e}")))
    }

    fn encode_key_id_base64url(key_id: &KeyId) -> String {
        encode_base64url(key_id.as_bytes())
    }

    /// Computes a KeyId from a public key
    fn compute_key_id_from_public_key(public_key: &[u8]) -> KeyId {
        let digest = Sha256::digest(public_key);
        let id_bytes = digest[..16].to_vec();
        KeyId::new(id_bytes)
    }

    /// Aggregates a list of SDK-model Permissions into a single Permission for ShareService
    ///
    /// - In monas-content, Write includes Read, so returns Write if there is at least one Write
    fn resolve_permission(permissions: &[Permission]) -> Result<DomainPermission, ApiError> {
        if permissions.is_empty() {
            return Err(ApiError::Validation("permissions must not be empty".into()));
        }
        if permissions.iter().any(|p| matches!(p, Permission::Write)) {
            return Ok(DomainPermission::Write);
        }
        Ok(DomainPermission::Read)
    }

    /// Picks the permission to put on the Token from the permissions recorded in the ACL
    /// (domain type). Write if there is a Write, otherwise Read. Owner is not delegated.
    fn resolve_domain_permission(perms: &[DomainPermission]) -> Option<DomainPermission> {
        if perms.iter().any(|p| matches!(p, DomainPermission::Write)) {
            Some(DomainPermission::Write)
        } else if perms.iter().any(|p| matches!(p, DomainPermission::Read)) {
            Some(DomainPermission::Read)
        } else {
            None
        }
    }

    fn to_key_envelope(domain_envelope: &DomainKeyEnvelope) -> KeyEnvelope {
        let recipient = domain_envelope.recipient();
        KeyEnvelope {
            enc: encode_base64url(recipient.enc()),
            wrapped_cek: encode_base64url(recipient.wrapped_cek()),
            ciphertext: encode_base64url(domain_envelope.ciphertext()),
            key_epoch: domain_envelope.key_epoch(),
        }
    }

    fn permission_to_capabilities(
        permission: DomainPermission,
    ) -> Result<Vec<DelegatedCapability>, ApiError> {
        match permission {
            DomainPermission::Read => Ok(vec![DelegatedCapability::Read]),
            DomainPermission::Write => Ok(vec![DelegatedCapability::Write]),
            // Delegating Owner permission is out of scope for the current phase; rejected at the
            // SDK boundary.
            DomainPermission::Owner => Err(ApiError::Validation(
                "owner permission is not supported for delegation".into(),
            )),
        }
    }

    fn map_delegation_error(error: IssueDelegatedTokenError) -> ApiError {
        match error {
            IssueDelegatedTokenError::NotFound => {
                ApiError::NotFound("stored account key not found".into())
            }
            IssueDelegatedTokenError::Validation(message) => ApiError::Validation(message),
            IssueDelegatedTokenError::UnsupportedAlgorithm(algorithm) => ApiError::Validation(
                format!("Stored account key must be P256 for delegation, got {algorithm}"),
            ),
            IssueDelegatedTokenError::KeyStore(err) => {
                ApiError::Internal(format!("account key store error: {err}"))
            }
            IssueDelegatedTokenError::InvalidKey(err) => {
                ApiError::Internal(format!("invalid account key: {err}"))
            }
            IssueDelegatedTokenError::JwtSigning(err) => {
                ApiError::Internal(format!("failed to create delegated token: {err}"))
            }
            IssueDelegatedTokenError::Time(message) => {
                ApiError::Internal(format!("failed to get system time: {message}"))
            }
        }
    }

    /// Issues a delegated Token.
    ///
    /// `min_issued_after` is the State Node's `min_valid_issued_at` (the revocation boundary
    /// advanced by revoke). The State Node only accepts Tokens with `iat > min_valid_issued_at`,
    /// so a Token issued in the same second as the revocation is invalid from the moment it is
    /// created. If it lands in the same second as the boundary, or before it due to clock skew,
    /// wait until the next second and reissue (bounded).
    fn issue_delegated_token(
        &self,
        content_id: &str,
        recipient_public_key_bytes: &[u8],
        permission: DomainPermission,
        min_issued_after: Option<u64>,
    ) -> Result<DelegatedAccessToken, ApiError> {
        const MAX_WAIT_SECS: u64 = 5;
        let capabilities = Self::permission_to_capabilities(permission)?;

        let mut waited = 0;
        loop {
            let req = IssueDelegatedTokenRequest {
                recipient_public_key: recipient_public_key_bytes.to_vec(),
                content_id: content_id.to_string(),
                capabilities: capabilities.clone(),
                ttl_secs: DEFAULT_DELEGATION_TTL_SECS,
            };

            let issued = self
                .account_service
                .issue_delegated_token(req)
                .map_err(Self::map_delegation_error)?;

            let token = DelegatedAccessToken {
                delegated_token: issued.delegated_token,
                issued_at: issued.issued_at,
                expires_at: issued.expires_at,
                jti: issued.jti,
            };
            match min_issued_after {
                Some(boundary) if token.issued_at <= boundary => {
                    let short_by = boundary - token.issued_at + 1;
                    if waited + short_by > MAX_WAIT_SECS {
                        return Err(ApiError::Internal(format!(
                            "delegated token would be issued at {} but the state node only accepts \
                             tokens issued after {}: clocks differ by more than {}s",
                            token.issued_at, boundary, MAX_WAIT_SECS
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_secs(short_by));
                    waited += short_by;
                }
                _ => return Ok(token),
            }
        }
    }

    /// Maps ShareApplicationError to ApiError
    fn map_share_error(e: ShareApplicationError) -> ApiError {
        match e {
            ShareApplicationError::ContentNotFound => {
                ApiError::NotFound("Content not found for sharing".into())
            }
            ShareApplicationError::ContentDeleted => {
                ApiError::NotFound("Content is deleted".into())
            }
            ShareApplicationError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
            ShareApplicationError::MissingContentEncryptionKey => {
                ApiError::Internal("Missing content encryption key".into())
            }
            ShareApplicationError::Share(
                monas_content::domain::share::share::ShareError::AlreadyShared,
            ) => ApiError::Conflict(
                "this recipient already has a share on the content; change its permission instead"
                    .into(),
            ),
            ShareApplicationError::Share(
                monas_content::domain::share::share::ShareError::RecipientNotFound,
            ) => ApiError::NotFound("this recipient has no share on the content".into()),
            ShareApplicationError::Share(err) => {
                ApiError::Internal(format!("Share domain error: {err:?}"))
            }
            ShareApplicationError::ContentRepository(err) => {
                ApiError::Internal(format!("Content repository error: {err}"))
            }
            ShareApplicationError::ContentEncryptionKeyStore(err) => {
                ApiError::Internal(format!("Key store error: {err}"))
            }
            ShareApplicationError::ShareRepository(err) => {
                ApiError::Internal(format!("Share repository error: {err}"))
            }
            ShareApplicationError::PublicKeyDirectory(err) => {
                ApiError::Internal(format!("Public key directory error: {err}"))
            }
            ShareApplicationError::MissingPublicKey => {
                ApiError::NotFound("Missing public key".into())
            }
            ShareApplicationError::KeyWrapping(msg) => {
                ApiError::Internal(format!("Key wrapping error: {msg}"))
            }
        }
    }

    fn capture_revoke_share_snapshot(
        &self,
        content_id: &ContentId,
    ) -> Result<RevokeShareLocalSnapshot, ApiError> {
        let share = self
            .share_service
            .get_share(content_id.clone())
            .map_err(Self::map_share_error)?
            .ok_or_else(|| ApiError::NotFound("Content not found for sharing".into()))?;

        let content = self
            .share_service
            .content_repository
            .find_by_id(content_id)
            .map_err(|e| ApiError::Internal(format!("Content repository error: {e}")))?
            .ok_or_else(|| ApiError::NotFound("Content not found".into()))?;

        let cek = self
            .share_service
            .cek_store
            .load(content_id)
            .map_err(|e| ApiError::Internal(format!("Key store error: {e}")))?
            .ok_or_else(|| ApiError::Internal("Missing content encryption key".into()))?;

        Ok(RevokeShareLocalSnapshot {
            share,
            content,
            cek,
        })
    }

    fn restore_revoke_share_snapshot(
        &self,
        snapshot: &RevokeShareLocalSnapshot,
    ) -> Result<(), ApiError> {
        self.share_service
            .share_repository
            .save(&snapshot.share)
            .map_err(|e| ApiError::Internal(format!("Share repository restore error: {e}")))?;

        let content_id = snapshot.content.series_id().clone();
        self.share_service
            .content_repository
            .save(&content_id, &snapshot.content)
            .map_err(|e| ApiError::Internal(format!("Content repository restore error: {e}")))?;

        self.share_service
            .cek_store
            .save(&content_id, &snapshot.cek)
            .map_err(|e| ApiError::Internal(format!("Key store restore error: {e}")))?;

        Ok(())
    }

    /// Shares content with another user
    ///
    /// Processing flow:
    /// 1. Validate input
    /// 2. Convert to ContentId
    /// 3. Decode the sender's public key and compute sender_key_id
    /// 4. Decode the recipient's public key
    /// 5. Convert Permission
    /// 6. Call ShareService::grant_share (adds the permission and generates the KeyEnvelope)
    /// 7. If issuing the delegated token fails, roll back the ACL with revoke_share (domain)
    /// 8. Convert the KeyEnvelope to SDK format
    /// 9. Return the result
    pub fn share_content(&self, input: ShareContentInput) -> ApiResponse<ShareContentOutput> {
        let trace_id = generate_trace_id();

        // 1. Validate input
        for (field, value) in [
            ("file_id", input.file_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
            ("sender_private_key", input.sender_private_key.as_str()),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. The file's key
        let content_id = ContentId::new(input.file_id.clone());

        // 3. Decode the sender's public key and compute sender_key_id
        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        // Sender's private key (used for sender authentication in HPKE Auth mode wrap; not stored)
        let sender_private_key_bytes =
            match Self::decode_base64url_field("sender_private_key", &input.sender_private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // 4. Decode the recipient's public key
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // Keep a copy of sender_key_id (to base64-encode later)
        let sender_key_id_for_output = sender_key_id.clone();

        // 5. Convert Permission (Write if Write is included, otherwise Read)
        let permission = match Self::resolve_permission(&input.permissions) {
            Ok(p) => p,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // This is a load-modify-save of the share settings, so serialize it with the same lock
        // as revoke / permission changes (keyed by the file's key), held through the rollback
        // on Token issuance failure.
        let _guard = self.content_revoke_locks.lock(content_id.as_str());

        // 6. Call ShareService::grant_share
        // This performs the following:
        // - Adds the permission for the recipient (saves the ACL to ShareRepository)
        // - Generates the KeyEnvelope
        let cmd = GrantShareCommand {
            content_id: content_id.clone(),
            sender_key_id,
            sender_private_key: sender_private_key_bytes.clone(),
            recipient_public_key: recipient_public_key_bytes.clone(),
            permission: permission.clone(),
        };

        let result = match self.share_service.grant_share(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        // The Token's resource is the series ID known to the State Node. No Token is issued
        // for local-only files not registered with the State Node
        // (the file's key never leaves the device).
        let delegated_access = match input.remote_content_id.as_deref().map(|remote| {
            self.issue_delegated_token(remote, &recipient_public_key_bytes, permission, None)
        }) {
            None => None,
            Some(Ok(token)) => Some(token),
            Some(Err(e)) => {
                let rollback_cmd = RevokeShareCommand {
                    content_id: content_id.clone(),
                    sender_key_id: sender_key_id_for_output.clone(),
                    sender_private_key: sender_private_key_bytes.clone(),
                    recipient_key_id: result.recipient_key_id.clone(),
                };
                if let Err(rb) = self.share_service.revoke_share(rollback_cmd) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            e,
                            rb,
                            "Delegated token issuance",
                            "issuance",
                            "rollback",
                        ),
                        trace_id,
                    );
                }
                return ApiResponse::error(e, trace_id);
            }
        };

        // 7. Convert the KeyEnvelope to SDK format
        let key_envelope = Self::to_key_envelope(&result.envelope);

        // base64url-encode sender_key_id and recipient_key_id
        let sender_key_id_b64 = Self::encode_key_id_base64url(&sender_key_id_for_output);
        let recipient_key_id_b64 = Self::encode_key_id_base64url(&result.recipient_key_id);

        // TODO: Send the Share to the State Node
        // A Share needs to be created and sent to the State Node

        let output = ShareContentOutput {
            content_id: result.envelope.content_id().as_str().to_string(),
            recipient_public_key: input.recipient_public_key,
            sender_public_key: input.sender_public_key,
            sender_key_id: sender_key_id_b64,
            recipient_key_id: recipient_key_id_b64,
            key_envelope,
            delegated_access,
            shared_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// Revokes a share of content.
    ///
    /// `auth` is the auth header forwarded to the `PUT /content/:id` sent to the State Node (sync
    /// after re-encryption). Must be `Some` in production.
    ///
    /// Processing flow:
    /// 1. Validate input
    /// 2. Convert to ContentId
    /// 3. Decode the recipient's public key and compute recipient_key_id
    /// 4. Advance the State Node's `min_valid_issued_at` to revoke all issued Tokens at once
    /// 5. Rotate the CEK and re-encrypt
    /// 6. Call ShareService::revoke_share (ACL update + reissue envelopes for remaining recipients)
    /// 7. Send the re-encrypted ciphertext to the State Node
    /// 8. Return the result
    ///
    /// Without 4, the revoked recipient's delegated write Token stays valid until its TTL expires
    /// (CEK rotation only stops decryption, not write permission).
    ///
    /// Revocation also takes down the remaining recipients' Tokens. Callers must reissue Tokens
    /// after `RevokeShareOutput::token_invalidated_at`.
    pub fn revoke_share(
        &self,
        input: RevokeShareInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<RevokeShareOutput> {
        let trace_id = generate_trace_id();

        // 1. Validate input
        for (field, value) in [
            ("file_id", input.file_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
            ("sender_private_key", input.sender_private_key.as_str()),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }
        let content_id = ContentId::new(input.file_id.clone());

        // Serialize revokes on this file (the lock is keyed by the file's key).
        // revoke is a load-modify-save spanning the ACL, CEK, local ciphertext and state node
        // state, with no version CAS anywhere. `MonasController` is shared via `Arc` by the
        // gateway and called concurrently, so without the lock two revokes read the same Share
        // and save last-writer-wins, losing one of the recipient removals (lost update). The
        // problem of different CEKs being handed out as the same key_epoch has the same cause.
        //
        // Take the lock before adopting the head and taking the snapshot: otherwise the snapshot
        // read can go stale before the lock is acquired, and a rollback on failure overwrites the
        // other revoke's result.
        //
        // The lock is in-process only. It does not prevent concurrent revokes from multiple
        // gateway processes; that requires a CAS on the state node side (current limitation).
        // Dropping the guard removes the entry from the table, so the registry does not keep
        // growing with the number of revoked contents.
        let _revoke_guard = self.content_revoke_locks.lock(content_id.as_str());

        // 2. Start by adopting the State Node's head. Versions written by recipients with
        //    delegated write are not present locally, and the later reencrypt reissues from the
        //    local plaintext, so skipping this makes revoke silently roll back that recipient's
        //    version (even if it is the revoked recipient's version, the latest state that the
        //    other remaining recipients and the owner saw is lost). Not needed without State
        //    Node integration.
        //
        //    Adopting only advances the same file's record; the file's key does not
        //    change.
        //
        //    A failed adopt does not stop the revoke: a broken head, or one that our CEK
        //    cannot open (an illegitimate writer put something there), is exactly when we want
        //    to revoke and rotate, and a writer must not be able to block revocation. Report it
        //    via `head_pull_error` instead.
        let mut head_pull_error = None;
        if let (Some(remote), Some(_)) = (input.remote_content_id.as_deref(), auth) {
            if let Err(response) = self.adopt_remote_head::<RevokeShareOutput>(
                remote,
                &input.file_id,
                auth,
                trace_id.clone(),
            ) {
                head_pull_error = Some(
                    response
                        .error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "unknown error".to_string()),
                );
            }
        }

        let snapshot = match self.capture_revoke_share_snapshot(&content_id) {
            Ok(snapshot) => snapshot,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        // Sender's private key (used for the HPKE Auth mode wrap of reissued envelopes; not stored)
        let sender_private_key_bytes =
            match Self::decode_base64url_field("sender_private_key", &input.sender_private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // 3. Decode the recipient's public key and compute recipient_key_id
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        let recipient_key_id = Self::compute_key_id_from_public_key(&recipient_public_key_bytes);

        // 3.5. First advance the state node's `min_valid_issued_at` to revoke all issued
        //      delegated Tokens at once. With CEK rotation alone, the "write Token held by the
        //      revoked recipient" stays alive until its TTL expires and can keep writing to the
        //      new state (contradicting the definition of "access revocation" in docs/design.md).
        //
        //      Why the order is invalidate → rotate: in the reverse order, the revoked
        //      recipient can write during the window between rotate and invalidate. If we
        //      revoke first, a later failure that rolls back local state only leaves an extra
        //      revocation, and the harm is limited to "remaining recipients need their Tokens
        //      reissued" (which is needed on CEK rotation anyway).
        //
        //      Without state node integration (`auth` is None, local-only tests, etc.) or for
        //      files not registered with the State Node (`remote_content_id` is None), there
        //      are no Tokens to revoke, so do nothing. The file's key never leaves the device,
        //      so it is never sent in its place.
        let state_node_content_id = input.remote_content_id.clone();
        let (token_invalidated_at, token_invalidation_reach) =
            if let (Some(remote), Some(_)) = (state_node_content_id.as_deref(), auth) {
                match self.send_invalidate_to_state_node::<RevokeShareOutput>(
                    remote,
                    auth,
                    trace_id.clone(),
                ) {
                    Ok(Some((at, reach))) => (Some(at), reach),
                    Ok(None) => (None, None),
                    // No local state has been changed yet, so no rollback is needed.
                    Err(response) => return response,
                }
            } else {
                (None, None)
            };

        // 4. First rotate the CEK and re-encrypt.
        //    ShareService::revoke_share reissues KeyEnvelopes for the remaining recipients with
        //    "the CEK and ciphertext at that point", so unless **reencrypt comes first** it hands
        //    out envelopes for the old CEK, defeating the rotation
        //    (matching the service-side step 2 assumption "after re-encryption this is the new
        //    CEK").
        let reencryption = match self.content_service.reencrypt(ReencryptContentCommand {
            content_id: content_id.clone(),
        }) {
            Ok(result) => result,
            Err(e) => {
                // reencrypt writes the old CEK back on a mid-way failure, but also restore the
                // snapshot to reliably return to pre-revoke, including the content repo state.
                //
                // TODO(pr29-followup): this path cannot be reproduced reliably through the SDK
                // public API alone, so there is no integration test. Add coverage to
                // tests/share_controller_integration_test.rs after introducing a test-hook feature.
                // See: the body of PR #45 commit 392d6f1.
                let primary = Self::map_reencrypt_error(e);
                if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            primary,
                            restore_err,
                            "Reencrypt",
                            "reencrypt",
                            "restore",
                        ),
                        trace_id,
                    );
                }
                return ApiResponse::error(primary, trace_id);
            }
        };

        // 5. Call ShareService::revoke_share (ACL update + reissue KeyEnvelopes for the
        //    remaining recipients with the new CEK and new ciphertext)
        let cmd = RevokeShareCommand {
            content_id,
            sender_key_id,
            sender_private_key: sender_private_key_bytes,
            recipient_key_id,
        };

        let result = match self.share_service.revoke_share(cmd) {
            Ok(result) => result,
            Err(e) => {
                // ShareService::revoke_share saves share_repository before generating envelopes,
                // so the ACL may already have been changed even if it fails mid-way.
                // Restore share/content/cek from the snapshot, including rolling back the
                // preceding reencrypt.
                let primary = Self::map_share_error(e);
                if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            primary,
                            restore_err,
                            "Revoke",
                            "revoke",
                            "restore",
                        ),
                        trace_id,
                    );
                }
                return ApiResponse::error(primary, trace_id);
            }
        };

        // The State Node manages content by series ID (remote_content_id).
        // Files not registered with the State Node have nowhere to be sent.
        if let Some(response) = state_node_content_id.as_deref().and_then(|remote| {
            self.send_update_to_state_node(
                remote,
                &reencryption.encrypted_content,
                auth,
                trace_id.clone(),
            )
        }) {
            if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                let primary = response.error.clone().unwrap_or_else(|| {
                    ApiError::Internal("unknown state node update failure".into())
                });
                return ApiResponse::error(
                    super::combine_rollback_failure(
                        primary,
                        restore_err,
                        "State Node revoke sync",
                        "remote",
                        "restore",
                    ),
                    trace_id,
                );
            }
            return response;
        }

        // Put the reissued envelopes for the remaining recipients (new CEK, new ciphertext) in
        // the output. The owner distributes them to each recipient, and when a recipient
        // processes one with decrypt_shared_content, its locally stored CEK is updated to the
        // rotated one.
        //
        // Step 3.5 advanced the State Node's revocation boundary, so the Tokens held by the
        // remaining recipients are revoked too. Delivering only the envelope allows decryption
        // but not reading from the State Node, so also reissue Tokens with an iat after the
        // boundary and bundle them. If issuance fails, the revoke itself has completed, so do
        // not roll back; return that recipient's `delegated_access` as `None`.
        let survivors_permissions = self
            .share_service
            .get_share(ContentId::new(input.file_id.clone()))
            .ok()
            .flatten();
        let reissued_envelopes = result
            .envelopes
            .iter()
            .map(|env| {
                let key_id = env.recipient().key_id();
                let delegated_access = survivors_permissions
                    .as_ref()
                    .and_then(|share| share.permissions_of(key_id))
                    .and_then(Self::resolve_domain_permission)
                    .and_then(|permission| {
                        self.share_service
                            .public_key_directory
                            .find_public_key(key_id)
                            .ok()
                            .flatten()
                            .map(|pk| (pk, permission))
                    })
                    .and_then(|(pk, permission)| {
                        self.issue_delegated_token(
                            state_node_content_id.as_deref()?,
                            &pk,
                            permission,
                            token_invalidated_at,
                        )
                        .ok()
                    });
                ReissuedKeyEnvelope {
                    recipient_key_id: encode_base64url(key_id.as_bytes()),
                    key_envelope: Self::to_key_envelope(env),
                    delegated_access,
                }
            })
            .collect();

        let output = RevokeShareOutput {
            content_id: result.content_id.as_str().to_string(),
            recipient_public_key: input.recipient_public_key,
            revoked: true,
            revoked_at: Some(Utc::now().to_rfc3339()),
            reissued_envelopes,
            token_invalidated_at,
            head_pull_error,
            token_invalidation_reach,
        };

        ApiResponse::success(output, trace_id)
    }

    /// Changes an existing recipient's permission between read ⇄ write.
    ///
    /// Calling `share_content` for the same recipient yields `AlreadyShared`, so until now the
    /// permission could only be changed via revoke → re-share (with CEK rotation and
    /// re-encryption). The permission is carried only on the delegated Token, and the
    /// KeyEnvelope (CEK) is unrelated to the permission, so the CEK is not rotated here.
    ///
    /// - Upgrade (read → write) / no change: just update the ACL and issue a Token with the new
    ///   permission. The old read Token remaining valid does no harm.
    /// - Downgrade (write → read): pointless unless the write Token in the recipient's hands is
    ///   stopped. The State Node cannot revoke Tokens individually (only bulk revocation via
    ///   `min_valid_issued_at`), so as with revoke, advance the boundary first, then reissue
    ///   and return Tokens with an iat after the boundary: read for this recipient, and each
    ///   other recipient's own permission for the others.
    ///
    /// Serialized with the same lock as revoke (both are a load-modify-save of the ACL).
    pub fn update_share_permission(
        &self,
        input: UpdateSharePermissionInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<UpdateSharePermissionOutput> {
        let trace_id = generate_trace_id();

        for (field, value) in [
            ("file_id", input.file_id.as_str()),
            (
                "remote_content_id",
                input.remote_content_id.as_deref().unwrap_or(""),
            ),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }
        let permission = match Self::resolve_permission(&input.permissions) {
            Ok(p) => p,
            Err(e) => return ApiResponse::error(e, trace_id),
        };
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let recipient_key_id = Self::compute_key_id_from_public_key(&recipient_public_key_bytes);
        let content_id = ContentId::new(input.file_id.clone());
        // The permission is carried only on the Token, so the State Node series ID is required
        // (validated above).
        let state_node_content_id = input.remote_content_id.clone().unwrap_or_default();

        let _guard = self.content_revoke_locks.lock(content_id.as_str());

        // The current ACL. Get the target's permission (to decide whether this is a downgrade)
        // and the list of other recipients caught up in the revocation here. Reject recipients
        // that are not shared with here.
        let current_share = match self.share_service.get_share(content_id.clone()) {
            Ok(share) => share,
            Err(e) => return ApiResponse::error(Self::map_share_error(e), trace_id),
        };
        let previous = current_share
            .as_ref()
            .and_then(|s| s.permissions_of(&recipient_key_id).map(|p| p.to_vec()))
            .and_then(|p| Self::resolve_domain_permission(&p));
        // Changing the target's permission does not change other recipients' permissions, so the
        // list from before the ACL update is enough.
        let mut others: Vec<_> = current_share
            .iter()
            .flat_map(|s| s.recipients().iter())
            .filter(|(kid, _)| **kid != recipient_key_id)
            .filter_map(|(kid, r)| {
                Self::resolve_domain_permission(r.permissions()).map(|p| (kid.clone(), p))
            })
            .collect();
        others.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let Some(previous) = previous else {
            return ApiResponse::error(
                ApiError::NotFound(
                    "this recipient has no share on the content; share it first".into(),
                ),
                trace_id,
            );
        };
        let downgrade = matches!(previous, DomainPermission::Write)
            && matches!(permission, DomainPermission::Read);
        // A downgrade advances the State Node's revocation boundary to stop the old write Token.
        // If it cannot be delivered (no auth), do not return success without stopping it.
        if downgrade && auth.is_none() {
            return ApiResponse::error(
                ApiError::Validation(
                    "a downgrade must void the recipient's write token on the state node; \
                     state node auth is required"
                        .into(),
                ),
                trace_id,
            );
        }
        // A request that does not change the permission may be a retry by a caller that lost
        // the success response of a downgrade. The first downgrade already advanced the
        // revocation boundary and the other recipients' old Tokens are no longer usable, so do
        // not revoke again but reissue and return the other recipients' Tokens too (the new
        // Tokens carry each recipient's current permission, so no permission is widened).
        let unchanged = matches!(
            (&previous, &permission),
            (DomainPermission::Read, DomainPermission::Read)
                | (DomainPermission::Write, DomainPermission::Write)
        );

        // Only on downgrade, revoke all issued Tokens at once before changing the ACL
        // (same order as revoke: revoking first means a later failure only leaves an extra
        // revocation).
        let (token_invalidated_at, token_invalidation_reach) = if downgrade && auth.is_some() {
            match self.send_invalidate_to_state_node::<UpdateSharePermissionOutput>(
                &state_node_content_id,
                auth,
                trace_id.clone(),
            ) {
                Ok(Some((at, reach))) => (Some(at), reach),
                Ok(None) => (None, None),
                Err(response) => return response,
            }
        } else {
            (None, None)
        };

        // Issue the target's Token before updating the ACL. If issuance fails, the ACL keeps the
        // original permission, so a retry redoes the same decision (for a downgrade: revoke +
        // reissue to other recipients). If the ACL were saved first, the retry would look like
        // "read → read" and would no longer return the other recipients' Tokens invalidated by
        // the first revocation.
        let delegated_access = match self.issue_delegated_token(
            &state_node_content_id,
            &recipient_public_key_bytes,
            permission.clone(),
            token_invalidated_at,
        ) {
            Ok(t) => t,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // If we revoked, the other recipients' Tokens were invalidated as collateral.
        // Return the same for an unchanged request (`unchanged` above). For the same reason as
        // the target, issue before updating the ACL, and return failure if even one cannot be
        // issued (returning an empty or incomplete list as success would leave the caller
        // unaware that those recipients lost access. The ACL is unchanged, so a retry starts
        // over from the downgrade decision).
        let reissued_tokens = if token_invalidated_at.is_some() || unchanged {
            let mut reissued = Vec::with_capacity(others.len());
            for (kid, p) in others {
                let public_key = match self
                    .share_service
                    .public_key_directory
                    .find_public_key(&kid)
                {
                    Ok(Some(pk)) => pk,
                    Ok(None) => {
                        return ApiResponse::error(
                            ApiError::Internal(format!(
                                "no public key is stored for recipient {}; \
                                 their token could not be reissued",
                                Self::encode_key_id_base64url(&kid)
                            )),
                            trace_id,
                        )
                    }
                    Err(e) => {
                        return ApiResponse::error(
                            ApiError::Internal(format!("public key lookup failed: {e}")),
                            trace_id,
                        )
                    }
                };
                let delegated_access = match self.issue_delegated_token(
                    &state_node_content_id,
                    &public_key,
                    p,
                    token_invalidated_at,
                ) {
                    Ok(t) => t,
                    Err(e) => return ApiResponse::error(e, trace_id),
                };
                reissued.push(ReissuedDelegatedToken {
                    recipient_key_id: Self::encode_key_id_base64url(&kid),
                    delegated_access: Some(delegated_access),
                });
            }
            reissued
        } else {
            Vec::new()
        };

        let result =
            match self
                .share_service
                .update_share_permission(UpdateSharePermissionCommand {
                    content_id: content_id.clone(),
                    recipient_key_id: recipient_key_id.clone(),
                    permission: permission.clone(),
                }) {
                Ok(r) => r,
                Err(e) => return ApiResponse::error(Self::map_share_error(e), trace_id),
            };

        let permissions = match result.current.first() {
            Some(DomainPermission::Write) => vec![Permission::Write],
            _ => vec![Permission::Read],
        };
        ApiResponse::success(
            UpdateSharePermissionOutput {
                content_id: result.content_id.as_str().to_string(),
                recipient_public_key: input.recipient_public_key,
                recipient_key_id: Self::encode_key_id_base64url(&result.recipient_key_id),
                permissions,
                delegated_access,
                reissued_tokens,
                token_invalidated_at,
                token_invalidation_reach,
            },
            trace_id,
        )
    }

    /// Decrypts a shared content payload
    ///
    /// Processing flow:
    /// 1. Validate input
    /// 2. Convert to ContentId
    /// 3. Decode sender_public_key and recipient_key_id
    /// 4. Verify the sender key pin (TOFU) and key generation (key_epoch):
    ///    - The first time, accept it as the sender public key candidate for this content and
    ///      pin it on successful decryption
    ///    - From the second time on, reject senders that do not match the pinned public key,
    ///      and reject envelopes older than the recorded key generation (prevents rotation
    ///      rollback replay)
    /// 5. Decode each field of the KeyEnvelope
    /// 6. Convert the KeyEnvelope to monas-content format
    /// 7. Call ShareService::unwrap_cek_from_envelope to obtain the CEK
    ///    (HPKE Auth mode: a successful unwrap proves the envelope was created by the holder
    ///    of the pinned key)
    /// 8. Call ContentService::decrypt_with_cek to decrypt the content
    /// 9. Save the CEK, sender key pin and key generation, and return the result
    pub fn decrypt_shared_content(
        &self,
        input: DecryptSharedContentInput,
    ) -> ApiResponse<DecryptSharedContentOutput> {
        let trace_id = generate_trace_id();

        // 1. Validate input
        for (field, value) in [
            ("content_id", input.content_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
            ("recipient_key_id", input.recipient_key_id.as_str()),
            ("private_key", input.private_key.as_str()),
            ("key_envelope.enc", input.key_envelope.enc.as_str()),
            (
                "key_envelope.wrapped_cek",
                input.key_envelope.wrapped_cek.as_str(),
            ),
            (
                "key_envelope.ciphertext",
                input.key_envelope.ciphertext.as_str(),
            ),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. Convert to ContentId
        let content_id = ContentId::new(input.content_id.clone());

        // 3. Decode sender_public_key and recipient_key_id
        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        let recipient_key_id_bytes =
            match Self::decode_base64url_field("recipient_key_id", &input.recipient_key_id) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let recipient_key_id = KeyId::new(recipient_key_id_bytes);

        // 4. Verify the sender key pin (TOFU) and key generation.
        //    For unwrap, prefer "the pinned key" over "the input key": as long as a pin
        //    exists, the root of verification does not move even if the caller passes a
        //    different key.
        //
        //    NOTE: the first time (no pin yet) is TOFU that trusts the caller's key as-is,
        //    not sender authentication. HPKE Auth only shows "the holder of that key created
        //    it", not "the owner created it", so a third party who knows the plaintext can
        //    take the pin before the legitimate envelope. Binding the first key to the owner
        //    identity is tracked in a separate issue as a trust anchor problem.
        // The pin is keyed by series ID. The version ID changes on edit, but the sender and key
        // generation belong to the series (see `DecryptSharedContentInput::remote_content_id`).
        let pin_key = input
            .remote_content_id
            .clone()
            .unwrap_or_else(|| input.content_id.clone());
        let pinned = match self.sender_pin_store.load(&pin_key) {
            Ok(p) => p,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("sender key pin store error: {e}")),
                    trace_id,
                );
            }
        };
        let effective_sender_public_key = match &pinned {
            None => sender_public_key_bytes.clone(),
            Some(pin) => {
                if pin.sender_public_key != sender_public_key_bytes {
                    return ApiResponse::error(
                        ApiError::Forbidden(format!(
                            "sender public key does not match the key pinned for content {} on                              first share. Rejecting the envelope: a different sender cannot                              replace the content encryption key.",
                            content_id.as_str()
                        )),
                        trace_id,
                    );
                }
                if input.key_envelope.key_epoch < pin.key_epoch {
                    return ApiResponse::error(
                        ApiError::Conflict(format!(
                            "stale key envelope: its key_epoch {} is older than the last accepted                              epoch {} for content {} (possible replay of a pre-rotation envelope).                              Ask the owner for the latest KeyEnvelope.",
                            input.key_envelope.key_epoch,
                            pin.key_epoch,
                            content_id.as_str()
                        )),
                        trace_id,
                    );
                }
                pin.sender_public_key.clone()
            }
        };

        // Decode the private key
        let private_key_bytes =
            match Self::decode_base64url_field("private_key", &input.private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // 5. Decode each field of the KeyEnvelope
        let enc = match Self::decode_base64url_field("key_envelope.enc", &input.key_envelope.enc) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };
        let wrapped_cek = match Self::decode_base64url_field(
            "key_envelope.wrapped_cek",
            &input.key_envelope.wrapped_cek,
        ) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };
        let ciphertext = match Self::decode_base64url_field(
            "key_envelope.ciphertext",
            &input.key_envelope.ciphertext,
        ) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // 6. Convert the KeyEnvelope to monas-content format
        let wrapped_recipient = WrappedRecipientKey::new(recipient_key_id, enc, wrapped_cek);
        let domain_envelope = DomainKeyEnvelope::new(
            content_id.clone(),
            KeyWrapAlgorithm::HpkeV1,
            sender_key_id,
            wrapped_recipient,
            ciphertext.clone(),
            input.key_envelope.key_epoch,
        );

        // 7. Call ShareService::unwrap_cek_from_envelope to obtain the CEK.
        //    Because of HPKE Auth mode, a successful unwrap proves the holder of
        //    effective_sender_public_key created this envelope (a fake sender's envelope fails
        //    here).
        let cek = match self.share_service.unwrap_cek_from_envelope(
            &domain_envelope,
            &private_key_bytes,
            &effective_sender_public_key,
        ) {
            Ok(cek) => cek,
            // In HPKE Auth mode, an unwrap failure can mean "sender verification failed"
            // (a fake sender's envelope / AAD tampering / key mismatch all fail here).
            Err(ShareApplicationError::KeyWrapping(msg)) => {
                return ApiResponse::error(
                    ApiError::Forbidden(format!(
                        "failed to unwrap the CEK with the expected sender public key: the \
                         envelope was not created by the pinned sender, or its fields \
                         (content_id / recipient / key_epoch) were tampered with: {msg}"
                    )),
                    trace_id,
                );
            }
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        // 8. Call ContentService::decrypt_with_cek to decrypt the content
        let raw_content: Vec<u8> =
            match self
                .content_service
                .decrypt_with_cek(content_id.clone(), cek.clone(), ciphertext)
            {
                Ok(content) => content,
                Err(e) => {
                    let error_msg = match e {
                        DecryptWithCekError::ContentIdMismatch { expected, actual } => {
                            format!(
                                "Content ID mismatch: expected {}, actual {}",
                                expected, actual
                            )
                        }
                        DecryptWithCekError::Domain(_) => "Failed to decrypt content".to_string(),
                    };
                    return ApiResponse::error(ApiError::Internal(error_msg), trace_id);
                }
            };

        // 9. Update local state (sender pin, key generation, CEK).
        //
        //    A successful unwrap + decryption is the point at which the sender and key
        //    generation are cryptographically confirmed, so only now are they applied locally.
        //
        //    The triple is kept in one record and swapped with a single compare-and-swap.
        //    Previously we "CAS the pin, then save the CEK to a separate store", but as long as
        //    it is split into two commits, processing of another generation interleaving in
        //    between can create an inconsistency like `pin = N+1, CEK = N`
        //    (the interleaving is described in the `SenderKeyPin` module doc).
        //
        //    A CAS failure means another process advanced to the same or a newer generation
        //    first, so discard our (older) triple.
        let new_pin = monas_content::application_service::share_service::SenderKeyPin {
            sender_public_key: effective_sender_public_key,
            key_epoch: input.key_envelope.key_epoch,
            cek: Some(cek.0.clone()),
        };
        //    By the time we get here, envelopes older than the recorded generation have already
        //    been rejected in step 4 (`stale key envelope`). So what remains is either "the same
        //    generation" or "a newer generation", and in both cases the CAS expected value is
        //    "exactly the record just read", so this is never a rollback.
        //
        //    The CAS runs even for the same generation so that, when the old record has no CEK
        //    (created before this fix, or the CEK save failed), it can recover by refilling the
        //    CEK at the same generation.
        //
        //    If the authoritative record is already exactly this triple, the CAS itself is
        //    unnecessary. However, the CEK cache alone may be missing, so let that update through.
        let already_current = pinned.as_ref() == Some(&new_pin);

        let should_refresh_cek_cache = if already_current {
            true
        } else {
            let advanced =
                match self
                    .sender_pin_store
                    .compare_and_save(&pin_key, pinned.as_ref(), &new_pin)
                {
                    Ok(advanced) => advanced,
                    Err(e) => {
                        return ApiResponse::error(
                            ApiError::Internal(format!(
                            "decrypted the shared content but failed to persist the sender key pin \
                             for {}: {e}. Re-process the KeyEnvelope.",
                            content_id.as_str()
                        )),
                            trace_id,
                        );
                    }
                };
            // If we lost the CAS, the winner wrote a newer (or the same) generation, so we must
            // not overwrite the cache with our CEK.
            advanced
        };

        // The CEK store is a cache derived from the authoritative record above.
        // The CEK stays local to the recipient device and never goes over the network.
        if should_refresh_cek_cache {
            if let Err(e) = self.content_service.cek_store.save(&content_id, &cek) {
                // The authoritative record contains the CEK, so even if this fails, reprocessing
                // can refill the cache. However, silently returning success would make the caller
                // believe "verified reads work on this device from now on" while they actually
                // fail with MissingKey, so return an error.
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "decrypted the shared content but failed to persist its CEK for {}: {e}. \
                         Re-process the KeyEnvelope to enable state-node reads on this device.",
                        content_id.as_str()
                    )),
                    trace_id,
                );
            }
        }

        let content_base64url = encode_base64url(&raw_content);

        let output = DecryptSharedContentOutput {
            content_id: input.content_id,
            content: content_base64url,
            version: input.version.unwrap_or_default(),
            metadata: None, // TODO: implement retrieving metadata
        };

        ApiResponse::success(output, trace_id)
    }

    /// Writes a new version to the owner's Content Network as the side that received the share.
    ///
    /// The recipient's device has no content record. All it has is the CEK that
    /// [`decrypt_shared_content`](Self::decrypt_shared_content) saved to the sender pin's
    /// authoritative record, so instead of the usual `update_content` (which requires a local
    /// record), this encrypts the plaintext with that CEK and PUTs it directly to the State
    /// Node.
    ///
    /// Authentication requires `Authorization: Bearer <delegated Token>` in `auth`. The State Node
    /// authorizes non-owner writes by the Token's capability (`content/write`) and verifies the
    /// request signature with the Token's `aud` key, so the signature is made with this
    /// gateway's account key (same message format as the owner's update) and only the
    /// Authorization is sent as the Token. If there is no Token, only read is allowed, or it
    /// has been revoked, the State Node rejects with 401/403, which is returned as-is.
    ///
    /// The new version's `local_content_id` (plaintext CID) is derived with the same rule as the
    /// owner and returned. When the owner reads this version, it does not match the current
    /// plainCid in the file's record, so the owner must read with `accept_any_version` or
    /// adopt it via pull.
    pub fn update_shared_content(
        &self,
        input: UpdateSharedContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<UpdateSharedContentOutput> {
        let trace_id = generate_trace_id();

        if let Err(e) = Self::validate_non_empty("remote_content_id", &input.remote_content_id) {
            return ApiResponse::error(e, trace_id);
        }
        let plaintext = match Self::decode_and_validate_content(&input.content, trace_id.clone()) {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };

        // Without a delegated Token, fail before reaching the State Node. The owner's update uses
        // `update_content`, so arriving here with `user:` is a caller error.
        let bearer = auth
            .and_then(|ctx| ctx.authorization.as_deref())
            .filter(|value| has_bearer_prefix(value));
        let Some(bearer) = bearer else {
            return ApiResponse::error(
                ApiError::Unauthorized(
                    "update_shared_content requires the delegated token from the share package \
                     as `Authorization: Bearer <token>`"
                        .into(),
                ),
                trace_id,
            );
        };
        let bearer = bearer.to_string();

        // Take the CEK from the sender pin's authoritative record (keyed by series ID). The CEK
        // store is only its cache, and this device generally does not know this series' version
        // IDs.
        let cek = match self.sender_pin_store.load(&input.remote_content_id) {
            Ok(Some(pin)) => match pin.cek {
                Some(bytes) => ContentEncryptionKey(bytes),
                None => {
                    return ApiResponse::error(
                        ApiError::NotFound(format!(
                            "no content encryption key is recorded for {}: re-process the \
                             owner's KeyEnvelope (decrypt_shared_content) on this device first",
                            input.remote_content_id
                        )),
                        trace_id,
                    );
                }
            },
            Ok(None) => {
                return ApiResponse::error(
                    ApiError::NotFound(format!(
                        "content {} has not been shared to this device: import the owner's \
                         share package (decrypt_shared_content) before writing to it",
                        input.remote_content_id
                    )),
                    trace_id,
                );
            }
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("sender key pin store error: {e}")),
                    trace_id,
                );
            }
        };

        let encrypted = match self.content_service.encrypt_with_cek(&cek, &plaintext) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("failed to encrypt the new version: {e:?}")),
                    trace_id,
                );
            }
        };

        // Sign the same `update:<content_id>:<ts>:<body digest>` as the owner's update with the
        // account key, and replace only the Authorization with the delegated Token.
        let signed_auth = match self.prepare_state_node_content_auth(
            auth,
            "update",
            &input.remote_content_id,
            &encrypted.ciphertext,
            &trace_id,
        ) {
            Ok(Some(mut signed)) => {
                signed.authorization = Some(bearer);
                signed
            }
            Ok(None) => {
                return ApiResponse::error(
                    ApiError::Unauthorized("State Node authentication context is required".into()),
                    trace_id,
                );
            }
            Err(response) => return response,
        };

        let request = StateNodeUpdateContentRequest {
            data: BASE64_STANDARD.encode(&encrypted.ciphertext),
        };
        if let Some(response) = self.send_signed_update_to_state_node(
            &input.remote_content_id,
            &request,
            Some(&signed_auth),
            trace_id.clone(),
        ) {
            return response;
        }

        ApiResponse::success(
            UpdateSharedContentOutput {
                remote_content_id: input.remote_content_id,
                version_id: encrypted.plain_content_id.as_str().to_string(),
                updated_at: Some(Utc::now().to_rfc3339()),
            },
            trace_id,
        )
    }
}

/// Whether `Authorization` has the form `Bearer <token>`.
///
/// Slicing the first 7 bytes with `value[..7]` panics with a char boundary violation for values
/// (non-ASCII) whose 7th byte falls in the middle of a multibyte character. `str::get` returns
/// `None` when off a boundary, so it can be treated directly as "not Bearer".
fn has_bearer_prefix(value: &str) -> bool {
    value.len() > 7
        && value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
}

#[cfg(test)]
mod bearer_prefix_tests {
    use super::has_bearer_prefix;

    #[test]
    fn accepts_a_bearer_token_in_any_case() {
        assert!(has_bearer_prefix("Bearer abc"));
        assert!(has_bearer_prefix("bearer abc"));
        assert!(has_bearer_prefix("BEARER abc"));
    }

    #[test]
    fn rejects_other_schemes_and_a_bare_prefix() {
        assert!(!has_bearer_prefix("user:deadbeef"));
        assert!(!has_bearer_prefix("Bearer "));
        assert!(!has_bearer_prefix(""));
    }

    /// Does not panic on values where the first-7-byte boundary falls mid-character.
    /// With "Bear" (4 bytes) + "éé" (2 bytes each), byte 7 falls inside the second "é".
    /// The old implementation's `value[..7]` hits a char boundary violation here.
    #[test]
    fn does_not_panic_when_byte_seven_is_inside_a_character() {
        assert!(!has_bearer_prefix("Bearéé token"));
        assert!(!has_bearer_prefix("Bearéétoken"));
        assert!(!has_bearer_prefix("日本語のトークン"));
    }
}
