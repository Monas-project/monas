use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::common::{generate_trace_id, ApiError, ApiResponse, StateNodeAuthContext};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};
use crate::models::share::{TokenInvalidationReach, UnreachedMember};
use crate::models::state_node::{
    StateNodeCreateContentRequest, StateNodeCreateContentResponse, StateNodeDeleteContentResponse,
    StateNodeErrorResponse, StateNodeInvalidateTokensResponse, StateNodeUpdateContentRequest,
    StateNodeUpdateContentResponse,
};

use monas_account::application_service::{AccountKeyStore, SignError};
use monas_account::infrastructure::key_pair::KeyAlgorithm;

use monas_content::application_service::content_service::{
    ContentEncryptionKeyStore, ContentRepository, ContentService, CreateContentCommand,
    DeleteContentCommand, DeleteError, FetchError, UpdateContentCommand, UpdateError,
};
use monas_content::domain::content::{Content, ContentEncryptionKey};
use monas_content::domain::content_id::ContentId;
use monas_content::infrastructure::{
    content_id::Sha256ContentIdGenerator,
    encryption::{Aes256GcmContentEncryption, OsRngContentEncryptionKeyGenerator},
    MultiStorageRepository,
};

use super::MonasController;

/// Type alias for ContentService (for readability).
///
/// The CEK store takes `Arc<dyn ContentEncryptionKeyStore + Send + Sync>`, so the persistence
/// backend (in-memory / sled, etc.) can be switched at runtime.
pub(super) type ContentServiceInstance = ContentService<
    Sha256ContentIdGenerator,
    MultiStorageRepository,
    OsRngContentEncryptionKeyGenerator,
    Aes256GcmContentEncryption,
    DynCekStore,
>;

/// Dynamic type of the CEK store shared by the SDK.
pub(super) type DynCekStore = std::sync::Arc<
    dyn monas_content::application_service::content_service::ContentEncryptionKeyStore
        + Send
        + Sync,
>;

#[derive(Clone)]
struct StoredContentSnapshot {
    content_id: ContentId,
    content: Content,
    cek: ContentEncryptionKey,
}

impl MonasController {
    pub(super) fn attach_state_node_auth<Any>(
        mut req: ureq::RequestBuilder<Any>,
        auth: Option<&StateNodeAuthContext>,
    ) -> ureq::RequestBuilder<Any> {
        if let Some(ctx) = auth {
            if let Some(value) = &ctx.authorization {
                req = req.header("Authorization", value);
            }
            if let Some(value) = &ctx.request_signature {
                req = req.header("X-Request-Signature", value);
            }
            if let Some(value) = ctx.request_timestamp {
                req = req.header("X-Request-Timestamp", &value.to_string());
            }
        }
        req
    }

    /// Domain separation tag. Must match `REQUEST_SIGNATURE_DOMAIN` on the State Node side.
    const REQUEST_SIGNATURE_DOMAIN: &'static str = "monas-request-v1";

    /// Builds the signing target of a request signature.
    ///
    /// Always binds to operation / resource / timestamp regardless of whether there is a body,
    /// and also includes the body's digest when present. Signature verification fails unless
    /// this matches the State Node side (`RequestMetadata::signing_message_with_body_digest`)
    /// exactly, so keep both in sync when changing it.
    fn build_request_signature_message(
        operation: &str,
        resource: &str,
        timestamp: u64,
        body: Option<&[u8]>,
    ) -> String {
        let body_digest_hex = match body {
            Some(bytes) => hex::encode(Sha256::digest(bytes)),
            None => String::new(),
        };
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            Self::REQUEST_SIGNATURE_DOMAIN,
            operation.len(),
            operation,
            resource.len(),
            resource,
            timestamp,
            body_digest_hex.len(),
            body_digest_hex,
        )
    }

    fn map_sign_error(error: SignError) -> ApiError {
        match error {
            SignError::NotFound => ApiError::NotFound("stored account key not found".into()),
            SignError::KeyStore(err) => {
                ApiError::Internal(format!("account key store error: {err}"))
            }
            SignError::InvalidKey(err) => ApiError::Internal(format!("invalid account key: {err}")),
        }
    }

    fn sign_state_node_message_with_account<T>(
        &self,
        signing_message: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<StateNodeAuthContext, ApiResponse<T>> {
        let stored = match self.account_service.key_store.load() {
            Ok(Some(stored)) => stored,
            Ok(None) => {
                return Err(ApiResponse::error(
                    ApiError::NotFound("stored account key not found".into()),
                    trace_id.to_string(),
                ));
            }
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Internal(format!("account key store error: {e}")),
                    trace_id.to_string(),
                ));
            }
        };
        if stored.algorithm != KeyAlgorithm::P256 {
            return Err(ApiResponse::error(
                ApiError::Validation(format!(
                    "Stored account key must be P256 for state node signing, got {:?}",
                    stored.algorithm
                )),
                trace_id.to_string(),
            ));
        }

        let (signature, _) = match self.account_service.sign(signing_message.as_bytes()) {
            Ok(signed) => signed,
            Err(e) => {
                return Err(ApiResponse::error(
                    Self::map_sign_error(e),
                    trace_id.to_string(),
                ));
            }
        };
        let authorization = format!("user:{}", hex::encode(stored.public_key));

        Ok(StateNodeAuthContext {
            authorization: Some(authorization),
            request_signature: Some(BASE64_STANDARD.encode(signature)),
            request_timestamp: Some(timestamp),
        })
    }

    /// Prepares the signature for a write that carries a body (create / update).
    ///
    /// `operation` / `resource` must match the values the State Node side passes to
    /// `verify_caller_signature`
    /// (create is `("create", "content")`, update is `("update", content_id)`).
    pub(super) fn prepare_state_node_content_auth<T>(
        &self,
        auth: Option<&StateNodeAuthContext>,
        operation: &str,
        resource: &str,
        content_bytes: &[u8],
        trace_id: &str,
    ) -> Result<Option<StateNodeAuthContext>, ApiResponse<T>> {
        let Some(ctx) = auth else {
            return Ok(None);
        };
        let timestamp = self.resolve_request_timestamp(ctx, trace_id)?;
        let signing_message = Self::build_request_signature_message(
            operation,
            resource,
            timestamp,
            Some(content_bytes),
        );
        self.sign_state_node_message_with_account(&signing_message, timestamp, trace_id)
            .map(Some)
    }

    pub(super) fn prepare_state_node_metadata_auth<T>(
        &self,
        auth: Option<&StateNodeAuthContext>,
        operation: &str,
        resource: &str,
        trace_id: &str,
    ) -> Result<Option<StateNodeAuthContext>, ApiResponse<T>> {
        let Some(ctx) = auth else {
            return Ok(None);
        };
        let timestamp = self.resolve_request_timestamp(ctx, trace_id)?;
        let signing_message =
            Self::build_request_signature_message(operation, resource, timestamp, None);
        self.sign_state_node_message_with_account(&signing_message, timestamp, trace_id)
            .map(Some)
    }

    pub(super) fn state_node_error_message_from_body(body: &str) -> Option<String> {
        serde_json::from_str::<StateNodeErrorResponse>(body.trim())
            .ok()
            .map(|e| e.error)
            .filter(|s| !s.is_empty())
    }

    pub(super) fn map_state_node_http_status_to_api_response<T>(
        status: u16,
        message: String,
        trace_id: String,
    ) -> ApiResponse<T> {
        match status {
            400 => ApiResponse::error(ApiError::Validation(message), trace_id),
            401 => ApiResponse::error(ApiError::Unauthorized(message), trace_id),
            403 => ApiResponse::error(ApiError::Forbidden(message), trace_id),
            404 => ApiResponse::error(ApiError::NotFound(message), trace_id),
            410 => ApiResponse::error(ApiError::Gone(message), trace_id),
            408 => ApiResponse::error(ApiError::Timeout(message), trace_id),
            409 => ApiResponse::error(ApiError::Conflict(message), trace_id),
            _ => ApiResponse::error(ApiError::Internal(message), trace_id),
        }
    }

    /// `Some(error)` if the HTTP status is not 2xx; `None` when it is 2xx.
    pub(super) fn try_state_node_http_error<T>(
        status: u16,
        body: &str,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        if (200..300).contains(&status) {
            return None;
        }
        let msg = Self::state_node_error_message_from_body(body).unwrap_or_else(|| {
            let t = body.trim();
            if t.is_empty() {
                format!("State Node returned HTTP {status}")
            } else {
                t.to_string()
            }
        });
        Some(Self::map_state_node_http_status_to_api_response(
            status, msg, trace_id,
        ))
    }

    /// Maps FetchError to ApiError
    fn map_fetch_error(e: FetchError) -> ApiError {
        match e {
            FetchError::NotFound => ApiError::NotFound("Content not found".into()),
            FetchError::Deleted => ApiError::NotFound("Content is deleted".into()),
            FetchError::MissingKey => {
                ApiError::Internal("Missing encryption key for content".into())
            }
            FetchError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            FetchError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            FetchError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
        }
    }

    /// Maps UpdateError to ApiError
    fn map_update_error(e: UpdateError) -> ApiError {
        match e {
            UpdateError::NotFound => ApiError::NotFound("Content not found".into()),
            UpdateError::Validation(msg) => ApiError::Validation(msg),
            UpdateError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            UpdateError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            UpdateError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
            UpdateError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
        }
    }

    /// Maps DeleteError to ApiError
    fn map_delete_error(e: DeleteError) -> ApiError {
        match e {
            DeleteError::NotFound => ApiError::NotFound("Content not found".into()),
            DeleteError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            DeleteError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            DeleteError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
        }
    }

    /// Validates content_id
    /// Returns Some(ApiResponse) on error, None on success
    fn validate_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    /// Validates the base64url-decoded content
    /// Returns ApiResponse<T> on error, Vec<u8> on success
    pub(super) fn decode_and_validate_content<T>(
        content_base64url: &str,
        trace_id: String,
    ) -> Result<Vec<u8>, ApiResponse<T>> {
        if content_base64url.is_empty() {
            return Err(ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            ));
        }

        let content_bytes = match URL_SAFE_NO_PAD.decode(content_base64url) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                ));
            }
        };

        if content_bytes.is_empty() {
            return Err(ApiResponse::error(
                ApiError::Validation("content must not be empty after decoding".into()),
                trace_id,
            ));
        }

        Ok(content_bytes)
    }

    fn capture_stored_content_snapshot(
        &self,
        content_id: &ContentId,
    ) -> Result<StoredContentSnapshot, ApiError> {
        let content = self
            .content_service
            .content_repository
            .find_by_id(content_id)
            .map_err(|e| ApiError::Internal(format!("Repository error: {e}")))?
            .ok_or_else(|| ApiError::NotFound("Content not found".into()))?;

        let cek = self
            .content_service
            .cek_store
            .load(content_id)
            .map_err(|e| ApiError::Internal(format!("Key store error: {e}")))?
            .ok_or_else(|| ApiError::Internal("Missing encryption key for content".into()))?;

        Ok(StoredContentSnapshot {
            content_id: content_id.clone(),
            content,
            cek,
        })
    }

    fn restore_stored_content_snapshot(
        &self,
        snapshot: &StoredContentSnapshot,
    ) -> Result<(), ApiError> {
        self.content_service
            .content_repository
            .save(&snapshot.content_id, &snapshot.content)
            .map_err(|e| ApiError::Internal(format!("Repository restore error: {e}")))?;

        self.content_service
            .cek_store
            .save(&snapshot.content_id, &snapshot.cek)
            .map_err(|e| ApiError::Internal(format!("Key store restore error: {e}")))?;

        Ok(())
    }

    fn rollback_created_content(&self, content_id: ContentId) -> Result<(), ApiError> {
        self.content_service
            .delete(DeleteContentCommand {
                content_id,
                provider: None,
            })
            .map(|_| ())
            .map_err(Self::map_delete_error)
    }

    /// Sends `POST /content` to the State Node (same contract as `http_api::create_content`).
    /// On success, returns the content_id returned by the State Node (`None` for an empty string).
    fn send_create_to_state_node<T>(
        &self,
        encrypted_content: &[u8],
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<Option<String>, ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeCreateContentRequest {
            data: encrypted_data_base64,
        };
        let request_body = match serde_json::to_string(&state_node_request) {
            Ok(body) => body,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Internal(format!(
                        "Failed to serialize State Node create request: {e}"
                    )),
                    trace_id,
                ));
            }
        };
        let signed_auth = self.prepare_state_node_content_auth(
            auth,
            "create",
            "content",
            encrypted_content,
            &trace_id,
        )?;

        let state_node_url = format!("{}/content", self.state_node_url);
        let req = Self::attach_state_node_auth(
            self.agent
                .post(&state_node_url)
                .header("Content-Type", "application/json"),
            signed_auth.as_ref(),
        );

        let resp = match req.send(request_body) {
            Ok(r) => r,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::from_ureq_error("Failed to send request to State Node", e),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        if body.trim().is_empty() {
            return Err(ApiResponse::error(
                ApiError::Internal(
                    "State Node create response is empty; expected content_id".into(),
                ),
                trace_id,
            ));
        }

        match serde_json::from_str::<StateNodeCreateContentResponse>(&body) {
            Ok(parsed) => {
                // An empty content_id is not treated as success, since it is the key required by
                // update/delete onward. Silently returning None would mass-produce "content that
                // can never be operated on again".
                if parsed.content_id.trim().is_empty() {
                    return Err(ApiResponse::error(
                        ApiError::Internal("State Node responded without content_id".into()),
                        trace_id,
                    ));
                }
                Ok(Some(parsed.content_id))
            }
            Err(e) => Err(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node create response JSON: {e}")),
                trace_id,
            )),
        }
    }

    /// Sends `PUT /content/:id` to the State Node (same contract as `http_api::update_content`).
    pub(super) fn send_update_to_state_node<T>(
        &self,
        content_id: &str,
        encrypted_content: &[u8],
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeUpdateContentRequest {
            data: encrypted_data_base64,
        };
        let signed_auth = match self.prepare_state_node_content_auth(
            auth,
            "update",
            content_id,
            encrypted_content,
            &trace_id,
        ) {
            Ok(auth) => auth,
            Err(response) => return Some(response),
        };
        self.send_signed_update_to_state_node(
            content_id,
            &state_node_request,
            signed_auth.as_ref(),
            trace_id,
        )
    }

    /// Sends `PUT /content/:id` as-is with an already-signed auth context.
    ///
    /// An owner's update reaches here via [`send_update_to_state_node`], which signs with the
    /// account key. A share recipient's update (`update_shared_content`) also signs the same
    /// message with the account key, but keeps Authorization as the delegated Token's
    /// `Bearer` rather than the owner's `user:<pubkey>`, so how the signature is attached is
    /// left to the caller.
    pub(super) fn send_signed_update_to_state_node<T>(
        &self,
        content_id: &str,
        state_node_request: &StateNodeUpdateContentRequest,
        signed_auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let request_body = match serde_json::to_string(state_node_request) {
            Ok(body) => body,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!(
                        "Failed to serialize State Node update request: {e}"
                    )),
                    trace_id,
                ));
            }
        };

        let state_node_url = format!("{}/content/{}", self.state_node_url, content_id);
        let req = Self::attach_state_node_auth(
            self.agent
                .put(&state_node_url)
                .header("Content-Type", "application/json"),
            signed_auth,
        );

        let resp = match req.send(request_body) {
            Ok(r) => r,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::from_ureq_error("Failed to send request to State Node", e),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Some(err);
        }

        if body.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<StateNodeUpdateContentResponse>(&body) {
            Ok(parsed) => {
                if !parsed.updated {
                    return Some(ApiResponse::error(
                        ApiError::Internal(
                            "State Node did not confirm content update (updated=false)".into(),
                        ),
                        trace_id,
                    ));
                }
                None
            }
            Err(e) => Some(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node update response JSON: {e}")),
                trace_id,
            )),
        }
    }

    /// Sends `POST /content/:id/access/invalidate` to the State Node
    /// (same contract as `http_api::invalidate_tokens_handler`).
    ///
    /// Advances `min_valid_issued_at` to the server time, revoking in bulk all delegated Tokens
    /// issued at or before it. Even if revoke rotates the CEK, a revoked recipient's delegated
    /// write Token stays valid until its TTL expires, so without calling this "the party that
    /// should have been revoked can keep writing to the new state".
    ///
    /// Returns `new_min_valid_issued_at` on success. On failure, returns the `ApiResponse`
    /// in `Err` (unlike the `send_*_to_state_node` family, to force the caller to always handle
    /// the result).
    pub(super) fn send_invalidate_to_state_node<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<Option<(u64, Option<TokenInvalidationReach>)>, ApiResponse<T>> {
        let state_node_url = format!(
            "{}/content/{}/access/invalidate",
            self.state_node_url, content_id
        );
        let signed_auth =
            self.prepare_state_node_metadata_auth(auth, "invalidate", content_id, &trace_id)?;
        let req = Self::attach_state_node_auth(
            self.agent
                .post(&state_node_url)
                .header("Content-Type", "application/json"),
            signed_auth.as_ref(),
        );

        let resp = match req.send("") {
            Ok(r) => r,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::from_ureq_error(
                        "Failed to send token invalidation request to State Node",
                        e,
                    ),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        if body.trim().is_empty() {
            return Ok(None);
        }

        match StateNodeInvalidateTokensResponse::from_json(&body) {
            // A state node from before the propagation report: nothing is
            // known about who has the cutoff. `None` reach, not an empty
            // (= "everyone reached") one.
            Ok(parsed) if !parsed.reports_reach => Ok(Some((parsed.new_min_valid_issued_at, None))),
            Ok(parsed) => Ok(Some((
                parsed.new_min_valid_issued_at,
                Some(TokenInvalidationReach {
                    notified_members: parsed.notified_members,
                    unreached_members: parsed
                        .unreached_members
                        .into_iter()
                        .map(|m| UnreachedMember {
                            node_id: m.node_id,
                            error: m.error,
                        })
                        .collect(),
                    relayed: parsed.relayed,
                }),
            ))),
            Err(e) => Err(ApiResponse::error(
                ApiError::Internal(format!(
                    "Invalid State Node token invalidation response JSON: {e}"
                )),
                trace_id,
            )),
        }
    }

    /// Sends `DELETE /content/:id` to the State Node (same contract as `http_api::delete_content`).
    fn send_delete_to_state_node<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let state_node_url = format!("{}/content/{}", self.state_node_url, content_id);
        let signed_auth =
            match self.prepare_state_node_metadata_auth(auth, "delete", content_id, &trace_id) {
                Ok(auth) => auth,
                Err(response) => return Some(response),
            };
        let req =
            Self::attach_state_node_auth(self.agent.delete(&state_node_url), signed_auth.as_ref());

        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::from_ureq_error("Failed to send delete request to State Node", e),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Some(err);
        }

        if body.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<StateNodeDeleteContentResponse>(&body) {
            Ok(parsed) => {
                if !parsed.deleted {
                    return Some(ApiResponse::error(
                        ApiError::Internal(
                            "State Node did not confirm content deletion (deleted=false)".into(),
                        ),
                        trace_id,
                    ));
                }
                None
            }
            Err(e) => Some(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node delete response JSON: {e}")),
                trace_id,
            )),
        }
    }
    /// Creates new content and registers it with the State Node.
    ///
    /// `auth` is the auth header forwarded to the State Node (passed through from the gateway etc.). `Some` is required in production.
    ///
    /// Flow:
    /// 1. Validate input (content, metadata.name)
    /// 2. base64url-decode the content
    /// 3. Call ContentService::create, which does:
    ///    - generate the file key (file_id) and the version's plainCid
    ///    - encrypt the content
    ///    - store the encrypted content in the repository
    ///    - store the CEK in the key store
    /// 4. Send the encrypted content to the State Node
    /// 5. Return the result
    pub fn create_content(
        &self,
        input: CreateContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<CreateContentOutput> {
        let trace_id = generate_trace_id();

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(bytes) => bytes,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                );
            }
        };

        if content_bytes.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty after decoding".into()),
                trace_id,
            );
        }

        let name = match input.metadata.as_ref().and_then(|m| m.name.clone()) {
            Some(name) => name,
            None => {
                return ApiResponse::error(
                    ApiError::Validation("metadata.name is required".into()),
                    trace_id,
                );
            }
        };

        let path = format!("/{name}");

        let content_service = &self.content_service;

        let cmd = CreateContentCommand {
            raw_content: content_bytes,
            name,
            path,
            provider: None,
        };

        let result = match content_service.create(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("Failed to create content: {e}")),
                    trace_id,
                );
            }
        };

        let remote_content_id =
            match self.send_create_to_state_node(&result.encrypted_content, auth, trace_id.clone())
            {
                Ok(remote_content_id) => remote_content_id,
                Err(response) => {
                    if let Err(rollback_err) =
                        self.rollback_created_content(result.series_id.clone())
                    {
                        let primary = response.error.clone().unwrap_or_else(|| {
                            ApiError::Internal("unknown state node create failure".into())
                        });
                        return ApiResponse::error(
                            super::combine_rollback_failure(
                                primary,
                                rollback_err,
                                "State Node create",
                                "remote",
                                "rollback",
                            ),
                            trace_id,
                        );
                    }
                    return response;
                }
            };

        let output = CreateContentOutput {
            file_id: result.series_id.as_str().to_string(),
            content_id: result.content_id.as_str().to_string(),
            remote_content_id,
            created_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// Fetches normal content from local state and decrypts it
    ///
    /// Flow:
    /// 1. Validate input (content_id)
    /// 2. Convert to ContentId
    /// 3. Call ContentService::fetch, which does:
    ///    - fetch the encrypted content from the repository
    ///    - fetch the CEK from the key store
    ///    - decrypt the content with the CEK
    /// 4. base64url-encode the decrypted content
    /// 5. Convert the metadata
    /// 6. Return the result
    pub fn get_content(&self, input: GetContentInput) -> ApiResponse<GetContentOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_content_id(&input.file_id, trace_id.clone()) {
            return response;
        }

        let content_id = ContentId::new(input.file_id.clone());

        let content_service = &self.content_service;

        let result = match content_service.fetch(content_id, None) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_fetch_error(e), trace_id);
            }
        };

        let content_base64url = URL_SAFE_NO_PAD.encode(&result.raw_content);

        let metadata = crate::models::content::ContentMetadata {
            name: Some(result.metadata.name().to_string()),
            content_type: None,
            created_at: Some(result.metadata.created_at().to_rfc3339()),
            updated_at: Some(result.metadata.updated_at().to_rfc3339()),
        };

        let output = GetContentOutput {
            content_id: result.content_id.as_str().to_string(),
            content: content_base64url,
            metadata: Some(metadata),
        };

        ApiResponse::success(output, trace_id)
    }

    /// Updates existing content.
    ///
    /// `auth` is the auth header forwarded to the State Node (passed through from the gateway etc.). `Some` is required in production.
    ///
    /// Flow:
    /// 1. Validate input (local_content_id, remote_content_id, content or metadata.name)
    /// 2. Convert to ContentId (keep the source version ID)
    /// 3. Prepare the update (new_name, new_raw_content)
    /// 4. Call ContentService::update, which does:
    ///    - fetch the existing content
    ///    - encrypt the new content if present
    ///    - store it in the repository
    ///    - update the CEK (as needed)
    /// 5. Send the encrypted content to the State Node
    /// 6. Return the result
    pub fn update_content(
        &self,
        input: UpdateContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<UpdateContentOutput> {
        let trace_id = generate_trace_id();

        // 1. Validate input
        if input.file_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("file_id must not be empty".into()),
                trace_id,
            );
        }
        if input.remote_content_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("remote_content_id must not be empty".into()),
                trace_id,
            );
        }

        // 2. Take the record by file key (on failure, restore this record and the CEK as-is).
        //
        // The record and CEK are one entry per file, so a rollback means "restore the whole
        // pre-save record". If run concurrently with other writes to the same file (a save from
        // another tab, revoke, delete, adoption), rolling back our failure would erase a write
        // that succeeded in between. Using the same per-file lock as revoke, serialize
        // everything from taking the record through sending to the State Node and rolling back.
        let content_id = ContentId::new(input.file_id.clone());
        let _file_guard = self.content_revoke_locks.lock(content_id.as_str());
        let before_update = match self.capture_stored_content_snapshot(&content_id) {
            Ok(snapshot) => snapshot,
            Err(error) => return ApiResponse::error(error, trace_id),
        };
        let base_version_id = before_update.content.raw_id().as_str().to_string();

        // 3. Prepare new_name and new_raw_content
        let new_name = input.metadata.as_ref().and_then(|m| m.name.clone());

        let new_raw_content = if input.content.is_empty() {
            None
        } else {
            // base64url-decode the content
            match Self::decode_and_validate_content(&input.content, trace_id.clone()) {
                Ok(bytes) => Some(bytes),
                Err(response) => return response,
            }
        };

        // 4. Ensure at least one of new_name and new_raw_content is specified
        if new_name.is_none() && new_raw_content.is_none() {
            return ApiResponse::error(
                ApiError::Validation(
                    "at least one of content or metadata.name must be provided".into(),
                ),
                trace_id,
            );
        }

        let content_service = &self.content_service;

        let cmd = UpdateContentCommand {
            content_id,
            new_name,
            new_raw_content,
            provider: None,
        };

        let result = match content_service.update(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_update_error(e), trace_id);
            }
        };

        if let Some(response) = self.send_update_to_state_node(
            &input.remote_content_id,
            &result.encrypted_content,
            auth,
            trace_id.clone(),
        ) {
            if let Err(rollback_err) = self.restore_stored_content_snapshot(&before_update) {
                let primary = response.error.clone().unwrap_or_else(|| {
                    ApiError::Internal("unknown state node update failure".into())
                });
                return ApiResponse::error(
                    super::combine_rollback_failure(
                        primary,
                        rollback_err,
                        "State Node update",
                        "remote",
                        "rollback",
                    ),
                    trace_id,
                );
            }
            return response;
        }

        let output = UpdateContentOutput {
            file_id: result.series_id.as_str().to_string(),
            previous_version_id: base_version_id,
            version_id: result.content_id.as_str().to_string(),
            updated_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// Deletes content.
    ///
    /// `auth` is the auth header forwarded to the State Node (passed through from the gateway etc.). `Some` is required in production.
    ///
    /// Flow:
    /// 1. Validate input (content_id)
    /// 2. Convert to ContentId
    /// 3. Call ContentService::delete, which does:
    ///    - delete the content from the repository (logical delete)
    ///    - delete the CEK from the key store
    /// 4. Notify the State Node of the deletion
    /// 5. Return the result
    pub fn delete_content(
        &self,
        input: DeleteContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<DeleteContentOutput> {
        let trace_id = generate_trace_id();

        // 1. Validate input
        if let Some(response) = Self::validate_content_id(&input.file_id, trace_id.clone()) {
            return response;
        }
        if input.remote_content_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("remote_content_id must not be empty".into()),
                trace_id,
            );
        }

        // 2. Take the record and CEK by file key. If the State Node rejects the deletion,
        //    restore them as-is (nothing is recreated, so the file key, CEK, ciphertext, and
        //    share settings are the same as before the deletion).
        let content_id = ContentId::new(input.file_id.clone());
        // For the same reason as update, serialize with writes to the same file.
        let _file_guard = self.content_revoke_locks.lock(content_id.as_str());

        let snapshot = match self.capture_stored_content_snapshot(&content_id) {
            Ok(snapshot) => snapshot,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // 3. Use ContentService
        let content_service = &self.content_service;

        // 4. Create the DeleteContentCommand
        let cmd = DeleteContentCommand {
            content_id,
            provider: None,
        };

        // 5. Call ContentService::delete to delete the content
        let result = match content_service.delete(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_delete_error(e), trace_id);
            }
        };

        if let Some(response) =
            self.send_delete_to_state_node(&input.remote_content_id, auth, trace_id.clone())
        {
            if let Err(restore_err) = self.restore_stored_content_snapshot(&snapshot) {
                let primary = response.error.clone().unwrap_or_else(|| {
                    ApiError::Internal("unknown state node delete failure".into())
                });
                return ApiResponse::error(
                    super::combine_rollback_failure(
                        primary,
                        restore_err,
                        "State Node delete",
                        "remote",
                        "restore",
                    ),
                    trace_id,
                );
            }
            return response;
        }

        let output = DeleteContentOutput {
            content_id: result.content_id.as_str().to_string(),
            deleted: true,
            deleted_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_signature_message_binds_operation_resource_timestamp() {
        let base = MonasController::build_request_signature_message("delete", "c1", 42, None);
        assert!(base.starts_with("monas-request-v1:"), "msg={base}");

        // Changing any of the 4 fields changes the signing target
        assert_ne!(
            base,
            MonasController::build_request_signature_message("read", "c1", 42, None)
        );
        assert_ne!(
            base,
            MonasController::build_request_signature_message("delete", "c2", 42, None)
        );
        assert_ne!(
            base,
            MonasController::build_request_signature_message("delete", "c1", 43, None)
        );
    }

    #[test]
    fn request_signature_message_binds_body_and_stays_bound_to_resource() {
        let with_body =
            MonasController::build_request_signature_message("update", "c1", 42, Some(b"abc"));

        // A different body changes the signing target too
        assert_ne!(
            with_body,
            MonasController::build_request_signature_message("update", "c1", 42, Some(b"abd"))
        );
        // Even with a body, it is bound to operation / resource (prevents cross-resource /
        // cross-operation replay)
        assert_ne!(
            with_body,
            MonasController::build_request_signature_message("update", "c2", 42, Some(b"abc"))
        );
        assert_ne!(
            with_body,
            MonasController::build_request_signature_message("create", "c1", 42, Some(b"abc"))
        );
        // Presence/absence of a body is also distinguished
        assert_ne!(
            with_body,
            MonasController::build_request_signature_message("update", "c1", 42, None)
        );
    }

    /// Rejects before sending to the state node when the signing key is not P-256.
    #[test]
    #[allow(deprecated)]
    fn state_node_signing_rejects_non_p256_account_key() {
        use monas_account::application_service::KeyTypeMapper;

        let controller = MonasController::with_state_node_url("http://127.0.0.1:9");
        controller
            .account_service
            .create(KeyTypeMapper::K256)
            .expect("overwrite signing key");

        let result: Result<StateNodeAuthContext, ApiResponse<()>> = controller
            .sign_state_node_message_with_account(
                "monas-request-v1",
                MonasController::current_unix_timestamp(),
                "trace",
            );

        match result {
            Err(response) => assert!(matches!(response.error, Some(ApiError::Validation(_)))),
            Ok(_) => panic!("non-P256 signing key must be rejected"),
        }
    }

    /// Values containing the delimiter do not shift field boundaries (thanks to length prefixes).
    #[test]
    fn request_signature_message_is_unambiguous_with_colons() {
        assert_ne!(
            MonasController::build_request_signature_message("a", "b:c", 1, None),
            MonasController::build_request_signature_message("a:b", "c", 1, None)
        );
    }
}
