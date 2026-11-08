use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::{Digest, Sha256};

use crate::common::{
    encode_base64url, generate_trace_id, ApiError, ApiResponse, StateNodeAuthContext,
};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    PullContentFromStateNodeInput, PullContentFromStateNodeOutput, ReadContentFromStateNodeInput,
    ReadContentFromStateNodeOutput, VerifyIntegrityInput, VerifyIntegrityOutput,
};
use crate::models::state_node::{StateNodeContentDataResponse, StateNodeContentHistoryResponse};
use monas_content::application_service::content_service::VerifiedRead;
use monas_content::domain::content_id::ContentId;

use super::MonasController;

/// Who reads with which key in a verified read.
pub(super) enum StateReader<'a> {
    /// The owner reads their own file. The CEK is looked up by file_id, and the expected
    /// plainCid (compared with the one recomputed from the decrypted body) is taken from that
    /// file's record (key = file_id).
    Owner { file_id: &'a str },
    /// A share recipient reads. The CEK is under the sender pin (series ID) or under the
    /// plainCid of the shared version.
    Recipient { local_content_id: &'a str },
}

/// Result of `MonasController::adopt_remote_head`.
pub(super) struct AdoptedHead {
    /// plainCid of the current version after adoption.
    pub local_content_id: ContentId,
    pub version: String,
    pub adopted: bool,
    pub plaintext: Vec<u8>,
}

impl MonasController {
    fn validate_state_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    /// Resolves the auth context for the State Node read API.
    ///
    /// If the caller explicitly provides both Authorization and a signature, pass them through.
    /// If there is no signature, sign `read:<content_id>:<timestamp>` with monas-account, the
    /// same as for writes (create/update/delete). Authorization is then:
    /// - `user:<hex(pubkey)>` if absent (reading as the owner)
    /// - kept as-is if it is `Bearer <delegated token>` (reading as a share recipient).
    ///   The State Node verifies the signature with the Token's `aud` key, so the recipient
    ///   must sign with the Token's audience key = this gateway's account key. Passing the
    ///   Token without signing is rejected with "Request signature is required".
    ///
    /// The State Node verifies this signed message on read
    /// (`verify_read_access` → `verify_caller_signature("read", content_id, ..)`).
    /// Binding the signature to content_id prevents a signature handed to a relay node etc.
    /// from being reused to read other content.
    fn resolve_state_read_auth<T>(
        &self,
        auth: Option<&StateNodeAuthContext>,
        content_id: &str,
        trace_id: &str,
    ) -> Result<Option<StateNodeAuthContext>, ApiResponse<T>> {
        match auth {
            Some(ctx) if ctx.request_signature.is_none() => {
                let signed =
                    self.prepare_state_node_metadata_auth(auth, "read", content_id, trace_id)?;
                Ok(signed.map(|mut s| {
                    if ctx.authorization.is_some() {
                        s.authorization = ctx.authorization.clone();
                    }
                    s
                }))
            }
            _ => Ok(auth.cloned()),
        }
    }

    fn state_node_get_string<T>(
        &self,
        url: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<(u16, String), ApiResponse<T>> {
        if let Some(ctx) = auth {
            self.resolve_request_timestamp::<T>(ctx, &trace_id)?;
        }

        let trace_id_for_call = trace_id.clone();
        let resp = Self::attach_state_node_auth(self.agent.get(url), auth)
            .call()
            .map_err(|e| {
                ApiResponse::error(
                    ApiError::from_ureq_error("Failed to call State Node", e),
                    trace_id_for_call,
                )
            })?;

        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                trace_id,
            )
        })?;

        Ok((status, body))
    }
    fn get_state_node_history<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentHistoryResponse, ApiResponse<T>> {
        let url = format!("{}/content/{}/history", self.state_node_url, content_id);

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentHistoryResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    fn get_state_node_version_data<T>(
        &self,
        content_id: &str,
        version: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentDataResponse, ApiResponse<T>> {
        let url = format!(
            "{}/content/{}/version/{}",
            self.state_node_url, content_id, version
        );

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentDataResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    /// Gets the latest version (CID) of a content.
    ///
    /// `auth` is the auth header forwarded to the State Node's `GET /content/:id/history`. `Some` is required in production.
    pub fn get_latest_version(
        &self,
        input: GetLatestVersionInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetLatestVersionOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetLatestVersionOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetLatestVersionOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        let latest = history
            .versions
            .last()
            .cloned()
            .unwrap_or_else(|| input.content_id.clone());

        ApiResponse::success(
            GetLatestVersionOutput {
                content_id: input.content_id,
                latest_version: latest,
                updated_at: None,
            },
            trace_id,
        )
    }

    /// Gets the update history of a content.
    ///
    /// `auth` is the auth header forwarded to the State Node's `GET /content/:id/history`. `Some` is required in production.
    pub fn get_history(
        &self,
        input: GetHistoryInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetHistoryOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetHistoryOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetHistoryOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        // limit does not exist on the State Node side, so apply it in the SDK (prefer the tail = newest side)
        let mut versions = history.versions;
        let limit = input.limit as usize;
        if limit > 0 && versions.len() > limit {
            versions = versions[versions.len() - limit..].to_vec();
        }

        ApiResponse::success(
            GetHistoryOutput {
                content_id: input.content_id,
                versions,
            },
            trace_id,
        )
    }

    /// Body of the verified read. Shared by `read_content_from_state_node` and
    /// `pull_content_from_state_node`. Returns the version CID read and the verification result.
    #[allow(clippy::too_many_arguments)]
    fn verified_read_from_state_node<T>(
        &self,
        content_id: &str,
        reader: StateReader<'_>,
        version: Option<&str>,
        accept_any_version: bool,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<(String, VerifiedRead), ApiResponse<T>> {
        let auth = self.resolve_state_read_auth::<T>(auth, content_id, &trace_id)?;
        let auth = auth.as_ref();

        // Decide the version. Without an explicit one, read the latest in the history.
        // The history has neither signatures nor series verification, so it can only be used to
        // choose "which version to read". The chosen version's payload is protected by the CID
        // verification below, but that version being the latest is not guaranteed
        // (see "Guarantee scope" above).
        let version = match version {
            Some(v) => v.to_string(),
            None => self
                .get_state_node_history::<T>(content_id, auth, trace_id.clone())?
                .versions
                .last()
                .cloned()
                .unwrap_or_else(|| content_id.to_string()),
        };

        // Fetch the Node CBOR + CID verification (A)
        let state_node_data =
            self.get_state_node_version_data::<T>(content_id, &version, auth, trace_id.clone())?;

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                ));
            }
        };

        // Tamper verification by CID recomputation + CEK load + AES-GCM decryption + plain CID check
        //
        // Verification always runs first inside `verify_and_decrypt_relay_read`, so there is no
        // need to call `verify_and_extract` here beforehand (it used to run twice with the same
        // arguments). Verification lives in one place as the content layer's responsibility.
        //
        // For the CEK, prefer the "authoritative sender-pin record". The CEK store is merely a
        // cache derived from that record, and if the write order after a successful CAS gets
        // swapped it can roll back to an older epoch (the epoch N handler stalls after its CAS,
        // meanwhile N+1 advances the authoritative record and the cache, then N resumes and
        // reverts only the cache to N). Reading directly from the authoritative record keeps
        // that rollback from affecting reads.
        //
        // An owner read uses the CEK and plainCid from the file's record
        // (the sender pin is a recipient-side thing).
        let local_content_id = match reader {
            StateReader::Owner { file_id } => {
                let read = self
                    .content_service
                    .verify_and_decrypt_owner_read(
                        &node_bytes,
                        &version,
                        &ContentId::new(file_id.to_string()),
                        accept_any_version,
                    )
                    .map_err(|e| {
                        ApiResponse::error(Self::map_verified_read_error(e, file_id), trace_id)
                    })?;
                return Ok((version, read));
            }
            StateReader::Recipient { local_content_id } => local_content_id,
        };
        let local_id = ContentId::new(local_content_id.to_string());

        //
        // The pin may be stored under either the series ID (= `content_id` here) or the version
        // ID (`local_content_id`): share recipients pass `remote_content_id` and get the series
        // ID; older calls that don't pass it get the version ID. Look up the series first.
        let pinned_cek = {
            let load = |key: &str| self.sender_pin_store.load(key);
            let by_series = load(content_id);
            let pin = match by_series {
                Ok(Some(p)) => Ok(Some(p)),
                Ok(None) => load(local_content_id),
                Err(e) => Err(e),
            };
            match pin {
                Ok(pin) => pin
                    .and_then(|p| p.cek)
                    .map(monas_content::domain::content::ContentEncryptionKey),
                Err(e) => {
                    return Err(ApiResponse::error(
                        ApiError::Internal(format!("sender key pin store error: {e}")),
                        trace_id,
                    ));
                }
            }
        };
        // A share recipient holds the CEK under "the id of the shared version", but cannot know
        // the plaintext CID of versions the owner wrote afterwards. `accept_any_version` skips
        // that check and returns the id the decrypted plaintext actually points to (the Node CID
        // and AES-GCM verification remain as-is).
        let read = if accept_any_version {
            self.content_service
                .verify_and_decrypt_relay_read_any_version(
                    &node_bytes,
                    &version,
                    local_id,
                    pinned_cek,
                )
        } else {
            self.content_service.verify_and_decrypt_relay_read(
                &node_bytes,
                &version,
                local_id,
                pinned_cek,
            )
        };
        let read = read.map_err(|e| {
            ApiResponse::error(Self::map_verified_read_error(e, local_content_id), trace_id)
        })?;

        Ok((version, read))
    }

    /// Reads content from the State Node, verifies and decrypts it, and returns the plaintext
    /// (verified read).
    ///
    /// The actual read path for `docs/design.md` §10 "read response integrity
    /// verification". Flow:
    /// 1. Resolve the auth context for the `read:{content_id}:{timestamp}` signature
    /// 2. Decide the version (the version given in `input.version` if any, otherwise the latest
    ///    in the history)
    /// 3. Fetch the Node CBOR and verify against tampering by recomputing the CID
    /// 4. Look up the CEK from the local cek_store, AES-GCM decrypt + plain CID check
    ///
    /// The CEK exists locally for "content you created" or "content whose share KeyEnvelope
    /// has been processed" (stored by `decrypt_shared_content`).
    ///
    /// **Guarantee scope**: what can be verified is only that "the returned Node's payload is
    /// authentic for the requested version CID". It does not guarantee "that the version is
    /// really the latest" or "that the version was written by a legitimate writer" — version
    /// metadata (parents, etc.) has no authenticity, and a Node that rewraps an observed
    /// legitimate ciphertext with arbitrary parents passes CID verification.
    /// Version authenticity and rollback resistance require a trust anchor such as an owner
    /// signature (issue #59). In a distributed system, stale reads due to sync delay are
    /// normal behavior and cannot be distinguished from an attack by a single response.
    pub fn read_content_from_state_node(
        &self,
        input: ReadContentFromStateNodeInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<ReadContentFromStateNodeOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }
        let reader = match (input.file_id.as_deref(), input.local_content_id.as_str()) {
            (Some(file_id), "") if !file_id.is_empty() => StateReader::Owner { file_id },
            (None, local) if !local.is_empty() => StateReader::Recipient {
                local_content_id: local,
            },
            _ => {
                return ApiResponse::error(
                    ApiError::Validation(
                        "exactly one of file_id (owner) or local_content_id (share recipient) \
                         must be given"
                            .into(),
                    ),
                    trace_id,
                );
            }
        };

        let (version, read) = match self
            .verified_read_from_state_node::<ReadContentFromStateNodeOutput>(
                &input.content_id,
                reader,
                input.version.as_deref(),
                input.accept_any_version,
                auth,
                trace_id.clone(),
            ) {
            Ok(r) => r,
            Err(e) => return e,
        };

        ApiResponse::success(
            ReadContentFromStateNodeOutput {
                content_id: input.content_id,
                local_content_id: read.plain_content_id.as_str().to_string(),
                version,
                content: encode_base64url(&read.plaintext),
            },
            trace_id,
        )
    }

    /// Adopts the State Node head into the owner's local record (pull).
    ///
    /// Versions written by a recipient who was delegated write permission exist only on the
    /// State Node, and the owner's local record stays stale. The owner's `update_content` /
    /// `revoke_share` (re-encryption) reissue from the local plaintext, so not calling this
    /// first silently overwrites the recipient's version. `revoke_share` calls it itself if
    /// `remote_content_id` and `auth` are present.
    ///
    /// Adopts only versions that pass the verified read (Node CID recomputation + AES-GCM
    /// decryption with our own CEK), and stores the State Node's ciphertext as-is
    /// (so `verify_integrity` keeps matching). If the head is the same as the local version,
    /// returns only the plaintext with `adopted: false`.
    pub fn pull_content_from_state_node(
        &self,
        input: PullContentFromStateNodeInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<PullContentFromStateNodeOutput> {
        let trace_id = generate_trace_id();
        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }
        if input.file_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("file_id must not be empty".into()),
                trace_id,
            );
        }
        // Adoption rewrites the record, so serialize it with other writes to the same file
        // (update, delete, revoke) under the same lock. revoke calls
        // `adopt_remote_head` while holding the lock, so the lock is taken here.
        let _file_guard = self.content_revoke_locks.lock(&input.file_id);
        match self.adopt_remote_head::<PullContentFromStateNodeOutput>(
            &input.content_id,
            &input.file_id,
            auth,
            trace_id.clone(),
        ) {
            Ok(head) => ApiResponse::success(
                PullContentFromStateNodeOutput {
                    content_id: input.content_id,
                    local_content_id: head.local_content_id.as_str().to_string(),
                    version: head.version,
                    adopted: head.adopted,
                    content: encode_base64url(&head.plaintext),
                },
                trace_id,
            ),
            Err(response) => response,
        }
    }

    /// Body of `pull_content_from_state_node`. Also called from `revoke_share`.
    ///
    /// If the head differs from the file's record (plainCid or ciphertext differs), advances
    /// the record to the head via `ContentService::adopt_version`. The record, CEK, and
    /// share settings are keyed by the file key, so nothing needs to be carried over even if
    /// the plainCid changes.
    pub(super) fn adopt_remote_head<T>(
        &self,
        content_id: &str,
        file_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<AdoptedHead, ApiResponse<T>> {
        let (version, read) = self.verified_read_from_state_node::<T>(
            content_id,
            StateReader::Owner { file_id },
            None,
            true,
            auth,
            trace_id.clone(),
        )?;
        let file = ContentId::new(file_id.to_string());
        let current = self.content_service.load_record(&file).ok().flatten();
        let unchanged = current.as_ref().is_some_and(|(c, _)| {
            c.raw_id() == &read.plain_content_id && c.encrypted_content() == Some(&read.ciphertext)
        });
        if unchanged {
            return Ok(AdoptedHead {
                local_content_id: read.plain_content_id,
                version,
                adopted: false,
                plaintext: read.plaintext,
            });
        }

        let adopted = self
            .content_service
            .adopt_version(&file, read.ciphertext)
            .map_err(|e| {
                ApiResponse::error(
                    ApiError::Internal(format!(
                        "state node head {} could not be adopted into the local file: {e}",
                        read.plain_content_id.as_str(),
                    )),
                    trace_id.clone(),
                )
            })?;

        Ok(AdoptedHead {
            local_content_id: adopted.content_id,
            version,
            adopted: true,
            plaintext: read.plaintext,
        })
    }

    /// Maps errors from `verify_and_decrypt_relay_read` to an `ApiError` the caller can act
    /// on. In particular, "no CEK" and "CEK mismatch" distinguish via the message which of
    /// share / rotation / revoke the situation is.
    fn map_verified_read_error(
        e: monas_content::application_service::content_service::VerifiedReadError,
        local_content_id: &str,
    ) -> ApiError {
        use monas_content::application_service::content_service::{
            DecryptWithCekError, VerifiedReadError,
        };
        match e {
            VerifiedReadError::NodeVerification(err) => ApiError::Internal(format!(
                "state node response failed CID verification (tampered response?): {err}"
            )),
            VerifiedReadError::KeyStore(err) => {
                ApiError::Internal(format!("CEK store error: {err:?}"))
            }
            VerifiedReadError::MissingKey => ApiError::NotFound(format!(
                "no content encryption key for local content {local_content_id} on this device: \
                 the content was neither created here nor received via share on this device. \
                 Process its share KeyEnvelope (POST /share/decrypt) first."
            )),
            VerifiedReadError::Decrypt(DecryptWithCekError::Domain(_)) => ApiError::Forbidden(
                "decryption failed with the locally stored CEK: the key may be stale after a CEK \
                 rotation, or your access may have been revoked. If you still have access, \
                 re-process the latest share KeyEnvelope to refresh the stored CEK."
                    .to_string(),
            ),
            VerifiedReadError::Decrypt(DecryptWithCekError::ContentIdMismatch {
                expected,
                actual,
            }) => ApiError::Conflict(format!(
                "decrypted content does not match local_content_id (expected {expected}, got \
                 {actual}): the content has likely been updated — pass the local content id that \
                 corresponds to the version being read"
            )),
        }
    }

    /// Verifies the integrity of the fetched content.
    ///
    /// `auth` is the auth header forwarded to the State Node history / version fetch APIs. `Some` is required in production.
    ///
    /// Flow:
    /// 1. Compute the content hash
    /// 2. Compare with the information fetched from the State Node
    /// 3. valid: true if they match
    pub fn verify_integrity(
        &self,
        input: VerifyIntegrityInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let auth = match self.resolve_state_read_auth::<VerifyIntegrityOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let auth = auth.as_ref();

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                );
            }
        };

        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&content_bytes);
            let digest = hasher.finalize();
            format!("{digest:x}")
        };

        let version_to_check = if let Some(v) = input.expected_version.clone() {
            v
        } else {
            match self.get_state_node_history::<VerifyIntegrityOutput>(
                &input.content_id,
                auth,
                trace_id.clone(),
            ) {
                Ok(h) => h
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone()),
                Err(e) => return e,
            }
        };

        let state_node_data = match self.get_state_node_version_data::<VerifyIntegrityOutput>(
            &input.content_id,
            &version_to_check,
            auth,
            trace_id.clone(),
        ) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                );
            }
        };

        // The State Node returns "the whole Node (CBOR)" as the read response. First recompute
        // the CID and verify it matches version (tamper detection), then extract the payload
        // ciphertext (§8.1). The comparison target is pinned to the version chosen by the
        // client. The version inside the response is self-reported, so comparing against it
        // would let verification pass by simply returning any Node + its CID.
        let state_bytes = match monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            &version_to_check,
        ) {
            Ok(verified) => verified.ciphertext,
            Err(e) => {
                return ApiResponse::success(
                    VerifyIntegrityOutput {
                        valid: false,
                        computed_hash,
                        reason: Some(format!("state node response failed CID verification: {e}")),
                    },
                    trace_id,
                );
            }
        };

        // What the State Node holds is the "ciphertext" the SDK sent, so
        // if a file_id is given, compare bytes against the ciphertext in that file's record.
        // (The plaintext `content` can never match the State Node's bytes.)
        let (valid, reason) = if let Some(local_id) = input.file_id.as_deref() {
            match self.content_service.fetch_encrypted(
                monas_content::domain::content_id::ContentId::new(local_id.to_string()),
            ) {
                Ok(local_cipher) => {
                    if local_cipher == state_bytes {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(format!(
                                "state node ciphertext differs from local ciphertext (version={version_to_check})"
                            )),
                        )
                    }
                }
                Err(e) => (
                    false,
                    Some(format!(
                        "failed to load local ciphertext for {local_id}: {e}"
                    )),
                ),
            }
        } else {
            let valid = content_bytes == state_bytes;
            (
                valid,
                if valid {
                    None
                } else {
                    Some(format!(
                        "content mismatch with state node (version={version_to_check})"
                    ))
                },
            )
        };

        ApiResponse::success(
            VerifyIntegrityOutput {
                valid,
                computed_hash,
                reason,
            },
            trace_id,
        )
    }
}
