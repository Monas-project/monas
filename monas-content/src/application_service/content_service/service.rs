use crate::domain::{
    content::encryption::{ContentEncryption, ContentEncryptionKey, ContentEncryptionKeyGenerator},
    content::{Content, ContentError},
    content_id::{ContentId, ContentIdGenerator},
};

use super::{
    ContentEncryptionKeyStore, ContentEncryptionKeyStoreError, ContentRepositoryError,
    CreateContentCommand, CreateContentResult, DeleteContentCommand, DeleteContentResult,
    FetchContentResult, MultiStorageContentRepository, ReencryptContentCommand,
    ReencryptContentResult, UpdateContentCommand, UpdateContentResult,
};

/// Application service for the content creation use case.
pub struct ContentService<G, R, K, E, S> {
    pub content_id_generator: G,
    pub content_repository: R,
    pub key_generator: K,
    pub encryptor: E,
    pub cek_store: S,
}

impl<G, R, K, E, S> ContentService<G, R, K, E, S>
where
    G: ContentIdGenerator,
    R: MultiStorageContentRepository,
    K: ContentEncryptionKeyGenerator,
    E: ContentEncryption,
    S: ContentEncryptionKeyStore,
{
    /// Looks up a record by file key (from the given provider, if specified).
    fn find(
        &self,
        provider: Option<&crate::domain::content::StorageProvider>,
        series_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        match provider {
            Some(provider) => self
                .content_repository
                .find_from(provider.as_str(), series_id),
            None => self.content_repository.find_by_id(series_id),
        }
    }

    /// Saves a record under the file key (overwrite).
    fn store(
        &self,
        provider: Option<&crate::domain::content::StorageProvider>,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        match provider {
            Some(provider) => {
                self.content_repository
                    .save_to(provider.as_str(), content.series_id(), content)
            }
            None => self.content_repository.save(content.series_id(), content),
        }
    }

    /// Looks up the record and CEK by file key.
    pub fn load_record(
        &self,
        series_id: &ContentId,
    ) -> Result<Option<(Content, Option<ContentEncryptionKey>)>, FetchError> {
        let Some(content) = self
            .content_repository
            .find_by_id(series_id)
            .map_err(FetchError::Repository)?
        else {
            return Ok(None);
        };
        let key = self
            .cek_store
            .load(series_id)
            .map_err(FetchError::KeyStore)?;
        Ok(Some((content, key)))
    }

    /// Restores the record and CEK obtained by [`load_record`](Self::load_record) as-is.
    ///
    /// Used to roll back failed operations (deletes, updates, etc. rejected by the state node).
    /// Nothing is recreated, so the file key, CEK, and ciphertext end up the same as before the
    /// operation.
    pub fn put_record(
        &self,
        content: &Content,
        key: Option<&ContentEncryptionKey>,
    ) -> Result<(), ContentRepositoryError> {
        self.store(content.metadata().provider(), content)?;
        if let Some(key) = key {
            self.cek_store
                .save(content.series_id(), key)
                .map_err(|e| ContentRepositoryError::Storage(format!("CEK store: {e}")))?;
        }
        Ok(())
    }

    pub fn create(&self, cmd: CreateContentCommand) -> Result<CreateContentResult, CreateError> {
        // Simple validation
        Self::validate_create_command(&cmd)?;

        // Generate the CEK
        let key = self.key_generator.generate();

        // Call the domain's Content::create: generates the ContentId, encrypts, and builds metadata.
        // The file key (series_id) includes the creation time, so it normally does not collide, but
        // regenerate it if already in use so an existing file's record is not overwritten.
        let mut attempts = 0;
        let content = loop {
            let (content, _event) = Content::create(
                cmd.name.clone(),
                cmd.raw_content.clone(),
                cmd.path.clone(),
                cmd.provider.clone(),
                &self.content_id_generator,
                &key,
                &self.encryptor,
            )
            .map_err(CreateError::Domain)?;
            let taken = self
                .find(cmd.provider.as_ref(), content.series_id())
                .map_err(CreateError::Repository)?
                .is_some();
            if !taken {
                break content;
            }
            attempts += 1;
            if attempts >= 8 {
                return Err(CreateError::Validation(
                    "could not allocate an unused file id".into(),
                ));
            }
        };

        // Save the CEK (by file key)
        self.cek_store
            .save(content.series_id(), &key)
            .map_err(CreateError::KeyStore)?;

        // Persist the content (to the given provider if specified, otherwise to the default)
        self.store(cmd.provider.as_ref(), &content)
            .map_err(CreateError::Repository)?;

        let metadata = content.metadata().clone();
        let content_id = content.raw_id().clone();
        let series_id = content.series_id().clone();

        let encrypted_content = content
            .encrypted_content()
            .ok_or(CreateError::MissingEncryptedContent)?
            .clone();

        Ok(CreateContentResult {
            content_id,
            series_id,
            metadata,
            public_key: String::new(), // TODO: set the public key in the future
            encrypted_content,
        })
    }

    /// Simple validation of CreateContentCommand.
    fn validate_create_command(cmd: &CreateContentCommand) -> Result<(), CreateError> {
        if cmd.raw_content.is_empty() {
            return Err(CreateError::Validation(
                "raw_content must not be empty".into(),
            ));
        }
        if cmd.name.trim().is_empty() {
            return Err(CreateError::Validation("name must not be empty".into()));
        }
        if cmd.path.trim().is_empty() {
            return Err(CreateError::Validation("path must not be empty".into()));
        }
        Ok(())
    }

    /// Content update use case.
    ///
    /// - `new_name` and `new_raw_content` may be specified individually or together
    /// - If both are `None`, it is a Validation error
    pub fn update(&self, cmd: UpdateContentCommand) -> Result<UpdateContentResult, UpdateError> {
        // Simple validation
        Self::validate_update_command(&cmd)?;

        // Fetch the existing content (`content_id` is the file key)
        let mut content = self
            .find(cmd.provider.as_ref(), &cmd.content_id)
            .map_err(UpdateError::Repository)?
            .ok_or(UpdateError::NotFound)?;

        // If a binary update is specified
        if let Some(raw) = cmd.new_raw_content {
            // Fetch the existing CEK from the key store and reuse it.
            // Assumes one CEK per content, with only the IV randomized on each encryption.
            let key = self
                .cek_store
                .load(content.series_id())
                .map_err(UpdateError::KeyStore)?
                .ok_or_else(|| {
                    UpdateError::KeyStore(ContentEncryptionKeyStoreError::Storage(
                        "missing content encryption key for content".to_string(),
                    ))
                })?;

            let (updated, _event) = content
                .update_content(raw, &self.content_id_generator, &key, &self.encryptor)
                .map_err(UpdateError::Domain)?;

            content = updated;
        }

        // If a rename is specified
        if let Some(name) = cmd.new_name {
            let (updated, _event) = content.rename(name).map_err(UpdateError::Domain)?;
            content = updated;
        }

        // Persist the content (overwriting the record under the file key)
        self.store(content.metadata().provider(), &content)
            .map_err(UpdateError::Repository)?;

        let metadata = content.metadata().clone();
        let content_id = content.raw_id().clone();
        let series_id = content.series_id().clone();

        let encrypted_content = content
            .encrypted_content()
            .ok_or(UpdateError::MissingEncryptedContent)?
            .clone();

        Ok(UpdateContentResult {
            content_id,
            series_id,
            metadata,
            encrypted_content,
        })
    }

    /// Simple validation of UpdateContentCommand.
    ///
    /// - At least one of `new_name` / `new_raw_content` must be specified.
    /// - Each specified value must be valid.
    fn validate_update_command(cmd: &UpdateContentCommand) -> Result<(), UpdateError> {
        if cmd.new_name.as_ref().is_none() && cmd.new_raw_content.as_ref().is_none() {
            return Err(UpdateError::Validation(
                "at least one of new_name or new_raw_content must be provided".into(),
            ));
        }
        if let Some(name) = &cmd.new_name {
            if name.trim().is_empty() {
                return Err(UpdateError::Validation("name must not be empty".into()));
            }
        }
        if let Some(raw) = &cmd.new_raw_content {
            if raw.is_empty() {
                return Err(UpdateError::Validation(
                    "new_raw_content must not be empty when provided".into(),
                ));
            }
        }
        Ok(())
    }

    /// Use case that fetches the content body and decrypts it (fetch).
    ///
    /// - Fetches the content for `content_id` and returns the bytes decrypted with the CEK.
    /// - Fetches from `provider` if specified, otherwise from the default provider.
    /// - Returns an error if the content is deleted or the CEK does not exist.
    pub fn fetch(
        &self,
        content_id: ContentId,
        provider: Option<&str>,
    ) -> Result<FetchContentResult, FetchError> {
        let content = match provider {
            Some(p) => self.content_repository.find_from(p, &content_id),
            None => self.content_repository.find_by_id(&content_id),
        }
        .map_err(FetchError::Repository)?
        .ok_or(FetchError::NotFound)?;

        if content.is_deleted() {
            return Err(FetchError::Deleted);
        }

        // Fetch the CEK from the key store (by file key)
        let key = self
            .cek_store
            .load(content.series_id())
            .map_err(FetchError::KeyStore)?
            .ok_or(FetchError::MissingKey)?;

        // Decrypt using the domain's decrypt
        let raw_content = content
            .decrypt(&key, &self.encryptor)
            .map_err(FetchError::Domain)?;

        Ok(FetchContentResult {
            content_id: content.raw_id().clone(),
            series_id: content.series_id().clone(),
            metadata: content.metadata().clone(),
            raw_content,
        })
    }

    /// Returns the locally stored "encrypted" bytes.
    ///
    /// For State Node integrity verification: the State Node holds the ciphertext sent by the
    /// SDK, so comparing it byte-for-byte with the local ciphertext, without decrypting,
    /// confirms "whether the State Node holds the same, untampered ciphertext".
    pub fn fetch_encrypted(&self, content_id: ContentId) -> Result<Vec<u8>, FetchError> {
        let content = self
            .content_repository
            .find_by_id(&content_id)
            .map_err(FetchError::Repository)?
            .ok_or(FetchError::NotFound)?;

        if content.is_deleted() {
            return Err(FetchError::Deleted);
        }

        content
            .encrypted_content()
            .cloned()
            .ok_or(FetchError::NotFound)
    }

    /// Use case that decrypts encrypted content using an externally unwrapped CEK.
    ///
    /// - Intended for decryption after the CEK has been extracted from a KeyEnvelope in the share
    ///   flow.
    /// - Recomputes the ContentId from the decrypted bytes and verifies that it matches the
    ///   `content_id` argument (integrity check based on content addressing).
    pub fn decrypt_with_cek(
        &self,
        expected_content_id: ContentId,
        key: ContentEncryptionKey,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, DecryptWithCekError> {
        let plaintext = self
            .encryptor
            .decrypt(&key, &ciphertext)
            .map_err(DecryptWithCekError::Domain)?;

        // Regenerate the ContentId (plainCid) from the decrypted plaintext and
        // check that it matches the expected ID (tamper detection).
        let actual_id = self.content_id_generator.generate(&plaintext);
        if actual_id != expected_content_id {
            return Err(DecryptWithCekError::ContentIdMismatch {
                expected: expected_content_id.as_str().to_string(),
                actual: actual_id.as_str().to_string(),
            });
        }

        Ok(plaintext)
    }

    /// Adopt a version that already exists on the state node as the newest
    /// local version of `content_id`.
    ///
    /// The owner's counterpart of a write share: a recipient with write
    /// access wrote `encrypted_content` under the owner's CEK, and the owner's
    /// local record is now behind the network head. Every owner-side
    /// operation that re-publishes from the local record — `update`,
    /// `reencrypt` on revoke — would otherwise silently overwrite that
    /// version with the stale local plaintext. Calling this first moves the
    /// local record to the head.
    ///
    /// The ciphertext is decrypted with the record's own CEK to obtain the
    /// plaintext (so a ciphertext this device cannot open is refused, and the
    /// caller's claim about the plaintext is never trusted) and stored
    /// as-is, so the local ciphertext keeps matching the state node's for
    /// integrity checks. `series_id` is the file's key; the record keeps it.
    /// Idempotent: adopting the ciphertext the record already holds changes
    /// nothing.
    pub fn adopt_version(
        &self,
        series_id: &ContentId,
        encrypted_content: Vec<u8>,
    ) -> Result<UpdateContentResult, UpdateError> {
        let content = self
            .content_repository
            .find_by_id(series_id)
            .map_err(UpdateError::Repository)?
            .ok_or(UpdateError::NotFound)?;
        let key = self
            .cek_store
            .load(content.series_id())
            .map_err(UpdateError::KeyStore)?
            .ok_or_else(|| {
                UpdateError::KeyStore(ContentEncryptionKeyStoreError::Storage(
                    "missing content encryption key for content".to_string(),
                ))
            })?;
        let raw_content = self
            .encryptor
            .decrypt(&key, &encrypted_content)
            .map_err(UpdateError::Domain)?;

        let (adopted, _event) = content
            .adopt_version(raw_content, encrypted_content, &self.content_id_generator)
            .map_err(UpdateError::Domain)?;

        let unchanged = adopted.raw_id() == content.raw_id()
            && adopted.encrypted_content() == content.encrypted_content();
        if !unchanged {
            self.store(adopted.metadata().provider(), &adopted)
                .map_err(UpdateError::Repository)?;
        }

        let encrypted_content = adopted
            .encrypted_content()
            .ok_or(UpdateError::MissingEncryptedContent)?
            .clone();
        Ok(UpdateContentResult {
            content_id: adopted.raw_id().clone(),
            series_id: adopted.series_id().clone(),
            metadata: adopted.metadata().clone(),
            encrypted_content,
        })
    }

    /// Encrypt a new plaintext under a caller-supplied CEK, without a local
    /// content record.
    ///
    /// The inverse of [`decrypt_with_cek`](Self::decrypt_with_cek), for a
    /// share recipient who writes a new version of the owner's content: the
    /// recipient holds the CEK (from the owner's envelope) but no `Content`
    /// aggregate, so [`update`](Self::update) cannot be used. The ciphertext
    /// is what the state node stores as the version payload; the returned
    /// plain id is the version's `local_content_id`, derived exactly as
    /// [`Content::update_content`](crate::domain::content::Content::update_content)
    /// derives it for the owner, so both sides address the version the same way.
    ///
    /// The CEK is also cached under that id so this device can later run a
    /// verified read of the version it wrote. A cache failure is not an error:
    /// the caller's authoritative CEK record still holds the key.
    pub fn encrypt_with_cek(
        &self,
        key: &ContentEncryptionKey,
        plaintext: &[u8],
    ) -> Result<EncryptedWithCek, ContentError> {
        if key.0.is_empty() {
            return Err(ContentError::EncryptionError(
                "Missing content encryption key".to_string(),
            ));
        }
        let ciphertext = self.encryptor.encrypt(key, plaintext)?;
        let plain_content_id = self.content_id_generator.generate(plaintext);
        let _ = self.cek_store.save(&plain_content_id, key);
        Ok(EncryptedWithCek {
            ciphertext,
            plain_content_id,
        })
    }

    /// Verify and decrypt a relay-read response fetched from a state node.
    ///
    /// The state node returns the whole crsl-lib `Node` (CBOR). This:
    /// 1. Recomputes the Node CID and confirms it equals `expected_version_cid`
    ///    (tamper detection — a relay peer cannot fabricate the payload).
    /// 2. Extracts the ciphertext from the Node payload.
    /// 3. Loads the CEK for `local_content_id` and AES-GCM-decrypts.
    ///
    /// This is the client-side core of the verified read path
    /// (`docs/design.md` §10, "read response integrity verification"). It verifies **payload
    /// authenticity only**: that these bytes are the ones named by
    /// `expected_version_cid`. It does not establish that the version is the
    /// canonical head, the latest, or the work of an authorized writer.
    ///
    /// There is **no monotonicity check anywhere** — neither here nor in the
    /// SDK above. One existed and was removed: forged `parents` bypass it, and
    /// it could not tell a legitimate sync lag from an attack, so it broke
    /// honest reads without stopping dishonest ones. Version authenticity needs
    /// an owner/writer-signed trust anchor, tracked in issue #59.
    ///
    /// Returns the plaintext and the verified node's parent CIDs. The parents
    /// are returned for callers that want to inspect the DAG; nothing in the
    /// SDK currently consumes them.
    /// If `cek` is given it is used; the local CEK store is consulted only when it is `None`.
    /// This argument lets the caller's CEK take precedence over the store when the caller knows
    /// more reliably "which CEK is correct" (a share recipient holds the CEK in the sender
    /// pin's authoritative record). The store is merely a cache that can roll back if writes
    /// are reordered.
    pub fn verify_and_decrypt_relay_read(
        &self,
        node_bytes: &[u8],
        expected_version_cid: &str,
        local_content_id: ContentId,
        cek: Option<ContentEncryptionKey>,
    ) -> Result<VerifiedRead, VerifiedReadError> {
        self.verify_and_decrypt_relay_read_inner(
            node_bytes,
            expected_version_cid,
            &local_content_id,
            Some(&local_content_id),
            cek,
        )
    }

    /// [`verify_and_decrypt_relay_read`](Self::verify_and_decrypt_relay_read)
    /// for a reader who cannot know the plain content id of the version in
    /// advance: a share recipient reading a version the owner wrote *after*
    /// sharing. The CEK is still selected by `key_content_id` (the id the
    /// share was received under), the Node CID is still recomputed, and
    /// AES-GCM still authenticates the ciphertext under that key — what is
    /// skipped is only the comparison of the re-derived plain id against an
    /// expectation the caller does not have. The id it does derive is
    /// returned in `plain_content_id`.
    pub fn verify_and_decrypt_relay_read_any_version(
        &self,
        node_bytes: &[u8],
        expected_version_cid: &str,
        key_content_id: ContentId,
        cek: Option<ContentEncryptionKey>,
    ) -> Result<VerifiedRead, VerifiedReadError> {
        self.verify_and_decrypt_relay_read_inner(
            node_bytes,
            expected_version_cid,
            &key_content_id,
            None,
            cek,
        )
    }

    /// The owner's verified read: the CEK and the expected plain id come from
    /// the local record of the file `series_id`.
    ///
    /// The record holds the file's current CEK and the plainCid of its
    /// current version. With `accept_any_version` the plain id is not
    /// compared (the owner reading a version other than the local one, e.g.
    /// a head written by a write-share recipient), but the Node CID and the
    /// AES-GCM authentication under the file's CEK still apply.
    pub fn verify_and_decrypt_owner_read(
        &self,
        node_bytes: &[u8],
        expected_version_cid: &str,
        series_id: &ContentId,
        accept_any_version: bool,
    ) -> Result<VerifiedRead, VerifiedReadError> {
        let content = self
            .content_repository
            .find_by_id(series_id)
            .map_err(|e| {
                VerifiedReadError::KeyStore(ContentEncryptionKeyStoreError::Storage(format!(
                    "content repository: {e}"
                )))
            })?
            .filter(|c| !c.is_deleted())
            .ok_or(VerifiedReadError::MissingKey)?;
        let expected = (!accept_any_version).then(|| content.raw_id().clone());
        self.verify_and_decrypt_relay_read_inner(
            node_bytes,
            expected_version_cid,
            series_id,
            expected.as_ref(),
            None,
        )
    }

    fn verify_and_decrypt_relay_read_inner(
        &self,
        node_bytes: &[u8],
        expected_version_cid: &str,
        key_content_id: &ContentId,
        expected_plain_id: Option<&ContentId>,
        cek: Option<ContentEncryptionKey>,
    ) -> Result<VerifiedRead, VerifiedReadError> {
        let verified = crate::infrastructure::node_verification::verify_and_extract(
            node_bytes,
            expected_version_cid,
        )
        .map_err(VerifiedReadError::NodeVerification)?;

        let key = match cek {
            Some(key) => key,
            None => self
                .cek_store
                .load(key_content_id)
                .map_err(VerifiedReadError::KeyStore)?
                .ok_or(VerifiedReadError::MissingKey)?,
        };

        let plaintext = self
            .encryptor
            .decrypt(&key, &verified.ciphertext)
            .map_err(|e| VerifiedReadError::Decrypt(DecryptWithCekError::Domain(e)))?;
        let plain_content_id = self.content_id_generator.generate(&plaintext);
        if let Some(expected) = expected_plain_id {
            if &plain_content_id != expected {
                return Err(VerifiedReadError::Decrypt(
                    DecryptWithCekError::ContentIdMismatch {
                        expected: expected.as_str().to_string(),
                        actual: plain_content_id.as_str().to_string(),
                    },
                ));
            }
        }

        Ok(VerifiedRead {
            plaintext,
            parents: verified.parents,
            plain_content_id,
            ciphertext: verified.ciphertext,
        })
    }

    /// Content deletion use case.
    ///
    /// - A "logical delete", not a physical one: sets the `is_deleted` flag and clears the buffer
    ///   on the domain object, then saves it
    pub fn delete(&self, cmd: DeleteContentCommand) -> Result<DeleteContentResult, DeleteError> {
        // Fetch the existing content
        let content = self
            .find(cmd.provider.as_ref(), &cmd.content_id)
            .map_err(DeleteError::Repository)?
            .ok_or(DeleteError::NotFound)?;

        // Domain deletion logic (state transition and validation)
        let (deleted_content, _event) = content.delete().map_err(DeleteError::Domain)?;

        // Delete the CEK
        self.cek_store
            .delete(deleted_content.series_id())
            .map_err(DeleteError::KeyStore)?;

        // Save the logically deleted state
        self.store(deleted_content.metadata().provider(), &deleted_content)
            .map_err(DeleteError::Repository)?;

        let content_id = deleted_content.raw_id().clone();

        Ok(DeleteContentResult { content_id })
    }

    /// Content re-encryption use case.
    ///
    /// Re-encrypts content so that a user with Owner permission can deny access to a specific
    /// user with Read or Write permission.
    pub fn reencrypt(
        &self,
        cmd: ReencryptContentCommand,
    ) -> Result<ReencryptContentResult, ReencryptError> {
        // Step 1: Fetch and validate the content
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(ReencryptError::ContentRepository)?
            .ok_or(ReencryptError::ContentNotFound)?;

        if content.is_deleted() {
            return Err(ReencryptError::ContentDeleted);
        }

        // Step 2: Decrypt with the existing CEK
        // reencrypt assumes "only the encryption is updated, keeping the same file key".
        let content_id = content.series_id().clone();
        let old_cek = self
            .cek_store
            .load(&content_id)
            .map_err(ReencryptError::KeyStore)?
            .ok_or(ReencryptError::MissingContentEncryptionKey)?;

        let plaintext = content
            .decrypt(&old_cek, &self.encryptor)
            .map_err(ReencryptError::Domain)?;

        // Step 3: Generate a new CEK
        let new_cek = self.key_generator.generate();

        // Step 4: Create the re-encrypted Content
        let (reencrypted_content, _event) = content
            .update_content(
                plaintext,
                &self.content_id_generator,
                &new_cek,
                &self.encryptor,
            )
            .map_err(ReencryptError::Domain)?;

        // In reencrypt the plaintext (decryption result) is identical, so the ContentId (plainCid)
        // is assumed not to change.
        debug_assert_eq!(
            reencrypted_content.raw_id(),
            content.raw_id(),
            "plain content_id should not change during reencrypt"
        );

        // Step 5: Save the CEK under the new ContentId
        self.cek_store
            .save(&content_id, &new_cek)
            .map_err(ReencryptError::KeyStore)?;

        // Step 6: Save the Content under the file key
        if let Err(e) = self.store(
            reencrypted_content.metadata().provider(),
            &reencrypted_content,
        ) {
            // Rollback:
            // - content_id is assumed not to change in this case, so delete is dangerous (it would
            //   also erase the old CEK)
            // - Restore the old CEK to keep consistency
            let _ = self.cek_store.save(&content_id, &old_cek);
            return Err(ReencryptError::ContentRepository(e));
        }

        // Step 7: Return the result
        let encrypted_content = reencrypted_content
            .encrypted_content()
            .ok_or(ReencryptError::MissingEncryptedContent)?
            .clone();

        Ok(ReencryptContentResult {
            encrypted_id: reencrypted_content.encrypted_id().clone(),
            raw_id: reencrypted_content.raw_id().clone(),
            metadata: reencrypted_content.metadata().clone(),
            encrypted_content,
        })
    }

    /// Returns the list of connected providers.
    pub fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
        self.content_repository.connected_providers()
    }

    /// Returns the current default provider.
    pub fn default_provider(&self) -> Result<String, ContentRepositoryError> {
        self.content_repository.default_provider()
    }

    /// Connects a storage provider (registers an auth token).
    pub fn connect_provider(
        &self,
        provider: String,
        access_token: String,
    ) -> Result<(), ContentRepositoryError> {
        self.content_repository
            .connect_provider(&provider, access_token)
    }

    /// Disconnects a storage provider (removes the auth token).
    pub fn disconnect_provider(&self, provider: String) -> Result<(), ContentRepositoryError> {
        self.content_repository.disconnect_provider(&provider)
    }

    /// Copies existing content to another provider.
    ///
    /// E.g., backing up locally stored content to the cloud.
    pub fn copy_to(
        &self,
        from_provider: &str,
        to_provider: &str,
        content_id: &ContentId,
    ) -> Result<(), ContentRepositoryError> {
        let content = self
            .content_repository
            .find_from(from_provider, content_id)?
            .ok_or_else(|| ContentRepositoryError::Storage("content not found".to_string()))?;

        self.content_repository
            .save_to(to_provider, content_id, &content)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteError {
    #[error("content not found")]
    NotFound,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("key-store error: {0}")]
    KeyStore(ContentEncryptionKeyStoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("key-store error: {0}")]
    KeyStore(ContentEncryptionKeyStoreError),
    #[error("missing encrypted content")]
    MissingEncryptedContent,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("content not found")]
    NotFound,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("key-store error: {0}")]
    KeyStore(ContentEncryptionKeyStoreError),
    #[error("missing encrypted content")]
    MissingEncryptedContent,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("content not found")]
    NotFound,
    #[error("content is deleted")]
    Deleted,
    #[error("missing encryption key for content")]
    MissingKey,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("key-store error: {0}")]
    KeyStore(ContentEncryptionKeyStoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptWithCekError {
    #[error("content id mismatch: expected {expected}, actual {actual}")]
    ContentIdMismatch { expected: String, actual: String },
    #[error("domain error: {0:?}")]
    Domain(ContentError),
}

/// Result of [`ContentService::encrypt_with_cek`]: the version payload for the
/// state node and the plain id the plaintext addresses to.
#[derive(Debug)]
pub struct EncryptedWithCek {
    pub ciphertext: Vec<u8>,
    pub plain_content_id: ContentId,
}

/// Result of a verified relay read: the plaintext plus the verified node's
/// parent version CIDs (used by the caller for the monotonicity check).
#[derive(Debug)]
pub struct VerifiedRead {
    pub plaintext: Vec<u8>,
    pub parents: Vec<String>,
    /// The version payload exactly as the state node holds it, for a caller
    /// that adopts the version locally ([`ContentService::adopt_version`]).
    pub ciphertext: Vec<u8>,
    /// The content id the decrypted plaintext addresses to. Equal to the
    /// expected id when one was given; for a reader that could not know it
    /// (a share recipient reading a version newer than the one shared) it
    /// is the only place the id comes from.
    pub plain_content_id: ContentId,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifiedReadError {
    #[error("node verification failed: {0}")]
    NodeVerification(crate::infrastructure::node_verification::NodeVerificationError),
    #[error("key store error: {0:?}")]
    KeyStore(ContentEncryptionKeyStoreError),
    #[error("no content encryption key for this content")]
    MissingKey,
    #[error("decrypt failed: {0}")]
    Decrypt(DecryptWithCekError),
}

#[derive(Debug, thiserror::Error)]
pub enum ReencryptError {
    #[error("content not found")]
    ContentNotFound,
    #[error("content is deleted")]
    ContentDeleted,
    #[error("missing content encryption key")]
    MissingContentEncryptionKey,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("content repository error: {0}")]
    ContentRepository(ContentRepositoryError),
    #[error("key-store error: {0}")]
    KeyStore(ContentEncryptionKeyStoreError),
    #[error("missing encrypted content")]
    MissingEncryptedContent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_service::content_service::ContentRepository;
    use crate::domain::{
        content::encryption::{ContentEncryptionKey, ContentEncryptionKeyGenerator},
        content::ContentStatus,
        content_id::{ContentId, ContentIdGenerator},
    };
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Simple ContentIdGenerator for tests.
    #[derive(Clone)]
    struct TestIdGenerator;

    impl ContentIdGenerator for TestIdGenerator {
        fn generate(&self, raw_content: &[u8]) -> ContentId {
            ContentId::new(format!("test-id-{}", raw_content.len()))
        }

        fn generate_encrypted(&self, plain_cid: &ContentId, ciphertext: &[u8]) -> ContentId {
            let mut hasher = Sha256::new();
            hasher.update(plain_cid.as_str().as_bytes());
            hasher.update([0u8]);
            hasher.update(ciphertext);
            let digest = hasher.finalize();
            ContentId::new(format!("test-enc-id-{}", hex::encode(digest)))
        }

        fn generate_series(&self, initial_plain_cid: &ContentId, created_at: u64) -> ContentId {
            ContentId::new(format!(
                "test-series-{}-{created_at}",
                initial_plain_cid.as_str()
            ))
        }
    }

    /// Fixed key generator for tests.
    #[derive(Clone)]
    struct TestKeyGenerator;

    impl ContentEncryptionKeyGenerator for TestKeyGenerator {
        fn generate(&self) -> ContentEncryptionKey {
            ContentEncryptionKey(vec![1, 2, 3])
        }
    }

    /// Test key generator that returns a different CEK on each call (reproduces the key changing
    /// between create and reencrypt).
    #[derive(Clone)]
    struct ToggleKeyGenerator {
        state: Arc<Mutex<bool>>,
        first: ContentEncryptionKey,
        second: ContentEncryptionKey,
    }

    impl ToggleKeyGenerator {
        fn new(first: ContentEncryptionKey, second: ContentEncryptionKey) -> Self {
            Self {
                state: Arc::new(Mutex::new(false)),
                first,
                second,
            }
        }
    }

    impl ContentEncryptionKeyGenerator for ToggleKeyGenerator {
        fn generate(&self) -> ContentEncryptionKey {
            let mut guard = self.state.lock().expect("mutex poisoned");
            if !*guard {
                *guard = true;
                self.first.clone()
            } else {
                self.second.clone()
            }
        }
    }

    /// Test encryption implementation that always succeeds (dummy).
    #[derive(Clone)]
    struct TestEncryptor;

    impl ContentEncryption for TestEncryptor {
        fn encrypt(
            &self,
            _key: &ContentEncryptionKey,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            // No real encryption here; just return a copy.
            Ok(plaintext.to_vec())
        }

        fn decrypt(
            &self,
            _key: &ContentEncryptionKey,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            Ok(ciphertext.to_vec())
        }
    }

    /// Test encryption whose ciphertext depends on the CEK.
    ///
    /// - encrypt: `ciphertext = key_bytes || plaintext`
    /// - decrypt: discards the leading `key_len` bytes and returns the rest as plaintext
    ///
    /// Note: not for security purposes; implemented to reproduce "if the CEK changes, the
    /// ciphertext changes too" in tests.
    #[derive(Clone)]
    struct KeyPrefixEncryptor {
        key_len: usize,
    }

    impl KeyPrefixEncryptor {
        fn new(key_len: usize) -> Self {
            Self { key_len }
        }
    }

    impl ContentEncryption for KeyPrefixEncryptor {
        fn encrypt(
            &self,
            key: &ContentEncryptionKey,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            let mut out = Vec::with_capacity(self.key_len + plaintext.len());
            // If the key is short, zero-pad it to a fixed length (for test convenience)
            if key.0.len() >= self.key_len {
                out.extend_from_slice(&key.0[..self.key_len]);
            } else {
                out.extend_from_slice(&key.0);
                out.extend(std::iter::repeat_n(0u8, self.key_len - key.0.len()));
            }
            out.extend_from_slice(plaintext);
            Ok(out)
        }

        fn decrypt(
            &self,
            _key: &ContentEncryptionKey,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            if ciphertext.len() < self.key_len {
                return Err(ContentError::DecryptionError(
                    "ciphertext too short for key prefix".into(),
                ));
            }
            Ok(ciphertext[self.key_len..].to_vec())
        }
    }

    /// Test implementation that always fails on encryption (to trigger a domain error).
    #[derive(Clone)]
    #[allow(dead_code)]
    struct FailingEncryptor;

    impl ContentEncryption for FailingEncryptor {
        fn encrypt(
            &self,
            _key: &ContentEncryptionKey,
            _plaintext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            Err(ContentError::EncryptionError(
                "encryption failed in test".into(),
            ))
        }

        fn decrypt(
            &self,
            _key: &ContentEncryptionKey,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            Err(ContentError::DecryptionError(
                "decryption failed in test".into(),
            ))
        }
    }

    /// Test repository backed by an internal Arc<Mutex<HashMap<...>>>.
    #[derive(Clone)]
    struct TestContentRepository {
        inner: Arc<Mutex<HashMap<String, Content>>>,
        fail_on_save: bool,
    }

    impl TestContentRepository {
        fn new(fail_on_save: bool) -> (Self, Arc<Mutex<HashMap<String, Content>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
                    fail_on_save,
                },
                inner,
            )
        }
    }

    impl ContentRepository for TestContentRepository {
        fn save(
            &self,
            content_id: &ContentId,
            content: &Content,
        ) -> Result<(), ContentRepositoryError> {
            if self.fail_on_save {
                return Err(ContentRepositoryError::Storage(
                    "save failed (test)".to_string(),
                ));
            }

            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;

            guard.insert(content_id.as_str().to_string(), content.clone());
            Ok(())
        }

        fn find_by_id(
            &self,
            content_id: &ContentId,
        ) -> Result<Option<Content>, ContentRepositoryError> {
            let guard = self
                .inner
                .lock()
                .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;

            Ok(guard.get(content_id.as_str()).cloned())
        }
    }

    impl MultiStorageContentRepository for TestContentRepository {
        fn save_to(
            &self,
            _provider: &str,
            content_id: &ContentId,
            content: &Content,
        ) -> Result<(), ContentRepositoryError> {
            // For tests: ignore the provider and delegate to the regular save
            self.save(content_id, content)
        }

        fn find_from(
            &self,
            _provider: &str,
            content_id: &ContentId,
        ) -> Result<Option<Content>, ContentRepositoryError> {
            // For tests: ignore the provider and delegate to the regular find_by_id
            self.find_by_id(content_id)
        }

        fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
            Ok(vec!["test".to_string()])
        }

        fn default_provider(&self) -> Result<String, ContentRepositoryError> {
            Ok("test".to_string())
        }

        fn connect_provider(
            &self,
            _provider: &str,
            _access_token: String,
        ) -> Result<(), ContentRepositoryError> {
            Ok(())
        }

        fn disconnect_provider(&self, _provider: &str) -> Result<(), ContentRepositoryError> {
            Ok(())
        }
    }

    /// In-memory CEK store for tests.
    #[derive(Clone, Default)]
    struct TestKeyStore {
        inner: Arc<Mutex<HashMap<String, ContentEncryptionKey>>>,
        fail_on_save: bool,
        fail_on_delete: bool,
    }

    impl TestKeyStore {
        fn new(
            fail_on_save: bool,
            fail_on_delete: bool,
        ) -> (Self, Arc<Mutex<HashMap<String, ContentEncryptionKey>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
                    fail_on_save,
                    fail_on_delete,
                },
                inner,
            )
        }
    }

    impl ContentEncryptionKeyStore for TestKeyStore {
        fn save(
            &self,
            content_id: &ContentId,
            key: &ContentEncryptionKey,
        ) -> Result<(), ContentEncryptionKeyStoreError> {
            if self.fail_on_save {
                return Err(ContentEncryptionKeyStoreError::Storage(
                    "save failed (test)".to_string(),
                ));
            }

            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

            guard.insert(content_id.as_str().to_string(), key.clone());
            Ok(())
        }

        fn load(
            &self,
            content_id: &ContentId,
        ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError> {
            let guard = self
                .inner
                .lock()
                .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

            Ok(guard.get(content_id.as_str()).cloned())
        }

        fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError> {
            if self.fail_on_delete {
                return Err(ContentEncryptionKeyStoreError::Storage(
                    "delete failed (test)".to_string(),
                ));
            }

            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

            guard.remove(content_id.as_str());
            Ok(())
        }
    }

    /// Builds bytes in the same CBOR shape as a crsl-lib `Node`
    /// (the minimal structure accepted by `node_verification`).
    fn make_test_node_bytes(ciphertext: &[u8]) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Payload<'a> {
            data: &'a [u8],
            access_policy: Option<()>,
        }
        #[derive(serde::Serialize)]
        struct Metadata {
            policy_type: Option<()>,
        }
        #[derive(serde::Serialize)]
        struct Node<'a> {
            payload: Payload<'a>,
            parents: Vec<()>,
            genesis: Option<()>,
            timestamp: u64,
            metadata: Metadata,
        }
        serde_cbor::to_vec(&Node {
            payload: Payload {
                data: ciphertext,
                access_policy: None,
            },
            parents: vec![],
            genesis: None,
            timestamp: 0,
            metadata: Metadata { policy_type: None },
        })
        .unwrap()
    }

    fn build_service<R, K, E, S>(
        repo: R,
        key_gen: K,
        encryptor: E,
        key_store: S,
    ) -> ContentService<TestIdGenerator, R, K, E, S>
    where
        R: MultiStorageContentRepository,
        K: ContentEncryptionKeyGenerator,
        E: ContentEncryption,
        S: ContentEncryptionKeyStore,
    {
        ContentService {
            content_id_generator: TestIdGenerator,
            content_repository: repo,
            key_generator: key_gen,
            encryptor,
            cek_store: key_store,
        }
    }

    #[derive(Clone)]
    struct FailOnSecondSaveContentRepository {
        inner: Arc<Mutex<HashMap<String, Content>>>,
        save_count: Arc<Mutex<usize>>,
    }

    impl FailOnSecondSaveContentRepository {
        fn new() -> (Self, Arc<Mutex<HashMap<String, Content>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            let repo = Self {
                inner: inner.clone(),
                save_count: Arc::new(Mutex::new(0)),
            };
            (repo, inner)
        }
    }

    impl ContentRepository for FailOnSecondSaveContentRepository {
        fn save(
            &self,
            content_id: &ContentId,
            content: &Content,
        ) -> Result<(), ContentRepositoryError> {
            let mut cnt = self
                .save_count
                .lock()
                .map_err(|e| ContentRepositoryError::Storage(format!("mutex poisoned: {e}")))?;
            *cnt += 1;
            if *cnt >= 2 {
                return Err(ContentRepositoryError::Storage(
                    "save failed on second call (test)".into(),
                ));
            }

            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;
            guard.insert(content_id.as_str().to_string(), content.clone());
            Ok(())
        }

        fn find_by_id(
            &self,
            content_id: &ContentId,
        ) -> Result<Option<Content>, ContentRepositoryError> {
            let guard = self
                .inner
                .lock()
                .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;
            Ok(guard.get(content_id.as_str()).cloned())
        }
    }

    impl MultiStorageContentRepository for FailOnSecondSaveContentRepository {
        fn save_to(
            &self,
            _provider: &str,
            content_id: &ContentId,
            content: &Content,
        ) -> Result<(), ContentRepositoryError> {
            // For tests: ignore the provider and delegate to the regular save (shares the behavior of
            // failing on the second call)
            self.save(content_id, content)
        }

        fn find_from(
            &self,
            _provider: &str,
            content_id: &ContentId,
        ) -> Result<Option<Content>, ContentRepositoryError> {
            // For tests: ignore the provider and delegate to the regular find_by_id
            self.find_by_id(content_id)
        }

        fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
            Ok(vec!["test".to_string()])
        }

        fn default_provider(&self) -> Result<String, ContentRepositoryError> {
            Ok("test".to_string())
        }

        fn connect_provider(
            &self,
            _provider: &str,
            _access_token: String,
        ) -> Result<(), ContentRepositoryError> {
            Ok(())
        }

        fn disconnect_provider(&self, _provider: &str) -> Result<(), ContentRepositoryError> {
            Ok(())
        }
    }

    #[test]
    fn create_success_persists_content() {
        let (repo, storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let cmd = CreateContentCommand {
            name: "test".into(),
            path: "path.txt".into(),
            raw_content: b"hello".to_vec(),
            provider: None,
        };

        let result = service.create(cmd).expect("create should succeed");

        assert_eq!(result.metadata.name(), "test");
        assert_eq!(result.metadata.path(), "path.txt");

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(result.series_id.as_str())
            .expect("content should be stored");
        assert!(!stored.is_deleted());
        assert_eq!(stored.content_status(), &ContentStatus::Active);
    }

    #[test]
    fn fetch_encrypted_returns_stored_ciphertext() {
        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let created = service
            .create(CreateContentCommand {
                name: "test".into(),
                path: "path.txt".into(),
                raw_content: b"hello".to_vec(),
                provider: None,
            })
            .expect("create should succeed");

        let encrypted = service
            .fetch_encrypted(created.series_id.clone())
            .expect("fetch_encrypted should succeed");
        // Contract: exactly the ciphertext produced at create time — the same
        // bytes create() sent to the state node, so the verify-integrity
        // comparison holds. (The test encryptor may be identity, so comparing
        // against the plaintext would be meaningless here.)
        assert_eq!(encrypted, created.encrypted_content);

        // Round-trip sanity: the plaintext fetch decrypts the same bytes.
        let fetched = service
            .fetch(created.series_id, None)
            .expect("fetch should succeed");
        assert_eq!(fetched.raw_content, b"hello".to_vec());
    }

    /// Two files created from the same body each keep their own record and CEK (no overwrite).
    #[test]
    fn two_files_with_the_same_body_keep_separate_records_and_keys() {
        let (repo, storage) = TestContentRepository::new(false);
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);
        let create = || {
            service
                .create(CreateContentCommand {
                    name: "same".into(),
                    path: "same.txt".into(),
                    raw_content: b"same body".to_vec(),
                    provider: None,
                })
                .expect("create should succeed")
        };
        let (a, b) = (create(), create());
        assert_eq!(a.content_id, b.content_id, "same plainCid");
        assert_ne!(a.series_id, b.series_id, "different files");
        assert_eq!(storage.lock().unwrap().len(), 2);
        assert_eq!(key_storage.lock().unwrap().len(), 2);
    }

    #[test]
    fn fetch_encrypted_not_found_for_unknown_content() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let result = service.fetch_encrypted(ContentId::new("missing".to_string()));
        assert!(matches!(result, Err(FetchError::NotFound)));
    }

    #[test]
    fn create_validation_error_when_name_is_empty() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let cmd = CreateContentCommand {
            name: "   ".into(),
            path: "path.txt".into(),
            raw_content: b"hello".to_vec(),
            provider: None,
        };

        let err = match service.create(cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected validation error but got Ok"),
        };
        assert!(matches!(err, CreateError::Validation(_)));
    }

    #[test]
    fn update_success_changes_content_and_name() {
        let (repo, storage) = TestContentRepository::new(false);
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo.clone(), TestKeyGenerator, TestEncryptor, key_store);

        let base_cmd = CreateContentCommand {
            name: "old".into(),
            path: "path.txt".into(),
            raw_content: b"old-data".to_vec(),
            provider: None,
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let update_cmd = UpdateContentCommand {
            content_id: base_result.series_id.clone(),
            new_name: Some("new-name".into()),
            new_raw_content: Some(b"new-data".to_vec()),
            provider: None,
        };

        let updated = service.update(update_cmd).expect("update should succeed");
        assert_eq!(updated.metadata.name(), "new-name");
        assert_eq!(updated.series_id, base_result.series_id);
        assert_eq!(storage.lock().unwrap().len(), 1, "one record per file");

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(updated.series_id.as_str())
            .expect("updated content should be stored under the file key");
        assert_eq!(stored.metadata().name(), "new-name");

        let key_guard = key_storage.lock().unwrap();
        assert!(
            key_guard.get(updated.series_id.as_str()).is_some(),
            "CEK should stay under the file key"
        );
    }

    #[test]
    fn update_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let update_cmd = UpdateContentCommand {
            content_id: ContentId::new("unknown-id".into()),
            new_name: Some("name".into()),
            new_raw_content: None,
            provider: None,
        };

        let err = match service.update(update_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, UpdateError::NotFound));
    }

    #[test]
    fn delete_success_marks_content_deleted() {
        let (repo, storage) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo.clone(), TestKeyGenerator, TestEncryptor, key_store);

        let base_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
            provider: None,
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let delete_cmd = DeleteContentCommand {
            content_id: base_result.series_id.clone(),
            provider: None,
        };

        let result = service.delete(delete_cmd).expect("delete should succeed");
        assert_eq!(result.content_id, base_result.content_id);

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(base_result.series_id.as_str())
            .expect("deleted content should be stored");
        assert!(stored.is_deleted());
        assert_eq!(stored.content_status(), &ContentStatus::Deleted);
        assert!(stored.raw_content().is_none());
        assert!(stored.encrypted_content().is_none());
    }

    #[test]
    fn delete_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let delete_cmd = DeleteContentCommand {
            content_id: ContentId::new("unknown-id".into()),
            provider: None,
        };

        let err = match service.delete(delete_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, DeleteError::NotFound));
    }

    #[test]
    fn fetch_success_returns_decrypted_content() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let raw = b"hello-fetch".to_vec();

        let cmd = CreateContentCommand {
            name: "fetch-test".into(),
            path: "path.txt".into(),
            raw_content: raw.clone(),
            provider: None,
        };

        let created = service.create(cmd).expect("create should succeed");

        let fetched = service
            .fetch(created.series_id.clone(), None)
            .expect("fetch should succeed");

        assert_eq!(fetched.content_id, created.content_id);
        assert_eq!(fetched.metadata.path(), created.metadata.path());
        assert_eq!(fetched.raw_content, raw);
    }

    #[test]
    fn fetch_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let unknown_id = ContentId::new("unknown-id".into());

        let err = match service.fetch(unknown_id, None) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, FetchError::NotFound));
    }

    #[test]
    fn fetch_deleted_returns_deleted_error() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, _) = TestKeyStore::new(false, false);
        let service = build_service(repo.clone(), TestKeyGenerator, TestEncryptor, key_store);

        let cmd = CreateContentCommand {
            name: "to-delete".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
            provider: None,
        };
        let created = service.create(cmd).expect("create should succeed");

        let delete_cmd = DeleteContentCommand {
            content_id: created.series_id.clone(),
            provider: None,
        };
        service.delete(delete_cmd).expect("delete should succeed");

        let err = match service.fetch(created.series_id, None) {
            Err(e) => e,
            Ok(_) => panic!("expected deleted error but got Ok"),
        };
        assert!(matches!(err, FetchError::Deleted));
    }

    #[test]
    fn fetch_missing_key_returns_missing_key_error() {
        let (repo, _) = TestContentRepository::new(false);
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let cmd = CreateContentCommand {
            name: "no-key".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
            provider: None,
        };
        let created = service.create(cmd).expect("create should succeed");

        // Remove this content's entry from the CEK store to reproduce the "no key" state.
        {
            let mut guard = key_storage.lock().unwrap();
            guard.remove(created.series_id.as_str());
        }

        let err = match service.fetch(created.series_id, None) {
            Err(e) => e,
            Ok(_) => panic!("expected missing-key error but got Ok"),
        };
        assert!(matches!(err, FetchError::MissingKey));
    }

    #[test]
    fn decrypt_with_cek_success_when_content_id_matches() {
        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let plaintext = b"decrypt-cek-success".to_vec();
        let expected_cid = service.content_id_generator.generate(&plaintext);

        let key = ContentEncryptionKey(vec![1, 2, 3]);
        let ciphertext = plaintext.clone();

        let result = service
            .decrypt_with_cek(expected_cid.clone(), key, ciphertext)
            .expect("decrypt_with_cek should succeed when content_id matches");

        assert_eq!(result, plaintext);
    }

    /// `verify_and_decrypt_relay_read` prefers an explicitly passed CEK over
    /// the local CEK store.
    ///
    /// The store is merely a cache derived from the authoritative record (sender pin), and since
    /// it is written outside the CAS, reordered writes can roll it back to an older generation
    /// (the generation-N handler stalls after its CAS; meanwhile N+1 advances the authoritative
    ///  record and the cache; then N resumes and moves only the cache back to N).
    /// If read uses the CEK from the authoritative record, that rollback has no effect.
    #[test]
    fn verified_read_prefers_the_explicit_cek_over_the_store() {
        /// Encryptor that actually looks at the key. It only XORs with the key's first byte, but it
        /// lets tests observe "which CEK was used for decryption".
        struct KeySensitiveEncryptor;
        impl ContentEncryption for KeySensitiveEncryptor {
            fn encrypt(
                &self,
                key: &ContentEncryptionKey,
                plaintext: &[u8],
            ) -> Result<Vec<u8>, ContentError> {
                Ok(plaintext.iter().map(|b| b ^ key.0[0]).collect())
            }
            fn decrypt(
                &self,
                key: &ContentEncryptionKey,
                ciphertext: &[u8],
            ) -> Result<Vec<u8>, ContentError> {
                Ok(ciphertext.iter().map(|b| b ^ key.0[0]).collect())
            }
        }

        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, KeySensitiveEncryptor, key_store);

        // The (correct) CEK from the authoritative record, and the CEK from the rolled-back cache
        let authoritative = ContentEncryptionKey(vec![0x11]);
        let stale_cache = ContentEncryptionKey(vec![0x22]);

        let plaintext = b"authoritative-cek-wins".to_vec();
        let ciphertext = service
            .encryptor
            .encrypt(&authoritative, &plaintext)
            .expect("encrypt");
        let content_id = service.content_id_generator.generate(&plaintext);

        // The cache holds an older generation's CEK
        service
            .cek_store
            .save(&content_id, &stale_cache)
            .expect("save stale cache");

        let node_bytes = make_test_node_bytes(&ciphertext);
        let version =
            crate::infrastructure::node_verification::recompute_node_cid(&node_bytes).unwrap();

        // Passing the authoritative record's CEK decrypts successfully
        let read = service
            .verify_and_decrypt_relay_read(
                &node_bytes,
                &version,
                content_id.clone(),
                Some(authoritative),
            )
            .expect("the explicit CEK must be used");
        assert_eq!(read.plaintext, plaintext);

        // Without it, the rolled-back cache is used and the plaintext does not match
        // (= read breaks if it depends on this path)
        let fallback =
            service.verify_and_decrypt_relay_read(&node_bytes, &version, content_id, None);
        assert!(
            fallback.is_err() || fallback.unwrap().plaintext != plaintext,
            "the stale cache must not yield the correct plaintext"
        );
    }

    /// A share recipient reads a version the owner wrote after sharing: the
    /// CEK is filed under the id the share came in as, but the plaintext of
    /// the newer version addresses to a different id. The strict read must
    /// refuse (it cannot tell this from tampering); the any-version read must
    /// decrypt and report the id it derived.
    #[test]
    fn any_version_relay_read_decrypts_a_newer_version_and_reports_its_plain_id() {
        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let key = ContentEncryptionKey(vec![7]);
        let shared_plain = b"version one".to_vec();
        let shared_id = service.content_id_generator.generate(&shared_plain);
        service
            .cek_store
            .save(&shared_id, &key)
            .expect("save cek under the shared id");

        // The test id generator derives the id from the length, so make the
        // newer version a different length.
        let newer_plain = b"version two, longer".to_vec();
        let newer_id = service.content_id_generator.generate(&newer_plain);
        assert_ne!(shared_id, newer_id);
        let ciphertext = service
            .encryptor
            .encrypt(&key, &newer_plain)
            .expect("encrypt");
        let node_bytes = make_test_node_bytes(&ciphertext);
        let version =
            crate::infrastructure::node_verification::recompute_node_cid(&node_bytes).unwrap();

        let strict =
            service.verify_and_decrypt_relay_read(&node_bytes, &version, shared_id.clone(), None);
        assert!(
            matches!(
                strict,
                Err(VerifiedReadError::Decrypt(
                    DecryptWithCekError::ContentIdMismatch { .. }
                ))
            ),
            "the strict read must not accept a plaintext that addresses elsewhere"
        );

        let read = service
            .verify_and_decrypt_relay_read_any_version(&node_bytes, &version, shared_id, None)
            .expect("the any-version read decrypts under the shared CEK");
        assert_eq!(read.plaintext, newer_plain);
        assert_eq!(read.plain_content_id, newer_id);
    }

    #[test]
    fn decrypt_with_cek_returns_mismatch_error_when_content_id_differs() {
        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let plaintext = b"decrypt-cek-mismatch".to_vec();
        let actual_cid = service.content_id_generator.generate(&plaintext);
        let expected_cid = ContentId::new("some-other-id".into());

        let key = ContentEncryptionKey(vec![9, 9, 9]);
        let ciphertext = plaintext.clone();

        let err = service
            .decrypt_with_cek(expected_cid.clone(), key, ciphertext)
            .expect_err("decrypt_with_cek should fail when content_id mismatches");

        match err {
            DecryptWithCekError::ContentIdMismatch { expected, actual } => {
                assert_eq!(expected, expected_cid.as_str());
                assert_eq!(actual, actual_cid.as_str());
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn reencrypt_success_keeps_plain_content_id_but_updates_cek_and_encrypted_content() {
        let (repo, storage) = TestContentRepository::new(false);
        let (key_store, key_storage) = TestKeyStore::new(false, false);

        let old = ContentEncryptionKey(vec![1, 2, 3]);
        let new = ContentEncryptionKey(vec![9, 9, 9]);
        let key_gen = ToggleKeyGenerator::new(old.clone(), new.clone());
        let encryptor = KeyPrefixEncryptor::new(3);

        let service = build_service(repo, key_gen, encryptor, key_store);

        let create_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"same-plaintext".to_vec(),
            provider: None,
        };
        let created = service.create(create_cmd).expect("create should succeed");

        let before = {
            let guard = storage.lock().unwrap();
            guard
                .get(created.series_id.as_str())
                .expect("content should be stored")
                .clone()
        };

        // reencrypt (assuming no body)
        let re_cmd = ReencryptContentCommand {
            content_id: created.series_id.clone(),
        };
        let result = service.reencrypt(re_cmd).expect("reencrypt should succeed");

        // plainCid does not change
        assert_eq!(result.raw_id, created.content_id);

        // But the ciphertext changes because the CEK changed
        let after = {
            let guard = storage.lock().unwrap();
            guard
                .get(created.series_id.as_str())
                .expect("content should still be stored")
                .clone()
        };
        assert_ne!(
            before.encrypted_content().unwrap(),
            after.encrypted_content().unwrap()
        );
        assert_ne!(before.encrypted_id(), after.encrypted_id());
        assert_eq!(&result.encrypted_id, after.encrypted_id());

        // The CEK has also been updated to the new one
        let kguard = key_storage.lock().unwrap();
        assert_eq!(
            kguard
                .get(created.series_id.as_str())
                .expect("cek should exist"),
            &new
        );
    }

    #[test]
    fn reencrypt_rolls_back_cek_when_content_save_fails() {
        let (repo, _storage) = FailOnSecondSaveContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new(false, false);

        let old = ContentEncryptionKey(vec![1, 2, 3]);
        let new = ContentEncryptionKey(vec![9, 9, 9]);
        let key_gen = ToggleKeyGenerator::new(old.clone(), new.clone());
        let encryptor = KeyPrefixEncryptor::new(3);

        let service = build_service(repo, key_gen, encryptor, key_store);

        let create_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"same-plaintext".to_vec(),
            provider: None,
        };
        let created = service.create(create_cmd).expect("create should succeed");

        // After create, the old CEK
        {
            let kguard = key_storage.lock().unwrap();
            assert_eq!(
                kguard
                    .get(created.series_id.as_str())
                    .expect("cek should exist"),
                &old
            );
        }

        let re_cmd = ReencryptContentCommand {
            content_id: created.series_id.clone(),
        };
        let err = service
            .reencrypt(re_cmd)
            .expect_err("reencrypt should fail when repository save fails");
        assert!(matches!(err, ReencryptError::ContentRepository(_)));

        // Even after the failure, it is back to the old CEK (rollback)
        let kguard = key_storage.lock().unwrap();
        assert_eq!(
            kguard
                .get(created.series_id.as_str())
                .expect("cek should still exist"),
            &old
        );
    }

    #[test]
    fn reencrypt_missing_key_returns_error() {
        let (repo, _storage) = TestContentRepository::new(false);
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let service = build_service(repo, TestKeyGenerator, TestEncryptor, key_store);

        let create_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
            provider: None,
        };
        let created = service.create(create_cmd).expect("create should succeed");

        // Remove the CEK to reproduce MissingContentEncryptionKey
        {
            let mut guard = key_storage.lock().unwrap();
            guard.remove(created.series_id.as_str());
        }

        let re_cmd = ReencryptContentCommand {
            content_id: created.series_id,
        };
        let err = service
            .reencrypt(re_cmd)
            .expect_err("reencrypt should fail when CEK is missing");
        assert!(matches!(err, ReencryptError::MissingContentEncryptionKey));
    }
}
