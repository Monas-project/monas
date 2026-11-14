use crate::application_service::content_service::{ContentEncryptionKeyStore, ContentRepository};
use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content::Content;
use crate::domain::share::{
    encryption::KeyWrapping, key_envelope::KeyWrapAlgorithm, KeyEnvelope, Share,
};

use super::{
    GrantShareCommand, GrantShareResult, PublicKeyDirectory, RevokeShareCommand, RevokeShareResult,
    ShareApplicationError, ShareRepository, UpdateSharePermissionCommand,
    UpdateSharePermissionResult,
};

/// Application service for the content sharing use case.
///
/// - Independent of ContentService; its responsibility is limited to "sharing" (ACL and
///   KeyEnvelope generation / CEK decryption).
pub struct ShareService<SR, CR, KS, KD, KW> {
    pub share_repository: SR,
    pub content_repository: CR,
    pub cek_store: KS,
    pub public_key_directory: KD,
    pub key_wrapper: KW,
}

impl<SR, CR, KS, KD, KW> ShareService<SR, CR, KS, KD, KW>
where
    SR: ShareRepository,
    CR: ContentRepository,
    KS: ContentEncryptionKeyStore,
    KD: PublicKeyDirectory,
    KW: KeyWrapping,
{
    #[allow(clippy::too_many_arguments)]
    fn build_envelope_for_recipient(
        &self,
        content_id: &crate::domain::content_id::ContentId,
        sender_key_id: &crate::domain::share::KeyId,
        sender_private_key: &[u8],
        recipient_key_id: &crate::domain::share::KeyId,
        cek: &crate::domain::content::encryption::ContentEncryptionKey,
        ciphertext: &[u8],
        key_epoch: u64,
    ) -> Result<KeyEnvelope, ShareApplicationError> {
        let recipient_public_key = self
            .public_key_directory
            .find_public_key(recipient_key_id)
            .map_err(ShareApplicationError::PublicKeyDirectory)?
            .ok_or(ShareApplicationError::MissingPublicKey)?;

        let aad = crate::domain::share::encryption::EnvelopeAad {
            content_id,
            recipient_key_id,
            key_epoch,
        };
        let (enc, wrapped_cek) = self
            .key_wrapper
            .wrap_cek(cek, &recipient_public_key, sender_private_key, &aad)
            .map_err(|e| ShareApplicationError::KeyWrapping(format!("{e:?}")))?;

        let wrapped_recipient = crate::domain::share::WrappedRecipientKey::new(
            recipient_key_id.clone(),
            enc,
            wrapped_cek,
        );

        Ok(KeyEnvelope::new(
            content_id.clone(),
            crate::domain::share::key_envelope::KeyWrapAlgorithm::HpkeV1,
            sender_key_id.clone(),
            wrapped_recipient,
            ciphertext.to_vec(),
            key_epoch,
        ))
    }

    /// Reads the share settings for `content`'s file (file key = `series_id`).
    fn load_share_of(&self, content: &Content) -> Result<Option<Share>, ShareApplicationError> {
        self.share_repository
            .load(content.series_id())
            .map_err(ShareApplicationError::ShareRepository)
    }

    /// Looks up the current record of file `series_id` (rejects deleted ones).
    fn current_record(
        &self,
        series_id: &crate::domain::content_id::ContentId,
    ) -> Result<Content, ShareApplicationError> {
        let content = self
            .content_repository
            .find_by_id(series_id)
            .map_err(ShareApplicationError::ContentRepository)?
            .ok_or(ShareApplicationError::ContentNotFound)?;
        if content.is_deleted() {
            return Err(ShareApplicationError::ContentDeleted);
        }
        Ok(content)
    }

    /// The file's current CEK.
    fn current_cek(
        &self,
        content: &Content,
    ) -> Result<ContentEncryptionKey, ShareApplicationError> {
        self.cek_store
            .load(content.series_id())
            .map_err(ShareApplicationError::ContentEncryptionKeyStore)?
            .ok_or(ShareApplicationError::MissingContentEncryptionKey)
    }

    /// Returns the current share state (ACL) for the specified file.
    ///
    /// - `series_id` is the file key.
    /// - Returns Ok(None) if the Share has never been saved.
    pub fn get_share(
        &self,
        series_id: crate::domain::content_id::ContentId,
    ) -> Result<Option<Share>, ShareApplicationError> {
        self.share_repository
            .load(&series_id)
            .map_err(ShareApplicationError::ShareRepository)
    }

    /// Grants a share to a single recipient and generates a KeyEnvelope for that recipient.
    pub fn grant_share(
        &self,
        cmd: GrantShareCommand,
    ) -> Result<GrantShareResult, ShareApplicationError> {
        // 1. Check the content body and encryption state (`content_id` is the file key).
        //    The wrapped CEK, the ciphertext, and the AAD's plainCid all belong to this file's
        //    current version.
        let content = self.current_record(&cmd.content_id)?;
        let plain_content_id = content.raw_id().clone();

        let ciphertext = content
            .encrypted_content()
            .cloned()
            .ok_or(ShareApplicationError::MissingEncryptedContent)?;

        // 2. Fetch the CEK
        let cek = self.current_cek(&content)?;

        // 3. Compute the KeyId
        let recipient_key_id = self
            .public_key_directory
            .compute_key_id(&cmd.recipient_public_key);

        // 4. Load the Share (share settings are per file = keyed by series ID)
        let mut share = self
            .load_share_of(&content)?
            .unwrap_or_else(|| Share::new(content.series_id().clone()));

        // 5. Validate the Share's domain rules
        let event = match cmd.permission {
            crate::domain::share::Permission::Read => share.grant_read(recipient_key_id.clone()),
            crate::domain::share::Permission::Write => share.grant_write(recipient_key_id.clone()),
            crate::domain::share::Permission::Owner => share.grant_owner(recipient_key_id.clone()),
        }
        .map_err(ShareApplicationError::Share)?;

        let _ = event;

        // 6. Wrap the CEK (HPKE Auth: sender authenticated with the sender's private key; the AAD
        //    binds the recipient and the key generation)
        let key_epoch = share.key_epoch();
        let aad = crate::domain::share::encryption::EnvelopeAad {
            content_id: &plain_content_id,
            recipient_key_id: &recipient_key_id,
            key_epoch,
        };
        let recipient_public_key = &cmd.recipient_public_key;
        let (enc, wrapped_cek) = self
            .key_wrapper
            .wrap_cek(&cek, recipient_public_key, &cmd.sender_private_key, &aad)
            .map_err(|e| ShareApplicationError::KeyWrapping(format!("{e:?}")))?;

        // 7. Register the public key
        self.public_key_directory
            .register_public_key(&cmd.recipient_public_key)
            .map_err(ShareApplicationError::PublicKeyDirectory)?;

        // 8. Save the Share (on failure, remove the public key to roll back)
        if let Err(e) = self.share_repository.save(&share) {
            // Compensating transaction: remove the public key to roll back
            let _ = self
                .public_key_directory
                .delete_public_key(&recipient_key_id);
            return Err(ShareApplicationError::ShareRepository(e));
        }
        // 9. Build the KeyEnvelope
        let wrapped_recipient = crate::domain::share::WrappedRecipientKey::new(
            recipient_key_id.clone(),
            enc,
            wrapped_cek,
        );

        let envelope = KeyEnvelope::new(
            plain_content_id,
            crate::domain::share::key_envelope::KeyWrapAlgorithm::HpkeV1,
            cmd.sender_key_id.clone(),
            wrapped_recipient,
            ciphertext,
            key_epoch,
        );

        Ok(GrantShareResult {
            envelope,
            recipient_key_id,
        })
    }

    /// Revokes the share relationship with the specified recipient.
    ///
    /// - Removes the recipient from the ACL, advances `key_epoch`, and reissues KeyEnvelopes
    ///   (under the current CEK and new epoch) for the remaining recipients, returning them.
    /// - Assumes the caller already ran reencrypt to rotate the CEK. Revoking or deleting
    ///   previously distributed KeyEnvelopes and deleting content are not handled here.
    pub fn revoke_share(
        &self,
        cmd: RevokeShareCommand,
    ) -> Result<RevokeShareResult, ShareApplicationError> {
        // 1. Check the content body and encryption state (needed to reissue KeyEnvelopes)
        let content = self.current_record(&cmd.content_id)?;
        let plain_content_id = content.raw_id().clone();

        let ciphertext = content
            .encrypted_content()
            .cloned()
            .ok_or(ShareApplicationError::MissingEncryptedContent)?;

        // 2. Fetch the CEK (after re-encryption, this is expected to be the new CEK)
        let cek = self.current_cek(&content)?;

        // 3. Load the Share and update the ACL. The CEK has been rotated (the caller
        //    ran reencrypt first), so also advance the key generation.
        let mut share = self
            .load_share_of(&content)?
            .ok_or(ShareApplicationError::ContentNotFound)?;

        share
            .revoke(&cmd.recipient_key_id)
            .map_err(ShareApplicationError::Share)?;
        share.bump_key_epoch();

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        // 4. Reissue KeyEnvelopes under the new key generation for the recipients remaining
        //    after revocation
        let mut recipient_key_ids: Vec<_> = share.recipients().keys().cloned().collect();
        recipient_key_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let mut envelopes = Vec::with_capacity(recipient_key_ids.len());
        for recipient_key_id in recipient_key_ids {
            let env = self.build_envelope_for_recipient(
                &plain_content_id,
                &cmd.sender_key_id,
                &cmd.sender_private_key,
                &recipient_key_id,
                &cek,
                &ciphertext,
                share.key_epoch(),
            )?;
            envelopes.push(env);
        }

        Ok(RevokeShareResult {
            content_id: plain_content_id,
            recipient_key_id: cmd.recipient_key_id,
            envelopes,
        })
    }

    /// Changes the permission of an existing recipient (ACL only).
    ///
    /// - Returns `Share(RecipientNotFound)` if the content is not shared with the recipient.
    /// - Does not change the CEK, key generation, or KeyEnvelope. The permission is carried by
    ///   the delegated Token, so reissuing the Token (and revoking the old Token on downgrade)
    ///   is done by the caller (SDK).
    pub fn update_share_permission(
        &self,
        cmd: UpdateSharePermissionCommand,
    ) -> Result<UpdateSharePermissionResult, ShareApplicationError> {
        let content = self.current_record(&cmd.content_id)?;

        let mut share = self
            .load_share_of(&content)?
            .ok_or(ShareApplicationError::Share(
                crate::domain::share::share::ShareError::RecipientNotFound,
            ))?;

        let previous = share
            .permissions_of(&cmd.recipient_key_id)
            .map(|p| p.to_vec())
            .unwrap_or_default();
        share
            .update_recipient_permissions(&cmd.recipient_key_id, vec![cmd.permission.clone()])
            .map_err(ShareApplicationError::Share)?;

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        Ok(UpdateSharePermissionResult {
            content_id: content.raw_id().clone(),
            recipient_key_id: cmd.recipient_key_id,
            previous,
            current: vec![cmd.permission],
        })
    }

    /// Decrypts (unwraps) the CEK from a KeyEnvelope and the recipient's private key bytes.
    ///
    /// - Assumes a separate service such as monas-account manages the private key and passes it
    ///   to this service as bytes.
    /// - `sender_public_key` is the sender public key the recipient expects (the key pinned via
    ///   TOFU). Since HPKE Auth mode is used, a successful unwrap proves that the holder of this
    ///   key created the envelope.
    /// - Currently only HpkeV1 is supported.
    pub fn unwrap_cek_from_envelope(
        &self,
        envelope: &KeyEnvelope,
        recipient_private_key: &[u8],
        sender_public_key: &[u8],
    ) -> Result<ContentEncryptionKey, ShareApplicationError> {
        match envelope.key_wrap_algorithm() {
            KeyWrapAlgorithm::HpkeV1 => {
                let recipient = envelope.recipient();
                let aad = crate::domain::share::encryption::EnvelopeAad {
                    content_id: envelope.content_id(),
                    recipient_key_id: recipient.key_id(),
                    key_epoch: envelope.key_epoch(),
                };
                self.key_wrapper
                    .unwrap_cek(
                        recipient.enc(),
                        recipient.wrapped_cek(),
                        recipient_private_key,
                        sender_public_key,
                        &aad,
                    )
                    .map_err(|e| ShareApplicationError::KeyWrapping(format!("{e:?}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ShareService;
    use crate::application_service::content_service::{
        ContentEncryptionKeyStore, ContentEncryptionKeyStoreError, ContentRepository,
        ContentRepositoryError,
    };
    use crate::application_service::share_service::{
        GrantShareCommand, PublicKeyDirectory, PublicKeyDirectoryError, RevokeShareCommand,
        ShareApplicationError, ShareRepository, ShareRepositoryError,
    };
    use crate::domain::{
        content::{Content, ContentEncryptionKey, Metadata},
        content_id::ContentId,
        share::{
            encryption::KeyWrapping,
            key_envelope::{KeyEnvelope, KeyWrapAlgorithm, WrappedRecipientKey},
            share::ShareError,
            Permission, Share,
        },
        KeyId,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct TestShareRepository {
        inner: Arc<Mutex<HashMap<String, Share>>>,
    }

    impl TestShareRepository {
        fn new() -> (Self, Arc<Mutex<HashMap<String, Share>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
                },
                inner,
            )
        }
    }

    impl ShareRepository for TestShareRepository {
        fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
            let guard = self
                .inner
                .lock()
                .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

            Ok(guard.get(content_id.as_str()).cloned())
        }

        fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

            guard.insert(share.content_id().as_str().to_string(), share.clone());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestContentRepository {
        inner: Arc<Mutex<HashMap<String, Content>>>,
    }

    impl TestContentRepository {
        fn new() -> (Self, Arc<Mutex<HashMap<String, Content>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
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

    #[derive(Clone)]
    struct TestKeyStore {
        inner: Arc<Mutex<HashMap<String, ContentEncryptionKey>>>,
    }

    impl TestKeyStore {
        fn new() -> (Self, Arc<Mutex<HashMap<String, ContentEncryptionKey>>>) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
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
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| ContentEncryptionKeyStoreError::Storage(e.to_string()))?;

            guard.remove(content_id.as_str());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestPublicKeyDirectory {
        registered: Arc<Mutex<Vec<Vec<u8>>>>,
        deleted: Arc<Mutex<Vec<KeyId>>>,
    }

    impl PublicKeyDirectory for TestPublicKeyDirectory {
        fn compute_key_id(&self, _public_key: &[u8]) -> KeyId {
            KeyId::new(vec![1, 2, 3])
        }

        fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
            let mut guard = self
                .registered
                .lock()
                .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
            guard.push(public_key.to_vec());
            Ok(KeyId::new(vec![1, 2, 3]))
        }

        fn find_public_key(
            &self,
            _key_id: &KeyId,
        ) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError> {
            let guard = self
                .registered
                .lock()
                .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
            Ok(guard.first().cloned())
        }

        fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError> {
            let mut guard = self
                .deleted
                .lock()
                .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
            guard.push(key_id.clone());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestKeyWrapper;

    impl KeyWrapping for TestKeyWrapper {
        fn wrap_cek(
            &self,
            _cek: &ContentEncryptionKey,
            _recipient_public_key: &[u8],
            _sender_private_key: &[u8],
            _aad: &crate::domain::share::encryption::EnvelopeAad<'_>,
        ) -> Result<(Vec<u8>, Vec<u8>), crate::domain::share::encryption::KeyWrappingError>
        {
            Ok((vec![0xAA, 0xBB], vec![0x11, 0x22, 0x33]))
        }

        fn unwrap_cek(
            &self,
            _enc: &[u8],
            wrapped_cek: &[u8],
            _recipient_private_key: &[u8],
            _sender_public_key: &[u8],
            _aad: &crate::domain::share::encryption::EnvelopeAad<'_>,
        ) -> Result<ContentEncryptionKey, crate::domain::share::encryption::KeyWrappingError>
        {
            Ok(ContentEncryptionKey(wrapped_cek.to_vec()))
        }
    }

    #[derive(Clone)]
    struct FailingKeyWrapper;

    impl KeyWrapping for FailingKeyWrapper {
        fn wrap_cek(
            &self,
            _cek: &ContentEncryptionKey,
            _recipient_public_key: &[u8],
            _sender_private_key: &[u8],
            _aad: &crate::domain::share::encryption::EnvelopeAad<'_>,
        ) -> Result<(Vec<u8>, Vec<u8>), crate::domain::share::encryption::KeyWrappingError>
        {
            Err(crate::domain::share::encryption::KeyWrappingError::Other(
                "wrap failed (test)".into(),
            ))
        }

        fn unwrap_cek(
            &self,
            _enc: &[u8],
            _wrapped_cek: &[u8],
            _recipient_private_key: &[u8],
            _sender_public_key: &[u8],
            _aad: &crate::domain::share::encryption::EnvelopeAad<'_>,
        ) -> Result<ContentEncryptionKey, crate::domain::share::encryption::KeyWrappingError>
        {
            Err(crate::domain::share::encryption::KeyWrappingError::Other(
                "unwrap failed (test)".into(),
            ))
        }
    }

    #[derive(Clone)]
    struct FailingSaveShareRepository;

    impl ShareRepository for FailingSaveShareRepository {
        fn load(&self, _content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
            Ok(None)
        }

        fn save(&self, _share: &Share) -> Result<(), ShareRepositoryError> {
            Err(ShareRepositoryError::Storage(
                "save failed (test)".to_string(),
            ))
        }
    }

    fn cid() -> ContentId {
        ContentId::new("test-content-id".into())
    }

    fn sender_key_id() -> KeyId {
        KeyId::new(vec![9])
    }

    fn cek() -> ContentEncryptionKey {
        ContentEncryptionKey(vec![0x10, 0x20, 0x30])
    }

    fn encrypted() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    }

    fn build_content(
        cid: &ContentId,
        encrypted_content: Option<Vec<u8>>,
        deleted: bool,
    ) -> Content {
        let metadata = Metadata::new("name".into(), "/path".into(), cid.clone(), None);
        Content::new(
            cid.clone(),
            metadata,
            Some(b"raw-content".to_vec()),
            encrypted_content,
            deleted,
        )
    }

    fn build_service<KW>(
        share_repo: TestShareRepository,
        content_repo: TestContentRepository,
        key_store: TestKeyStore,
        public_key_dir: TestPublicKeyDirectory,
        key_wrapper: KW,
    ) -> ShareService<
        TestShareRepository,
        TestContentRepository,
        TestKeyStore,
        TestPublicKeyDirectory,
        KW,
    >
    where
        KW: KeyWrapping,
    {
        ShareService {
            share_repository: share_repo,
            content_repository: content_repo,
            cek_store: key_store,
            public_key_directory: public_key_dir,
            key_wrapper,
        }
    }

    #[test]
    fn unwrap_cek_from_envelope_success() {
        let (share_repo, _share_storage) = TestShareRepository::new();
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cid = cid();
        let recipient_key_id = sender_key_id();
        let wrapped_cek_bytes = vec![0x11, 0x22, 0x33];
        let recipient = WrappedRecipientKey::new(
            recipient_key_id,
            vec![0xAA, 0xBB],
            wrapped_cek_bytes.clone(),
        );
        let envelope = KeyEnvelope::new(
            cid.clone(),
            KeyWrapAlgorithm::HpkeV1,
            sender_key_id(),
            recipient,
            encrypted(),
            0,
        );

        let recipient_private_key = vec![0x99, 0x88];

        let result = service
            .unwrap_cek_from_envelope(&envelope, &recipient_private_key, &[0x04; 65])
            .expect("unwrap_cek_from_envelope should succeed");

        assert_eq!(result.0, wrapped_cek_bytes);
    }

    #[test]
    fn unwrap_cek_from_envelope_propagates_key_wrapper_error() {
        let (share_repo, _share_storage) = TestShareRepository::new();
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = FailingKeyWrapper;

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cid = cid();
        let recipient_key_id = sender_key_id();
        let recipient =
            WrappedRecipientKey::new(recipient_key_id, vec![0xAA, 0xBB], vec![0x11, 0x22, 0x33]);
        let envelope = KeyEnvelope::new(
            cid.clone(),
            KeyWrapAlgorithm::HpkeV1,
            sender_key_id(),
            recipient,
            encrypted(),
            0,
        );

        let recipient_private_key = vec![0x99, 0x88];

        let err = service
            .unwrap_cek_from_envelope(&envelope, &recipient_private_key, &[0x04; 65])
            .expect_err("unwrap_cek_from_envelope should propagate key wrapper error");

        assert!(matches!(err, ShareApplicationError::KeyWrapping(_)));
    }

    #[test]
    fn grant_share_success_creates_envelope_and_updates_acl() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content.clone());
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let service = build_service(
            share_repo.clone(),
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid.clone(),
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3, 4],
            permission: Permission::Read,
        };

        let result = service
            .grant_share(cmd)
            .expect("grant_share should succeed");

        assert_eq!(result.envelope.content_id(), &cid);
        assert_eq!(result.envelope.sender_key_id(), &sender_key_id());
        assert_eq!(result.envelope.ciphertext(), encrypted().as_slice());
        assert_eq!(
            result.envelope.recipient().key_id(),
            &result.recipient_key_id
        );

        let guard = share_storage.lock().unwrap();
        let stored_share = guard
            .get(cid.as_str())
            .expect("share should be stored after grant");
        let perms = stored_share
            .permissions_of(&result.recipient_key_id)
            .expect("recipient should exist");
        assert_eq!(perms, &[Permission::Read]);
    }

    #[test]
    fn grant_share_with_write_sets_write_permission_and_implies_read() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content.clone());
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let service = build_service(
            share_repo.clone(),
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid.clone(),
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3, 4],
            permission: Permission::Write,
        };

        let result = service
            .grant_share(cmd)
            .expect("grant_share with write should succeed");

        let guard = share_storage.lock().unwrap();
        let stored_share = guard
            .get(cid.as_str())
            .expect("share should be stored after grant");
        let perms = stored_share
            .permissions_of(&result.recipient_key_id)
            .expect("recipient should exist");

        assert_eq!(perms, &[Permission::Write]);
        assert!(Permission::can_read(perms));
        assert!(Permission::can_write(perms));
    }

    #[test]
    fn grant_share_fails_when_content_not_found() {
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid(),
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when content is missing");
        assert!(matches!(err, ShareApplicationError::ContentNotFound));
    }

    #[test]
    fn grant_share_fails_when_content_deleted() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let deleted_content = build_content(&cid, Some(encrypted()), true);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), deleted_content);
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail for deleted content");
        assert!(matches!(err, ShareApplicationError::ContentDeleted));
    }

    #[test]
    fn grant_share_fails_when_missing_encrypted_content() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content_without_cipher = build_content(&cid, None, false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content_without_cipher);
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when encrypted content is missing");
        assert!(matches!(
            err,
            ShareApplicationError::MissingEncryptedContent
        ));
    }

    #[test]
    fn grant_share_fails_when_missing_cek() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content);
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when CEK is missing");
        assert!(matches!(
            err,
            ShareApplicationError::MissingContentEncryptionKey
        ));
    }

    #[test]
    fn grant_share_fails_when_already_shared() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content);
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let mut share = Share::new(cid.clone());
        let kid = KeyId::new(vec![1, 2, 3]);
        share
            .grant_read(kid.clone())
            .expect("initial grant_read should succeed");
        {
            let mut guard = share_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), share);
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![9, 9, 9],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when already shared");
        assert!(matches!(
            err,
            ShareApplicationError::Share(ShareError::AlreadyShared)
        ));
    }

    #[test]
    fn grant_share_propagates_key_wrapping_error() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = FailingKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content);
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when key wrapping fails");
        assert!(matches!(err, ShareApplicationError::KeyWrapping(_)));
    }

    #[test]
    fn grant_share_rollbacks_public_key_when_share_save_fails() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let share_repo = FailingSaveShareRepository;
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content);
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let service = ShareService {
            share_repository: share_repo,
            content_repository: content_repo,
            cek_store: key_store,
            public_key_directory: public_key_dir.clone(),
            key_wrapper,
        };

        let cmd = GrantShareCommand {
            content_id: cid,
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_public_key: vec![1, 2, 3, 4],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when share save fails");
        assert!(matches!(err, ShareApplicationError::ShareRepository(_)));

        let registered = public_key_dir.registered.lock().unwrap();
        assert_eq!(
            registered.len(),
            1,
            "public key should have been registered"
        );

        let deleted = public_key_dir.deleted.lock().unwrap();
        assert_eq!(
            deleted.len(),
            1,
            "delete_public_key should have been called for rollback"
        );
        assert_eq!(
            deleted[0],
            KeyId::new(vec![1, 2, 3]),
            "correct key_id should be deleted"
        );
    }

    #[test]
    fn revoke_share_success_updates_acl() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let content_id = cid();
        let revoked_kid = KeyId::new(vec![1, 2, 3]);
        let remaining_kid = KeyId::new(vec![4, 5, 6]);
        let sender = sender_key_id();

        // revoke_share needs the content (ciphertext) and the CEK to reissue KeyEnvelopes
        let content = build_content(&content_id, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(content_id.as_str().to_string(), content);
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(content_id.as_str().to_string(), cek());
        }

        let mut share = Share::new(content_id.clone());
        share
            .grant_read(revoked_kid.clone())
            .expect("initial grant_read (revoked) should succeed");
        share
            .grant_read(remaining_kid.clone())
            .expect("initial grant_read should succeed");
        {
            let mut guard = share_storage.lock().unwrap();
            guard.insert(content_id.as_str().to_string(), share);
        }

        // build_envelope_for_recipient needs a public key directory lookup (the implementation
        // just returns the first one)
        public_key_dir
            .register_public_key(&[1, 2, 3, 4])
            .expect("public key registration should succeed");

        let service = build_service(
            share_repo.clone(),
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = RevokeShareCommand {
            content_id: content_id.clone(),
            sender_key_id: sender.clone(),
            sender_private_key: vec![0x55; 32],
            recipient_key_id: revoked_kid.clone(),
        };

        let result = service
            .revoke_share(cmd)
            .expect("revoke_share should succeed");
        assert_eq!(result.content_id, content_id);
        assert_eq!(result.recipient_key_id, revoked_kid);

        // KeyEnvelopes are reissued for the recipients remaining after revocation
        assert_eq!(result.envelopes.len(), 1);
        let env = &result.envelopes[0];
        assert_eq!(env.content_id(), &content_id);
        assert_eq!(env.sender_key_id(), &sender);
        assert_eq!(env.recipient().key_id(), &remaining_kid);
        assert_eq!(env.ciphertext(), encrypted().as_slice());

        let guard = share_storage.lock().unwrap();
        let stored_share = guard
            .get(content_id.as_str())
            .expect("share should still exist after revoke");
        assert_eq!(stored_share.recipients().len(), 1);
        assert!(stored_share.recipients().contains_key(&remaining_kid));
    }

    #[test]
    fn revoke_share_fails_when_share_not_found() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        // revoke_share references content/ciphertext and the CEK before loading the share
        let cid = cid();
        let content = build_content(&cid, Some(encrypted()), false);
        {
            let mut guard = content_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), content);
        }
        {
            let mut guard = key_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), cek());
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = RevokeShareCommand {
            content_id: cid.clone(),
            sender_key_id: sender_key_id(),
            sender_private_key: vec![0x55; 32],
            recipient_key_id: KeyId::new(vec![1]),
        };

        let err = service
            .revoke_share(cmd)
            .expect_err("revoke_share should fail when share does not exist");
        assert!(matches!(err, ShareApplicationError::ContentNotFound));
    }

    #[test]
    fn update_share_permission_changes_acl_without_touching_epoch() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let content_id = cid();
        let kid = KeyId::new(vec![9, 9, 9]);
        content_storage.lock().unwrap().insert(
            content_id.as_str().to_string(),
            build_content(&content_id, Some(encrypted()), false),
        );
        let mut share = Share::new(content_id.clone());
        share.grant_read(kid.clone()).expect("grant_read");
        share_storage
            .lock()
            .unwrap()
            .insert(content_id.as_str().to_string(), share);

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );
        let result = service
            .update_share_permission(super::UpdateSharePermissionCommand {
                content_id: content_id.clone(),
                recipient_key_id: kid.clone(),
                permission: Permission::Write,
            })
            .expect("update should succeed");
        assert_eq!(result.previous, vec![Permission::Read]);
        assert_eq!(result.current, vec![Permission::Write]);

        let guard = share_storage.lock().unwrap();
        let stored = guard.get(content_id.as_str()).expect("share kept");
        assert_eq!(stored.permissions_of(&kid), Some(&[Permission::Write][..]));
        assert_eq!(stored.key_epoch(), 0, "a permission change must not rotate");
    }

    #[test]
    fn update_share_permission_fails_for_unknown_recipient() {
        let (content_repo, content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let content_id = cid();
        content_storage.lock().unwrap().insert(
            content_id.as_str().to_string(),
            build_content(&content_id, Some(encrypted()), false),
        );
        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            TestPublicKeyDirectory::default(),
            TestKeyWrapper,
        );
        let err = service
            .update_share_permission(super::UpdateSharePermissionCommand {
                content_id,
                recipient_key_id: KeyId::new(vec![1]),
                permission: Permission::Read,
            })
            .expect_err("unknown recipient");
        assert!(matches!(
            err,
            ShareApplicationError::Share(ShareError::RecipientNotFound)
        ));
    }

    #[test]
    fn get_share_returns_none_when_not_saved() {
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, _share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let result = service.get_share(cid()).expect("get_share should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn get_share_returns_existing_share() {
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let mut share = Share::new(cid.clone());
        let kid = KeyId::new(vec![1, 2, 3]);
        share
            .grant_read(kid)
            .expect("initial grant_read should succeed");
        {
            let mut guard = share_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), share.clone());
        }

        let service = build_service(
            share_repo,
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let result = service
            .get_share(cid)
            .expect("get_share should succeed")
            .expect("share should exist");
        assert_eq!(result.recipients().len(), 1);
    }

    /// Share settings and the CEK are looked up by file key (series_id), and what is wrapped is
    /// the current version (the record's ciphertext, with the current plainCid as AAD). Even if
    /// an edit changes plainCid, there is still only one share setting.
    #[test]
    fn share_is_keyed_by_the_file_and_wraps_the_current_version() {
        use crate::infrastructure::content_id::Sha256ContentIdGenerator;
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let service = build_service(
            share_repo,
            content_repo.clone(),
            key_store,
            TestPublicKeyDirectory::default(),
            TestKeyWrapper,
        );

        let v1 = build_content(&cid(), Some(encrypted()), false);
        let (v2, _) = v1
            .adopt_version(b"body B".to_vec(), vec![0xB2], &Sha256ContentIdGenerator)
            .unwrap();
        assert_ne!(v2.raw_id(), v1.raw_id());
        assert_eq!(v2.series_id(), v1.series_id());
        // One record per file key (the current version).
        content_repo.save(v2.series_id(), &v2).unwrap();
        service.cek_store.save(v2.series_id(), &cek()).unwrap();

        // The test public key directory always returns this KeyId.
        let bob = KeyId::new(vec![1, 2, 3]);
        let granted = service
            .grant_share(GrantShareCommand {
                content_id: v2.series_id().clone(),
                sender_key_id: sender_key_id(),
                sender_private_key: vec![1],
                recipient_public_key: vec![7],
                permission: Permission::Write,
            })
            .unwrap();
        assert_eq!(granted.envelope.content_id(), v2.raw_id());
        assert_eq!(granted.envelope.ciphertext(), &[0xB2][..]);

        service
            .update_share_permission(super::UpdateSharePermissionCommand {
                content_id: v2.series_id().clone(),
                recipient_key_id: bob.clone(),
                permission: Permission::Read,
            })
            .unwrap();
        let share = service
            .get_share(v2.series_id().clone())
            .unwrap()
            .expect("share");
        assert_eq!(share.permissions_of(&bob), Some(&[Permission::Read][..]));
        assert_eq!(share_storage.lock().unwrap().len(), 1, "one share per file");
    }
}
