use crate::application_service::content_service::{ContentEncryptionKeyStore, ContentRepository};
use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::share::{
    encryption::KeyWrapping, key_envelope::KeyWrapAlgorithm, KeyEnvelope, Share,
};

use super::{
    GrantShareCommand, GrantShareResult, PublicKeyDirectory, RevokeShareCommand, RevokeShareResult,
    ShareApplicationError, ShareRepository,
};

/// コンテンツ共有ユースケースのアプリケーションサービス。
///
/// - ContentService とは独立に、「共有（ACL と KeyEnvelope 生成 / CEK 復号）」に責務を限定する。
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
    /// 指定されたコンテンツに対する現在の共有状態（ACL）を取得する。
    ///
    /// - Share がまだ一度も保存されていない場合は Ok(None) を返す。
    pub fn get_share(
        &self,
        content_id: crate::domain::content_id::ContentId,
    ) -> Result<Option<Share>, ShareApplicationError> {
        self.share_repository
            .load(&content_id)
            .map_err(ShareApplicationError::ShareRepository)
    }

    /// 1 人の受信者に対して共有を付与し、その受信者向けの KeyEnvelope を生成する。
    pub fn grant_share(
        &self,
        cmd: GrantShareCommand,
    ) -> Result<GrantShareResult, ShareApplicationError> {
        // 1. コンテンツ本体と暗号化状態の確認
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(ShareApplicationError::ContentRepository)?
            .ok_or(ShareApplicationError::ContentNotFound)?;

        if content.is_deleted() {
            return Err(ShareApplicationError::ContentDeleted);
        }

        let ciphertext = content
            .encrypted_content()
            .cloned()
            .ok_or(ShareApplicationError::MissingEncryptedContent)?;

        // 2. CEK の取得
        let cek = self
            .cek_store
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ContentEncryptionKeyStore)?
            .ok_or(ShareApplicationError::MissingContentEncryptionKey)?;

        // 3. 受信者公開鍵を登録し、対応する KeyId を発行
        let recipient_key_id = self
            .public_key_directory
            .register_public_key(&cmd.recipient_public_key)
            .map_err(ShareApplicationError::PublicKeyDirectory)?;
        let recipient_public_key = &cmd.recipient_public_key;

        // 4. HPKE で CEK をラップ
        let (enc, wrapped_cek) = self
            .key_wrapper
            .wrap_cek(&cek, recipient_public_key, &cmd.content_id)
            .map_err(|e| ShareApplicationError::KeyWrapping(format!("{e:?}")))?;

        let wrapped_recipient = crate::domain::share::WrappedRecipientKey::new(
            recipient_key_id.clone(),
            enc,
            wrapped_cek,
        );

        // 5. KeyEnvelope を構築
        let envelope = KeyEnvelope::new(
            cmd.content_id.clone(),
            crate::domain::share::key_envelope::KeyWrapAlgorithm::HpkeV1,
            cmd.sender_key_id.clone(),
            wrapped_recipient,
            ciphertext,
        );

        // 6. Share (ACL) を更新
        let mut share = self
            .share_repository
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ShareRepository)?
            .unwrap_or_else(|| Share::new(cmd.content_id.clone()));

        let event = match cmd.permission {
            crate::domain::share::Permission::Read => share.grant_read(recipient_key_id.clone()),
            crate::domain::share::Permission::Write => share.grant_write(recipient_key_id.clone()),
        }
        .map_err(ShareApplicationError::Share)?;

        // NOTE: 現状では ShareEvent は外に返さず、ACL の保存のみ行う。
        let _ = event;

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        Ok(GrantShareResult {
            envelope,
            recipient_key_id,
        })
    }

    /// 指定された受信者との共有関係を取り消す。
    ///
    /// - ACL のみを更新し、KeyEnvelope の失効やコンテンツ削除はここでは扱わない。
    pub fn revoke_share(
        &self,
        cmd: RevokeShareCommand,
    ) -> Result<RevokeShareResult, ShareApplicationError> {
        let mut share = self
            .share_repository
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ShareRepository)?
            .ok_or(ShareApplicationError::ContentNotFound)?;

        share
            .revoke(&cmd.recipient_key_id)
            .map_err(ShareApplicationError::Share)?;

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        Ok(RevokeShareResult {
            content_id: cmd.content_id,
            recipient_key_id: cmd.recipient_key_id,
        })
    }

    /// KeyEnvelope と受信者の秘密鍵バイト列から CEK を復号（アンラップ）する。
    ///
    /// - monas-account など別サービスが秘密鍵を管理し、このサービスにはバイト列として渡ってくる前提。
    /// - 現時点では HpkeV1 のみをサポートする。
    pub fn unwrap_cek_from_envelope(
        &self,
        envelope: &KeyEnvelope,
        recipient_private_key: &[u8],
    ) -> Result<ContentEncryptionKey, ShareApplicationError> {
        match envelope.key_wrap_algorithm() {
            KeyWrapAlgorithm::HpkeV1 => {
                let recipient = envelope.recipient();
                self.key_wrapper
                    .unwrap_cek(
                        recipient.enc(),
                        recipient.wrapped_cek(),
                        recipient_private_key,
                        envelope.content_id(),
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
    }

    impl PublicKeyDirectory for TestPublicKeyDirectory {
        fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
            let mut guard = self
                .registered
                .lock()
                .map_err(|e| PublicKeyDirectoryError::Lookup(e.to_string()))?;
            guard.push(public_key.to_vec());

            // テストでは固定の KeyId を返す。
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
    }

    #[derive(Clone, Default)]
    struct TestKeyWrapper;

    impl KeyWrapping for TestKeyWrapper {
        fn wrap_cek(
            &self,
            _cek: &ContentEncryptionKey,
            _recipient_public_key: &[u8],
            _content_id: &ContentId,
        ) -> Result<(Vec<u8>, Vec<u8>), crate::domain::share::encryption::KeyWrappingError>
        {
            Ok((vec![0xAA, 0xBB], vec![0x11, 0x22, 0x33]))
        }

        fn unwrap_cek(
            &self,
            _enc: &[u8],
            wrapped_cek: &[u8],
            _recipient_private_key: &[u8],
            _content_id: &ContentId,
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
            _content_id: &ContentId,
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
            _content_id: &ContentId,
        ) -> Result<ContentEncryptionKey, crate::domain::share::encryption::KeyWrappingError>
        {
            Err(crate::domain::share::encryption::KeyWrappingError::Other(
                "unwrap failed (test)".into(),
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
        let metadata = Metadata::new("name".into(), "/path".into(), cid.clone());
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
        );

        let recipient_private_key = vec![0x99, 0x88];

        let result = service
            .unwrap_cek_from_envelope(&envelope, &recipient_private_key)
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
        );

        let recipient_private_key = vec![0x99, 0x88];

        let err = service
            .unwrap_cek_from_envelope(&envelope, &recipient_private_key)
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
            recipient_public_key: vec![1, 2, 3],
            permission: Permission::Read,
        };

        let err = service
            .grant_share(cmd)
            .expect_err("grant_share should fail when key wrapping fails");
        assert!(matches!(err, ShareApplicationError::KeyWrapping(_)));
    }

    #[test]
    fn revoke_share_success_updates_acl() {
        let (content_repo, _content_storage) = TestContentRepository::new();
        let (key_store, _key_storage) = TestKeyStore::new();
        let (share_repo, share_storage) = TestShareRepository::new();
        let public_key_dir = TestPublicKeyDirectory::default();
        let key_wrapper = TestKeyWrapper;

        let cid = cid();
        let kid = KeyId::new(vec![1, 2, 3]);
        let mut share = Share::new(cid.clone());
        share
            .grant_read(kid.clone())
            .expect("initial grant_read should succeed");
        {
            let mut guard = share_storage.lock().unwrap();
            guard.insert(cid.as_str().to_string(), share);
        }

        let service = build_service(
            share_repo.clone(),
            content_repo,
            key_store,
            public_key_dir,
            key_wrapper,
        );

        let cmd = RevokeShareCommand {
            content_id: cid.clone(),
            recipient_key_id: kid.clone(),
        };

        let result = service
            .revoke_share(cmd)
            .expect("revoke_share should succeed");
        assert_eq!(result.content_id, cid);
        assert_eq!(result.recipient_key_id, kid);

        let guard = share_storage.lock().unwrap();
        let stored_share = guard
            .get(cid.as_str())
            .expect("share should still exist after revoke");
        assert!(stored_share.recipients().is_empty());
    }

    #[test]
    fn revoke_share_fails_when_share_not_found() {
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

        let cmd = RevokeShareCommand {
            content_id: cid(),
            recipient_key_id: KeyId::new(vec![1]),
        };

        let err = service
            .revoke_share(cmd)
            .expect_err("revoke_share should fail when share does not exist");
        assert!(matches!(err, ShareApplicationError::ContentNotFound));
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
}
