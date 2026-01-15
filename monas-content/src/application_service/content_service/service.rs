use crate::domain::{
    content::encryption::{ContentEncryption, ContentEncryptionKey, ContentEncryptionKeyGenerator},
    content::{Content, ContentError},
    content_id::{ContentId, ContentIdGenerator},
};

use super::{
    ContentCreatedOperation, ContentDeletedOperation, ContentEncryptionKeyStore,
    ContentEncryptionKeyStoreError, ContentRepository, ContentRepositoryError,
    ContentUpdatedOperation, CreateContentCommand, CreateContentResult, DeleteContentCommand,
    DeleteContentResult, FetchContentResult, ReencryptContentCommand, ReencryptContentResult,
    StateNodeClient, StateNodeClientError, UpdateContentCommand, UpdateContentResult,
};

use crate::application_service::share_service::ShareRepository;

/// コンテンツ作成ユースケースのアプリケーションサービス。
pub struct ContentService<G, R, C, K, E, S, SR> {
    pub content_id_generator: G,
    pub content_repository: R,
    pub state_node_client: C,
    pub key_generator: K,
    pub encryptor: E,
    pub cek_store: S,
    pub share_repository: SR,
}

impl<G, R, C, K, E, S, SR> ContentService<G, R, C, K, E, S, SR>
where
    G: ContentIdGenerator,
    R: ContentRepository,
    C: StateNodeClient,
    K: ContentEncryptionKeyGenerator,
    E: ContentEncryption,
    S: ContentEncryptionKeyStore,
    SR: ShareRepository,
{
    pub fn create(&self, cmd: CreateContentCommand) -> Result<CreateContentResult, CreateError> {
        // 簡易バリデーション
        Self::validate_create_command(&cmd)?;

        // CEK の生成
        let key = self.key_generator.generate();

        // ドメインの Content::create を呼び出し、ContentId生成＋暗号化＋メタデータ生成
        let (content, _event) = Content::create(
            cmd.name,
            cmd.raw_content,
            cmd.path,
            &self.content_id_generator,
            &key,
            &self.encryptor,
        )
        .map_err(CreateError::Domain)?;

        // CEK を保存
        self.cek_store
            .save(content.id(), &key)
            .map_err(CreateError::KeyStore)?;

        // コンテンツを永続化
        self.content_repository
            .save(content.id(), &content)
            .map_err(CreateError::Repository)?;

        // state-node に送る Operation を組み立て
        let metadata = content.metadata().clone();
        let content_id = content.id().clone();
        let operation = ContentCreatedOperation {
            content_id: content_id.clone(),
            hash: content_id.as_str().to_string(),
            path: metadata.path().to_string(),
            // 現時点では公開鍵を扱っていないため空文字。
            // 将来的にShare/鍵管理と連携したら埋める想定。
            public_key: String::new(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_created(&operation)
            .map_err(CreateError::StateNode)?;

        Ok(CreateContentResult {
            content_id,
            metadata,
            public_key: operation.public_key,
        })
    }

    /// CreateContentCommand の簡易バリデーション。
    fn validate_create_command(cmd: &CreateContentCommand) -> Result<(), CreateError> {
        if cmd.name.trim().is_empty() {
            return Err(CreateError::Validation("name must not be empty".into()));
        }
        if cmd.path.trim().is_empty() {
            return Err(CreateError::Validation("path must not be empty".into()));
        }
        if cmd.raw_content.is_empty() {
            return Err(CreateError::Validation(
                "raw_content must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// コンテンツ更新ユースケース。
    ///
    /// - `new_name` と `new_raw_content` はどちらか片方だけ、あるいは両方指定可能
    /// - どちらも `None` の場合は Validation エラーとする
    pub fn update(&self, cmd: UpdateContentCommand) -> Result<UpdateContentResult, UpdateError> {
        // 簡易バリデーション
        Self::validate_update_command(&cmd)?;

        // 既存コンテンツの取得
        let mut content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(UpdateError::Repository)?
            .ok_or(UpdateError::NotFound)?;

        // バイナリ更新が指定されている場合
        if let Some(raw) = cmd.new_raw_content {
            // 既存の CEK をキーストアから取得して再利用する。
            // コンテンツごとに 1 つの CEK を持ち、暗号化のたびに IV のみランダムにする前提。
            let key = self
                .cek_store
                .load(content.id())
                .map_err(UpdateError::KeyStore)?
                .ok_or_else(|| {
                    UpdateError::KeyStore(ContentEncryptionKeyStoreError::Storage(
                        "missing content encryption key for content".to_string(),
                    ))
                })?;

            let (updated, _event) = content
                .update_content(raw, &self.content_id_generator, &key, &self.encryptor)
                .map_err(UpdateError::Domain)?;

            self.cek_store
                .save(updated.id(), &key)
                .map_err(UpdateError::KeyStore)?;

            content = updated;
        }

        // 名前変更が指定されている場合
        if let Some(name) = cmd.new_name {
            let (updated, _event) = content.rename(name).map_err(UpdateError::Domain)?;
            content = updated;
        }

        // state nodeの実装によるため仮置き
        self.content_repository
            .save(content.id(), &content)
            .map_err(UpdateError::Repository)?;

        // state-node に送る更新 Operation を組み立て
        let metadata = content.metadata().clone();
        let content_id = content.id().clone();
        let operation = ContentUpdatedOperation {
            content_id: content_id.clone(),
            hash: content_id.as_str().to_string(),
            path: metadata.path().to_string(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_updated(&operation)
            .map_err(UpdateError::StateNode)?;

        Ok(UpdateContentResult {
            content_id,
            metadata,
        })
    }

    /// UpdateContentCommand の簡易バリデーション。
    ///
    /// - `new_name` / `new_raw_content` のいずれか一方以上が指定されていること。
    /// - 指定されている場合、それぞれの値が妥当であること。
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

    /// コンテンツ本体を復号して取得するユースケース（fetch）。
    ///
    /// - `content_id` に対応するコンテンツを取得し、CEK を用いて復号したバイト列を返す。
    /// - 削除済みコンテンツや CEK が存在しない場合はエラーとなる。
    pub fn fetch(&self, content_id: ContentId) -> Result<FetchContentResult, FetchError> {
        let content = self
            .content_repository
            .find_by_id(&content_id)
            .map_err(FetchError::Repository)?
            .ok_or(FetchError::NotFound)?;

        if content.is_deleted() {
            return Err(FetchError::Deleted);
        }

        // CEK をキーストアから取得
        let key = self
            .cek_store
            .load(content.id())
            .map_err(FetchError::KeyStore)?
            .ok_or(FetchError::MissingKey)?;

        // ドメインの decrypt を用いて復号
        let raw_content = content
            .decrypt(&key, &self.encryptor)
            .map_err(FetchError::Domain)?;

        Ok(FetchContentResult {
            content_id: content.id().clone(),
            series_id: content.series_id().clone(),
            metadata: content.metadata().clone(),
            raw_content,
        })
    }

    /// 外部でアンラップされた CEK と暗号化済みコンテンツを用いて復号するユースケース。
    ///
    /// - 共有フロー（Share）で KeyEnvelope から CEK を取り出した後の復号処理を想定。
    /// - 復号結果のバイト列から ContentId を再計算し、引数の `content_id` と一致することを検証する。
    ///   （コンテンツアドレス化に基づく整合性チェック）
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

        // 復号したプレーンテキストから ContentId を再生成し、期待される ID と一致するか確認する。
        let actual_id = self.content_id_generator.generate(&plaintext);
        if actual_id != expected_content_id {
            return Err(DecryptWithCekError::ContentIdMismatch {
                expected: expected_content_id.as_str().to_string(),
                actual: actual_id.as_str().to_string(),
            });
        }

        Ok(plaintext)
    }

    /// コンテンツ削除ユースケース。
    ///
    /// - 物理削除ではなく、ドメインオブジェクト上で `is_deleted` フラグとバッファをクリアして保存する「論理削除」
    pub fn delete(&self, cmd: DeleteContentCommand) -> Result<DeleteContentResult, DeleteError> {
        // 既存コンテンツの取得
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(DeleteError::Repository)?
            .ok_or(DeleteError::NotFound)?;

        // ドメインの削除処理（状態遷移とバリデーション）
        let (deleted_content, _event) = content.delete().map_err(DeleteError::Domain)?;

        // CEK を削除
        self.cek_store
            .delete(deleted_content.id())
            .map_err(DeleteError::KeyStore)?;

        // 論理削除済みの状態を保存
        self.content_repository
            .save(deleted_content.id(), &deleted_content)
            .map_err(DeleteError::Repository)?;

        // state-node に送る削除 Operation を組み立て
        let metadata = deleted_content.metadata().clone();
        let content_id = deleted_content.id().clone();
        let operation = ContentDeletedOperation {
            content_id: content_id.clone(),
            path: metadata.path().to_string(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_deleted(&operation)
            .map_err(DeleteError::StateNode)?;

        Ok(DeleteContentResult { content_id })
    }

    /// コンテンツ再暗号化ユースケース。
    ///
    /// Owner権限を持つユーザが、特定のReadまたはWrite権限ユーザのアクセスを拒否するために、
    /// コンテンツを再暗号化する機能。
    pub fn reencrypt(
        &self,
        cmd: ReencryptContentCommand,
    ) -> Result<ReencryptContentResult, ReencryptError> {
        // Step 1: コンテンツの取得と検証
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(ReencryptError::ContentRepository)?
            .ok_or(ReencryptError::ContentNotFound)?;

        if content.is_deleted() {
            return Err(ReencryptError::ContentDeleted);
        }

        // Step 2: Shareの取得とOwner権限確認
        let share = self
            .share_repository
            .load(&cmd.content_id)
            .map_err(|_| ReencryptError::ShareNotFound)?
            .ok_or(ReencryptError::ShareNotFound)?;

        if share.owner_key_id() != Some(&cmd.requester_key_id) {
            return Err(ReencryptError::OwnerPermissionDenied(
                cmd.requester_key_id.clone(),
                cmd.content_id.as_str().to_string(),
            ));
        }

        // Step 3: 更新確認（暫定的な実装方針に従う、現時点では詳細未定）
        // 注意: Owner権限があれば、存在するユーザを削除するために再暗号化を実行できる
        // revoked_key_idがShareに存在するかどうかはチェックしない
        let _metadata = content.metadata();
        let _updated_at = content.metadata().updated_at();

        // Step 4: 既存のCEKで復号
        let old_content_id = content.id().clone();
        let old_cek = self
            .cek_store
            .load(&old_content_id)
            .map_err(ReencryptError::KeyStore)?
            .ok_or(ReencryptError::MissingContentEncryptionKey)?;

        let plaintext = content
            .decrypt(&old_cek, &self.encryptor)
            .map_err(ReencryptError::Domain)?;

        // Step 5: 新しいCEKを生成
        let new_cek = self.key_generator.generate();

        // Step 6: 再暗号化されたContentを作成
        let (reencrypted_content, _event) = content
            .update_content(
                plaintext,
                &self.content_id_generator,
                &new_cek,
                &self.encryptor,
            )
            .map_err(ReencryptError::Domain)?;

        let new_content_id = reencrypted_content.id().clone();

        // Step 7: 新しいContentIdでCEKを保存
        self.cek_store
            .save(&new_content_id, &new_cek)
            .map_err(ReencryptError::KeyStore)?;

        // Step 8: 新しいContentIdでContentを保存
        if let Err(e) = self
            .content_repository
            .save(&new_content_id, &reencrypted_content)
        {
            // ロールバック: 新しいContentIdのCEKを削除（失敗しても問題なし）
            let _ = self.cek_store.delete(&new_content_id);
            return Err(ReencryptError::ContentRepository(e));
        }

        // 注意: 現状、古いContentIdのContentとCEKの削除処理は不要
        // 理由: 再暗号化では常に再暗号化前と同じcontent idであるので、上書き保存により古いデータは自動的に新しいデータに置き換えられる:
        // - Contentの場合: ContentRepository::save()はHashMap::insert()を使用（monas-content/src/infrastructure/repository.rs:25）
        // - CEKの場合: ContentEncryptionKeyStore::save()はHashMap::insert()を使用（monas-content/src/infrastructure/key_store.rs:30）
        // したがって、Step 7とStep 8の上書き保存により、古いContentとCEKは自動的に新しいものに置き換えられる

        // 将来の実装: 暗号文からContentIdを生成する場合の削除処理
        // 将来的には暗号文からContentIdを生成するため、再暗号化時にContentIdが変わるので、
        // 以下の削除処理が必要になる:
        // Step 9: 古いContentIdのContentを削除（ContentIdが変わった場合のみ）
        // if old_content_id != new_content_id {
        //     let _ = self.content_repository.delete(&old_content_id);
        // }
        //
        // Step 10: 古いContentIdのCEKを削除（ContentIdが変わった場合のみ）
        // if old_content_id != new_content_id {
        //     let _ = self.cek_store.delete(&old_content_id);
        // }

        // Step 9: 結果を返す
        let encrypted_content = reencrypted_content
            .encrypted_content()
            .ok_or(ReencryptError::MissingEncryptedContent)?
            .clone();

        Ok(ReencryptContentResult {
            content_id: new_content_id,
            series_id: reencrypted_content.series_id().clone(),
            metadata: reencrypted_content.metadata().clone(),
            encrypted_content,
        })
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
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
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
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
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
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
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

#[derive(Debug, thiserror::Error)]
pub enum ReencryptError {
    #[error("content not found")]
    ContentNotFound,
    #[error("content is deleted")]
    ContentDeleted,
    #[error("share not found")]
    ShareNotFound,
    #[error("owner permission denied: requester_key_id={0:?}, content_id={1}")]
    OwnerPermissionDenied(crate::domain::KeyId, String),
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
    use crate::domain::{
        content::encryption::{ContentEncryptionKey, ContentEncryptionKeyGenerator},
        content::ContentStatus,
        content_id::{ContentId, ContentIdGenerator},
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// テスト用のシンプルな ContentIdGenerator。
    #[derive(Clone)]
    struct TestIdGenerator;

    impl ContentIdGenerator for TestIdGenerator {
        fn generate(&self, raw_content: &[u8]) -> ContentId {
            ContentId::new(format!("test-id-{}", raw_content.len()))
        }
    }

    /// テスト用の固定キー生成器。
    #[derive(Clone)]
    struct TestKeyGenerator;

    impl ContentEncryptionKeyGenerator for TestKeyGenerator {
        fn generate(&self) -> ContentEncryptionKey {
            ContentEncryptionKey(vec![1, 2, 3])
        }
    }

    /// 常に成功するテスト用暗号化実装（ダミー）。
    #[derive(Clone)]
    struct TestEncryptor;

    impl ContentEncryption for TestEncryptor {
        fn encrypt(
            &self,
            _key: &ContentEncryptionKey,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ContentError> {
            // ここでは実際の暗号化は行わず、そのままコピーを返す。
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

    /// 暗号化時に必ずエラーを返すテスト用実装（ドメインエラー発生用）。
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

    /// Arc<Mutex<HashMap<...>>> を内部に持つテスト用リポジトリ。
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

        // 将来の実装: 暗号文からContentIdを生成する場合の削除処理
        // 将来的には暗号文からContentIdを生成するため、再暗号化時にContentIdが変わる可能性がある
        // その場合は、古いContentIdのContentを削除する処理が必要になる
        // 現状は使用していない（再暗号化では上書き保存により古いデータが自動的に新しいデータに置き換えられる）
        // fn delete(&self, content_id: &ContentId) -> Result<(), ContentRepositoryError> {
        //     let mut guard = self
        //         .inner
        //         .lock()
        //         .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;
        //
        //     guard.remove(content_id.as_str());
        //     Ok(())
        // }
    }

    #[derive(Clone, Default)]
    struct TestStateNodeClient {
        fail_on_created: bool,
        fail_on_updated: bool,
        fail_on_deleted: bool,
    }

    impl StateNodeClient for TestStateNodeClient {
        fn send_content_created(
            &self,
            _operation: &ContentCreatedOperation,
        ) -> Result<(), StateNodeClientError> {
            if self.fail_on_created {
                Err(StateNodeClientError::Network(
                    "created operation failed (test)".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn send_content_updated(
            &self,
            _operation: &ContentUpdatedOperation,
        ) -> Result<(), StateNodeClientError> {
            if self.fail_on_updated {
                Err(StateNodeClientError::Network(
                    "updated operation failed (test)".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn send_content_deleted(
            &self,
            _operation: &ContentDeletedOperation,
        ) -> Result<(), StateNodeClientError> {
            if self.fail_on_deleted {
                Err(StateNodeClientError::Network(
                    "deleted operation failed (test)".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    /// テスト用のインメモリ CEK ストア。
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

    /// テスト用のインメモリ ShareRepository。
    #[derive(Clone, Default)]
    struct TestShareRepository {
        inner: Arc<Mutex<HashMap<String, crate::domain::share::Share>>>,
    }

    impl TestShareRepository {
        fn new() -> (
            Self,
            Arc<Mutex<HashMap<String, crate::domain::share::Share>>>,
        ) {
            let inner = Arc::new(Mutex::new(HashMap::new()));
            (
                Self {
                    inner: inner.clone(),
                },
                inner,
            )
        }
    }

    impl crate::application_service::share_service::ShareRepository for TestShareRepository {
        fn load(
            &self,
            content_id: &ContentId,
        ) -> Result<
            Option<crate::domain::share::Share>,
            crate::application_service::share_service::ShareRepositoryError,
        > {
            let guard = self.inner.lock().map_err(|e| {
                crate::application_service::share_service::ShareRepositoryError::Storage(
                    e.to_string(),
                )
            })?;
            Ok(guard.get(content_id.as_str()).cloned())
        }

        fn save(
            &self,
            share: &crate::domain::share::Share,
        ) -> Result<(), crate::application_service::share_service::ShareRepositoryError> {
            let mut guard = self.inner.lock().map_err(|e| {
                crate::application_service::share_service::ShareRepositoryError::Storage(
                    e.to_string(),
                )
            })?;
            guard.insert(share.content_id().as_str().to_string(), share.clone());
            Ok(())
        }
    }

    fn build_service<R, C, K, E, S, SR>(
        repo: R,
        client: C,
        key_gen: K,
        encryptor: E,
        key_store: S,
        share_repo: SR,
    ) -> ContentService<TestIdGenerator, R, C, K, E, S, SR>
    where
        R: ContentRepository,
        C: StateNodeClient,
        K: ContentEncryptionKeyGenerator,
        E: ContentEncryption,
        S: ContentEncryptionKeyStore,
        SR: crate::application_service::share_service::ShareRepository,
    {
        ContentService {
            content_id_generator: TestIdGenerator,
            content_repository: repo,
            state_node_client: client,
            key_generator: key_gen,
            encryptor,
            cek_store: key_store,
            share_repository: share_repo,
        }
    }

    #[test]
    fn create_success_persists_and_notifies_state_node() {
        let (repo, storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let cmd = CreateContentCommand {
            name: "test".into(),
            path: "path.txt".into(),
            raw_content: b"hello".to_vec(),
        };

        let result = service.create(cmd).expect("create should succeed");

        assert_eq!(result.metadata.name(), "test");
        assert_eq!(result.metadata.path(), "path.txt");

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(result.content_id.as_str())
            .expect("content should be stored");
        assert!(!stored.is_deleted());
        assert_eq!(stored.content_status(), &ContentStatus::Active);
    }

    #[test]
    fn create_validation_error_when_name_is_empty() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let cmd = CreateContentCommand {
            name: "   ".into(),
            path: "path.txt".into(),
            raw_content: b"hello".to_vec(),
        };

        let err = match service.create(cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected validation error but got Ok"),
        };
        assert!(matches!(err, CreateError::Validation(_)));
    }

    #[test]
    fn create_state_node_error_is_propagated() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient {
            fail_on_created: true,
            ..Default::default()
        };
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let cmd = CreateContentCommand {
            name: "test".into(),
            path: "path.txt".into(),
            raw_content: b"hello".to_vec(),
        };

        let err = match service.create(cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected state-node error but got Ok"),
        };
        assert!(matches!(err, CreateError::StateNode(_)));
    }

    #[test]
    fn update_success_changes_content_and_name() {
        let (repo, storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo.clone(),
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let base_cmd = CreateContentCommand {
            name: "old".into(),
            path: "path.txt".into(),
            raw_content: b"old-data".to_vec(),
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let update_cmd = UpdateContentCommand {
            content_id: base_result.content_id.clone(),
            new_name: Some("new-name".into()),
            new_raw_content: Some(b"new-data".to_vec()),
        };

        let updated = service.update(update_cmd).expect("update should succeed");
        assert_eq!(updated.metadata.name(), "new-name");

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(updated.content_id.as_str())
            .expect("updated content should be stored");
        assert_eq!(stored.metadata().name(), "new-name");

        let key_guard = key_storage.lock().unwrap();
        assert!(
            key_guard.get(updated.content_id.as_str()).is_some(),
            "CEK should be stored under the updated content_id"
        );
    }

    #[test]
    fn update_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let update_cmd = UpdateContentCommand {
            content_id: ContentId::new("unknown-id".into()),
            new_name: Some("name".into()),
            new_raw_content: None,
        };

        let err = match service.update(update_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, UpdateError::NotFound));
    }

    #[test]
    fn update_state_node_error_is_propagated() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient {
            fail_on_updated: true,
            ..Default::default()
        };
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo.clone(),
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let base_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let update_cmd = UpdateContentCommand {
            content_id: base_result.content_id,
            new_name: Some("new".into()),
            new_raw_content: None,
        };

        let err = match service.update(update_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected state-node error but got Ok"),
        };
        assert!(matches!(err, UpdateError::StateNode(_)));
    }

    #[test]
    fn delete_success_marks_content_deleted_and_notifies_state_node() {
        let (repo, storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo.clone(),
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let base_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let delete_cmd = DeleteContentCommand {
            content_id: base_result.content_id.clone(),
        };

        let result = service.delete(delete_cmd).expect("delete should succeed");
        assert_eq!(result.content_id, base_result.content_id);

        let guard = storage.lock().unwrap();
        let stored = guard
            .get(base_result.content_id.as_str())
            .expect("deleted content should be stored");
        assert!(stored.is_deleted());
        assert_eq!(stored.content_status(), &ContentStatus::Deleted);
        assert!(stored.raw_content().is_none());
        assert!(stored.encrypted_content().is_none());
    }

    #[test]
    fn delete_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let delete_cmd = DeleteContentCommand {
            content_id: ContentId::new("unknown-id".into()),
        };

        let err = match service.delete(delete_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, DeleteError::NotFound));
    }

    #[test]
    fn delete_state_node_error_is_propagated() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient {
            fail_on_deleted: true,
            ..Default::default()
        };
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo.clone(),
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let base_cmd = CreateContentCommand {
            name: "name".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
        };
        let base_result = service
            .create(base_cmd)
            .expect("initial create should succeed");

        let delete_cmd = DeleteContentCommand {
            content_id: base_result.content_id,
        };

        let err = match service.delete(delete_cmd) {
            Err(e) => e,
            Ok(_) => panic!("expected state-node error but got Ok"),
        };
        assert!(matches!(err, DeleteError::StateNode(_)));
    }

    #[test]
    fn fetch_success_returns_decrypted_content() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let raw = b"hello-fetch".to_vec();

        let cmd = CreateContentCommand {
            name: "fetch-test".into(),
            path: "path.txt".into(),
            raw_content: raw.clone(),
        };

        let created = service.create(cmd).expect("create should succeed");

        let fetched = service
            .fetch(created.content_id.clone())
            .expect("fetch should succeed");

        assert_eq!(fetched.content_id, created.content_id);
        assert_eq!(fetched.metadata.path(), created.metadata.path());
        assert_eq!(fetched.raw_content, raw);
    }

    #[test]
    fn fetch_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let unknown_id = ContentId::new("unknown-id".into());

        let err = match service.fetch(unknown_id) {
            Err(e) => e,
            Ok(_) => panic!("expected not-found error but got Ok"),
        };
        assert!(matches!(err, FetchError::NotFound));
    }

    #[test]
    fn fetch_deleted_returns_deleted_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo.clone(),
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let cmd = CreateContentCommand {
            name: "to-delete".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
        };
        let created = service.create(cmd).expect("create should succeed");

        let delete_cmd = DeleteContentCommand {
            content_id: created.content_id.clone(),
        };
        service.delete(delete_cmd).expect("delete should succeed");

        let err = match service.fetch(created.content_id) {
            Err(e) => e,
            Ok(_) => panic!("expected deleted error but got Ok"),
        };
        assert!(matches!(err, FetchError::Deleted));
    }

    #[test]
    fn fetch_missing_key_returns_missing_key_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, key_storage) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let cmd = CreateContentCommand {
            name: "no-key".into(),
            path: "path.txt".into(),
            raw_content: b"data".to_vec(),
        };
        let created = service.create(cmd).expect("create should succeed");

        // CEK ストアから該当コンテンツのエントリを削除して「鍵がない」状態を再現。
        {
            let mut guard = key_storage.lock().unwrap();
            guard.remove(created.content_id.as_str());
        }

        let err = match service.fetch(created.content_id) {
            Err(e) => e,
            Ok(_) => panic!("expected missing-key error but got Ok"),
        };
        assert!(matches!(err, FetchError::MissingKey));
    }

    #[test]
    fn decrypt_with_cek_success_when_content_id_matches() {
        let (repo, _storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

        let plaintext = b"decrypt-cek-success".to_vec();
        let expected_cid = service.content_id_generator.generate(&plaintext);

        let key = ContentEncryptionKey(vec![1, 2, 3]);
        let ciphertext = plaintext.clone();

        let result = service
            .decrypt_with_cek(expected_cid.clone(), key, ciphertext)
            .expect("decrypt_with_cek should succeed when content_id matches");

        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_with_cek_returns_mismatch_error_when_content_id_differs() {
        let (repo, _storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let (key_store, _key_storage) = TestKeyStore::new(false, false);
        let (share_repo, _) = TestShareRepository::new();
        let service = build_service(
            repo,
            client,
            TestKeyGenerator,
            TestEncryptor,
            key_store,
            share_repo,
        );

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
}
