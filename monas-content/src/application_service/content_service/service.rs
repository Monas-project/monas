use crate::domain::{
    content::{Content, ContentError},
    content_id::ContentIdGenerator,
    encryption::{ContentEncryption, ContentEncryptionKeyGenerator},
};

use super::{
    ContentCreatedOperation, ContentDeletedOperation, ContentRepository, ContentRepositoryError,
    ContentUpdatedOperation, CreateContentCommand, CreateContentResult, DeleteContentCommand,
    DeleteContentResult, StateNodeClient, StateNodeClientError, UpdateContentCommand,
    UpdateContentResult,
};

/// コンテンツ作成ユースケースのアプリケーションサービス。
pub struct ContentService<G, R, C, K, E> {
    pub content_id_generator: G,
    pub content_repository: R,
    pub state_node_client: C,
    pub key_generator: K,
    pub encryptor: E,
}

impl<G, R, C, K, E> ContentService<G, R, C, K, E>
where
    G: ContentIdGenerator,
    R: ContentRepository,
    C: StateNodeClient,
    K: ContentEncryptionKeyGenerator,
    E: ContentEncryption,
{
    pub fn create(&self, cmd: CreateContentCommand) -> Result<CreateContentResult, CreateError> {
        // 簡易バリデーション
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

    /// コンテンツ更新ユースケース。
    ///
    /// - `new_name` と `new_raw_content` はどちらか片方だけ、あるいは両方指定可能
    /// - どちらも `None` の場合は Validation エラーとする
    pub fn update(&self, cmd: UpdateContentCommand) -> Result<UpdateContentResult, UpdateError> {
        // 簡易バリデーション
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

        // 既存コンテンツの取得
        let mut content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(UpdateError::Repository)?
            .ok_or(UpdateError::NotFound)?;

        // バイナリ更新が指定されている場合
        if let Some(raw) = cmd.new_raw_content {
            let key = self.key_generator.generate();
            let (updated, _event) = content
                .update_content(raw, &key, &self.encryptor)
                .map_err(UpdateError::Domain)?;
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
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteError {
    #[error("content not found")]
    NotFound,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
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
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        content::ContentStatus,
        content_id::{ContentId, ContentIdGenerator},
        encryption::{ContentEncryptionKey, ContentEncryptionKeyGenerator},
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
    }

    /// テスト用の StateNodeClient 実装。
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

    fn build_service<R, C, K, E>(
        repo: R,
        client: C,
        key_gen: K,
        encryptor: E,
    ) -> ContentService<TestIdGenerator, R, C, K, E>
    where
        R: ContentRepository,
        C: StateNodeClient,
        K: ContentEncryptionKeyGenerator,
        E: ContentEncryption,
    {
        ContentService {
            content_id_generator: TestIdGenerator,
            content_repository: repo,
            state_node_client: client,
            key_generator: key_gen,
            encryptor,
        }
    }

    #[test]
    fn create_success_persists_and_notifies_state_node() {
        let (repo, storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let service = build_service(repo, client, TestKeyGenerator, TestEncryptor);

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
        let service = build_service(repo, client, TestKeyGenerator, TestEncryptor);

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
        let service = build_service(repo, client, TestKeyGenerator, TestEncryptor);

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
        let service = build_service(repo.clone(), client, TestKeyGenerator, TestEncryptor);

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
    }

    #[test]
    fn update_not_found_returns_error() {
        let (repo, _) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let service = build_service(repo, client, TestKeyGenerator, TestEncryptor);

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
        let service = build_service(repo.clone(), client, TestKeyGenerator, TestEncryptor);

        // 既存コンテンツを用意
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

    // --- delete のテスト ---

    #[test]
    fn delete_success_marks_content_deleted_and_notifies_state_node() {
        let (repo, storage) = TestContentRepository::new(false);
        let client = TestStateNodeClient::default();
        let service = build_service(repo.clone(), client, TestKeyGenerator, TestEncryptor);

        // 既存コンテンツを用意
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
        let service = build_service(repo, client, TestKeyGenerator, TestEncryptor);

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
        let service = build_service(repo.clone(), client, TestKeyGenerator, TestEncryptor);

        // 既存コンテンツを用意
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
}
