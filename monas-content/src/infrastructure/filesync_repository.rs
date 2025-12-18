//! monas-filesync を使った ContentRepository 実装。
//!
//! `filesync` feature が有効な場合のみコンパイルされる。
//!
//! ## 提供するリポジトリ
//!
//! - [`MultiStorageRepository`] - 複数のストレージプロバイダーを使い分け

use crate::application_service::content_service::{
    ContentRepository, ContentRepositoryError, MultiStorageContentRepository,
};
use crate::domain::content::Content;
use crate::domain::content_id::ContentId;
use monas_filesync::{AuthSession, FetcherRegistry, StorageProvider};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::runtime::Handle;

/// 複数のストレージプロバイダーを使い分けられる ContentRepository 実装。
///
/// 内部で `Arc` を使用しているため、`Clone` で安価に共有可能。
/// 複数のサービスで同じリポジトリを共有する場合に便利。
///
/// # 使用例
///
/// ```ignore
/// use monas_filesync::{FilesyncConfig, FetcherRegistry, AuthSession};
/// use monas_content::infrastructure::MultiStorageRepository;
///
/// let config = FilesyncConfig::from_env();
/// let registry = Arc::new(FetcherRegistry::from_config(&config));
///
/// // リポジトリを作成（永続化あり）
/// let repo = MultiStorageRepository::new(
///     registry,
///     "local",
///     "~/.monas/credentials.json",
/// )?;
///
/// // Clone で共有可能
/// let repo_clone = repo.clone();
///
/// // ユーザーが Google Drive を接続したとき（自動的にファイルに保存される）
/// repo.connect("google-drive", AuthSession { access_token: "...".into() })?;
///
/// // 特定のストレージに保存
/// repo.save_to("google-drive", &content_id, &content)?;
///
/// // デフォルトストレージに保存（ContentRepository トレイト経由）
/// repo.save(&content_id, &content)?;
/// ```
#[derive(Clone)]
pub struct MultiStorageRepository {
    inner: Arc<MultiStorageRepositoryInner>,
}

/// MultiStorageRepository の内部状態
struct MultiStorageRepositoryInner {
    registry: Arc<FetcherRegistry>,
    /// プロバイダーごとの認証セッション
    auth_sessions: RwLock<HashMap<String, AuthSession>>,
    /// デフォルトで使用するプロバイダー
    default_provider: RwLock<String>,
    /// 認証情報の保存先パス（None の場合は永続化しない）
    credentials_path: Option<PathBuf>,
}

/// ファイルに保存する認証情報の形式
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCredentials {
    /// プロバイダー名 → アクセストークン
    sessions: HashMap<String, String>,
}

impl MultiStorageRepository {
    /// 新しい MultiStorageRepository を作成する（永続化あり）。
    ///
    /// 認証情報は指定されたパスに JSON 形式で保存される。
    /// 既存のファイルがあれば読み込んで復元する。
    ///
    /// # Arguments
    ///
    /// * `registry` - 登録済みのプロバイダーを持つ FetcherRegistry
    /// * `default_provider` - デフォルトで使用するストレージプロバイダー
    /// * `credentials_path` - 認証情報の保存先パス
    ///
    /// # Example
    ///
    /// ```ignore
    /// let repo = MultiStorageRepository::new(
    ///     registry,
    ///     "local",
    ///     "~/.monas/credentials.json",
    /// )?;
    /// ```
    pub fn new(
        registry: Arc<FetcherRegistry>,
        default_provider: impl Into<String>,
        credentials_path: impl Into<PathBuf>,
    ) -> Result<Self, ContentRepositoryError> {
        let path = credentials_path.into();
        let repo = Self::create(registry, default_provider.into(), Some(path));

        // 既存のファイルがあれば読み込む
        repo.load_credentials()?;

        Ok(repo)
    }

    /// テスト用の MultiStorageRepository を作成する（永続化なし）。
    ///
    /// 認証情報はメモリ内にのみ保持され、アプリ終了時に失われる。
    ///
    /// # Arguments
    ///
    /// * `registry` - 登録済みのプロバイダーを持つ FetcherRegistry
    /// * `default_provider` - デフォルトで使用するストレージプロバイダー
    pub fn in_memory(registry: Arc<FetcherRegistry>, default_provider: impl Into<String>) -> Self {
        Self::create(registry, default_provider.into(), None)
    }

    /// 内部用のコンストラクタ
    fn create(
        registry: Arc<FetcherRegistry>,
        default_provider: String,
        credentials_path: Option<PathBuf>,
    ) -> Self {
        let mut auth_sessions = HashMap::new();

        // ローカルストレージはデフォルトで接続済み（認証不要）
        auth_sessions.insert(
            "local".to_string(),
            AuthSession {
                access_token: String::new(),
            },
        );
        auth_sessions.insert(
            "local-mobile".to_string(),
            AuthSession {
                access_token: String::new(),
            },
        );

        Self {
            inner: Arc::new(MultiStorageRepositoryInner {
                registry,
                auth_sessions: RwLock::new(auth_sessions),
                default_provider: RwLock::new(default_provider),
                credentials_path,
            }),
        }
    }

    /// ストレージプロバイダーを接続する（認証セッションを登録）。
    ///
    /// ユーザーがUIで「Google Drive を接続」などを選択したときに呼び出す。
    /// 永続化が有効な場合、自動的にファイルに保存される。
    pub fn connect(
        &self,
        provider: impl Into<String>,
        auth: AuthSession,
    ) -> Result<(), ContentRepositoryError> {
        let provider = provider.into();

        if self.inner.registry.resolve(&provider).is_none() {
            return Err(ContentRepositoryError::Storage(format!(
                "unknown storage provider: {}",
                provider
            )));
        }

        {
            let mut sessions = self.inner.auth_sessions.write().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;
            sessions.insert(provider, auth);
        }

        // 永続化が有効なら保存
        self.save_credentials()?;

        Ok(())
    }

    /// ストレージプロバイダーを切断する（認証セッションを削除）。
    ///
    /// 永続化が有効な場合、自動的にファイルから削除される。
    pub fn disconnect(&self, provider: &str) -> Result<(), ContentRepositoryError> {
        {
            let mut sessions = self.inner.auth_sessions.write().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;
            sessions.remove(provider);
        }

        // 永続化が有効なら保存
        self.save_credentials()?;

        Ok(())
    }

    /// 認証情報をファイルに保存する。
    ///
    /// `credentials_path` が設定されている場合のみ保存される。
    pub fn save_credentials(&self) -> Result<(), ContentRepositoryError> {
        let path = match &self.inner.credentials_path {
            Some(p) => p,
            None => return Ok(()), // 永続化が無効なら何もしない
        };

        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        // ローカルストレージ以外のセッションのみ保存（ローカルは認証不要なので）
        let persisted = PersistedCredentials {
            sessions: sessions
                .iter()
                .filter(|(k, _)| *k != "local" && *k != "local-mobile")
                .map(|(k, v)| (k.clone(), v.access_token.clone()))
                .collect(),
        };

        // 親ディレクトリを作成
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ContentRepositoryError::Storage(format!(
                    "failed to create credentials directory: {e}"
                ))
            })?;
        }

        // JSON として保存
        let json = serde_json::to_string_pretty(&persisted).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to serialize credentials: {e}"))
        })?;

        std::fs::write(path, json).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to write credentials file: {e}"))
        })?;

        Ok(())
    }

    /// 認証情報をファイルから読み込む。
    ///
    /// `credentials_path` が設定されており、ファイルが存在する場合のみ読み込まれる。
    fn load_credentials(&self) -> Result<(), ContentRepositoryError> {
        let path = match &self.inner.credentials_path {
            Some(p) => p,
            None => return Ok(()), // 永続化が無効なら何もしない
        };

        // ファイルが存在しなければスキップ
        if !path.exists() {
            return Ok(());
        }

        let json = std::fs::read_to_string(path).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to read credentials file: {e}"))
        })?;

        let persisted: PersistedCredentials = serde_json::from_str(&json).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to parse credentials file: {e}"))
        })?;

        let mut sessions =
            self.inner.auth_sessions.write().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        // 読み込んだセッションを追加（registry に存在するもののみ）
        for (provider, token) in persisted.sessions {
            if self.inner.registry.resolve(&provider).is_some() {
                sessions.insert(
                    provider,
                    AuthSession {
                        access_token: token,
                    },
                );
            }
        }

        Ok(())
    }

    /// 接続済みのプロバイダー一覧を取得する。
    pub fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        Ok(sessions.keys().cloned().collect())
    }

    /// 現在のデフォルトプロバイダーを取得する。
    pub fn default_provider(&self) -> Result<String, ContentRepositoryError> {
        let default =
            self.inner.default_provider.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        Ok(default.clone())
    }

    /// 指定したストレージプロバイダーにコンテンツを保存する。
    pub fn save_to(
        &self,
        provider: &str,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        let (storage_provider, auth) = self.get_provider_and_auth(provider)?;
        let path = Self::content_path(provider, content_id);

        let data = serde_json::to_vec(content)
            .map_err(|e| ContentRepositoryError::Storage(format!("serialization error: {e}")))?;

        tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(async { storage_provider.save(&auth, &path, &data).await })
                .map_err(|e| ContentRepositoryError::Storage(e.message))
        })
    }

    /// 指定したストレージプロバイダーからコンテンツを取得する。
    pub fn find_from(
        &self,
        provider: &str,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        let (storage_provider, auth) = self.get_provider_and_auth(provider)?;
        let path = Self::content_path(provider, content_id);

        let result = tokio::task::block_in_place(|| {
            Handle::current().block_on(async { storage_provider.fetch(&auth, &path).await })
        });

        match result {
            Ok(bytes) => {
                let content: Content = serde_json::from_slice(&bytes).map_err(|e| {
                    ContentRepositoryError::Storage(format!("deserialization error: {e}"))
                })?;
                Ok(Some(content))
            }
            Err(e) => {
                if e.message.contains("failed to read") || e.message.contains("not found") {
                    Ok(None)
                } else {
                    Err(ContentRepositoryError::Storage(e.message))
                }
            }
        }
    }

    /// プロバイダーと認証セッションを取得する。
    fn get_provider_and_auth(
        &self,
        provider: &str,
    ) -> Result<(Arc<dyn StorageProvider>, AuthSession), ContentRepositoryError> {
        let storage_provider = self.inner.registry.resolve(provider).ok_or_else(|| {
            ContentRepositoryError::Storage(format!(
                "storage provider '{}' not found in registry",
                provider
            ))
        })?;

        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        let auth = sessions.get(provider).ok_or_else(|| {
            ContentRepositoryError::Storage(format!(
                "storage provider '{}' is not connected. Call connect() first.",
                provider
            ))
        })?;

        Ok((storage_provider, auth.clone()))
    }

    /// コンテンツIDからストレージパスを生成する。
    fn content_path(provider: &str, content_id: &ContentId) -> String {
        format!("{}://content/{}.json", provider, content_id.as_str())
    }
}

/// ContentRepository トレイトの実装（デフォルトプロバイダーを使用）
impl ContentRepository for MultiStorageRepository {
    fn save(
        &self,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        let default = MultiStorageContentRepository::default_provider(self)?;
        self.save_to(&default, content_id, content)
    }

    fn find_by_id(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        let default = MultiStorageContentRepository::default_provider(self)?;
        self.find_from(&default, content_id)
    }
}

/// MultiStorageContentRepository トレイトの実装
impl MultiStorageContentRepository for MultiStorageRepository {
    fn save_to(
        &self,
        provider: &str,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        MultiStorageRepository::save_to(self, provider, content_id, content)
    }

    fn find_from(
        &self,
        provider: &str,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        MultiStorageRepository::find_from(self, provider, content_id)
    }

    fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
        MultiStorageRepository::connected_providers(self)
    }

    fn default_provider(&self) -> Result<String, ContentRepositoryError> {
        MultiStorageRepository::default_provider(self)
    }

    fn connect_provider(
        &self,
        provider: &str,
        access_token: String,
    ) -> Result<(), ContentRepositoryError> {
        let auth = AuthSession { access_token };
        MultiStorageRepository::connect(self, provider, auth)
    }

    fn disconnect_provider(&self, provider: &str) -> Result<(), ContentRepositoryError> {
        MultiStorageRepository::disconnect(self, provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monas_filesync::init_registry_default;
    use std::sync::Arc;
    use tempfile::TempDir;

    // ========================================================================
    // テストヘルパー関数
    // ========================================================================

    /// テスト用の FetcherRegistry を作成する。
    ///
    /// 指定された一時ディレクトリを base_path としたローカルプロバイダーを含む。
    fn create_test_registry(temp_dir: &TempDir) -> Arc<monas_filesync::FetcherRegistry> {
        let config_str = format!(
            r#"[local]
base_path = "{}""#,
            temp_dir.path().display()
        );
        let config = monas_filesync::FilesyncConfig::from_toml_str(&config_str)
            .expect("failed to parse config");
        Arc::new(monas_filesync::FetcherRegistry::from_config(&config))
    }

    /// テスト用の Content を作成する。
    fn create_test_content(id: &str) -> Content {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "series_id": id,
            "metadata": {
                "name": "test",
                "path": "/test/path",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "id": id,
                "provider": null
            },
            "encrypted_content": [1, 2, 3, 4],
            "is_deleted": false,
            "content_status": "Active"
        }))
        .expect("failed to create test content")
    }

    // ========================================================================
    // MultiStorageRepository のテスト
    // ========================================================================

    #[test]
    fn test_multi_storage_repository_default_provider() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let registry = create_test_registry(&temp_dir);

        let repo = MultiStorageRepository::in_memory(registry, "local");

        // デフォルトプロバイダーを確認
        assert_eq!(repo.default_provider().unwrap(), "local");

        // ローカルは自動接続されている
        let connected = repo.connected_providers().unwrap();
        assert!(connected.contains(&"local".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi_storage_repository_save_and_find_with_default() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let registry = create_test_registry(&temp_dir);
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let content_id = ContentId::new("multi-test-123".to_string());
        let content = create_test_content("multi-test-123");

        // デフォルトプロバイダー（local）に保存
        repo.save(&content_id, &content)
            .expect("failed to save content");

        // デフォルトプロバイダー（local）から取得
        let found = repo
            .find_by_id(&content_id)
            .expect("failed to find content")
            .expect("content should exist");

        assert_eq!(found.id(), content.id());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi_storage_repository_save_to_specific_provider() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let registry = create_test_registry(&temp_dir);
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let content_id = ContentId::new("specific-provider-test".to_string());
        let content = create_test_content("specific-provider-test");

        // 明示的に "local" を指定して保存
        repo.save_to("local", &content_id, &content)
            .expect("failed to save content");

        // 明示的に "local" を指定して取得
        let found = repo
            .find_from("local", &content_id)
            .expect("failed to find content")
            .expect("content should exist");

        assert_eq!(found.id(), content.id());
    }

    #[test]
    fn test_multi_storage_repository_not_connected_provider() {
        let registry = Arc::new(init_registry_default());
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let content_id = ContentId::new("test".to_string());
        let content = create_test_content("test");

        // google-drive は接続していない
        let result = repo.save_to("google-drive", &content_id, &content);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not connected"));
    }

    #[test]
    fn test_multi_storage_repository_connect_and_disconnect() {
        let registry = Arc::new(init_registry_default());
        let repo = MultiStorageRepository::in_memory(registry, "local");

        // Google Drive を接続
        let auth = AuthSession {
            access_token: "test-token".to_string(),
        };
        repo.connect("google-drive", auth).unwrap();

        // 接続済みプロバイダーに含まれる
        let connected = repo.connected_providers().unwrap();
        assert!(connected.contains(&"google-drive".to_string()));

        // 切断
        repo.disconnect("google-drive").unwrap();

        // 接続済みプロバイダーから削除されている
        let connected = repo.connected_providers().unwrap();
        assert!(!connected.contains(&"google-drive".to_string()));
    }

    #[test]
    fn test_multi_storage_repository_connect_unknown_provider() {
        let registry = Arc::new(init_registry_default());
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let auth = AuthSession {
            access_token: "test-token".to_string(),
        };

        // 存在しないプロバイダーに接続しようとするとエラー
        let result = repo.connect("unknown-provider", auth);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown storage provider"));
    }

    // ========================================================================
    // 永続化のテスト
    // ========================================================================

    #[test]
    fn test_multi_storage_repository_persistence_save_and_load() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let credentials_path = temp_dir.path().join("credentials.json");

        let registry = Arc::new(init_registry_default());

        // 永続化付きでリポジトリを作成
        let repo = MultiStorageRepository::new(registry.clone(), "local", &credentials_path)
            .expect("failed to create repo");

        // Google Drive を接続
        let auth = AuthSession {
            access_token: "test-google-token".to_string(),
        };
        repo.connect("google-drive", auth).unwrap();

        // ファイルが作成されていることを確認
        assert!(credentials_path.exists());

        // 新しいリポジトリを作成し、ファイルから読み込む
        let repo2 = MultiStorageRepository::new(registry, "local", &credentials_path)
            .expect("failed to create repo2");

        // Google Drive が接続済みになっていることを確認
        let connected = repo2.connected_providers().unwrap();
        assert!(connected.contains(&"google-drive".to_string()));
    }

    #[test]
    fn test_multi_storage_repository_persistence_disconnect_removes_from_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let credentials_path = temp_dir.path().join("credentials.json");

        let registry = Arc::new(init_registry_default());

        let repo = MultiStorageRepository::new(registry.clone(), "local", &credentials_path)
            .expect("failed to create repo");

        // 接続
        repo.connect(
            "google-drive",
            AuthSession {
                access_token: "token".into(),
            },
        )
        .unwrap();

        // 切断
        repo.disconnect("google-drive").unwrap();

        // 新しいリポジトリを作成し、ファイルから読み込む
        let repo2 = MultiStorageRepository::new(registry, "local", &credentials_path)
            .expect("failed to create repo2");

        // Google Drive が接続されていないことを確認
        let connected = repo2.connected_providers().unwrap();
        assert!(!connected.contains(&"google-drive".to_string()));
    }

    #[test]
    fn test_multi_storage_repository_in_memory() {
        let registry = Arc::new(init_registry_default());

        // 永続化なしで作成（in_memory）
        let repo = MultiStorageRepository::in_memory(registry, "local");

        // 接続してもエラーにならない（ファイルは作成されない）
        repo.connect(
            "google-drive",
            AuthSession {
                access_token: "token".into(),
            },
        )
        .unwrap();

        // 切断してもエラーにならない
        repo.disconnect("google-drive").unwrap();
    }
}
