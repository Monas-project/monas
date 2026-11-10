//! ContentRepository implementation using monas-filesync.
//!
//! Compiled only when the `filesync` feature is enabled.
//!
//! ## Provided repositories
//!
//! - [`MultiStorageRepository`] - switches between multiple storage providers

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

/// ContentRepository implementation that can switch between multiple storage providers.
///
/// Uses `Arc` internally, so it can be cheaply shared via `Clone`.
/// Useful when sharing the same repository across multiple services.
///
/// # Example
///
/// ```ignore
/// use monas_filesync::{FilesyncConfig, FetcherRegistry, AuthSession};
/// use monas_content::infrastructure::MultiStorageRepository;
///
/// let config = FilesyncConfig::from_env();
/// let registry = Arc::new(FetcherRegistry::from_config(&config));
///
/// // Create the repository (with persistence)
/// let repo = MultiStorageRepository::new(
///     registry,
///     "local",
///     "~/.monas/credentials.json",
/// )?;
///
/// // Shareable via Clone
/// let repo_clone = repo.clone();
///
/// // When the user connects Google Drive (automatically saved to the file)
/// repo.connect("google-drive", AuthSession { access_token: "...".into() })?;
///
/// // Save to a specific storage
/// repo.save_to("google-drive", &content_id, &content)?;
///
/// // Save to the default storage (via the ContentRepository trait)
/// repo.save(&content_id, &content)?;
/// ```
#[derive(Clone)]
pub struct MultiStorageRepository {
    inner: Arc<MultiStorageRepositoryInner>,
}

/// Internal state of MultiStorageRepository
struct MultiStorageRepositoryInner {
    registry: Arc<FetcherRegistry>,
    /// Auth session per provider
    auth_sessions: RwLock<HashMap<String, AuthSession>>,
    /// Provider used by default
    default_provider: RwLock<String>,
    /// Path where credentials are saved (no persistence if None)
    credentials_path: Option<PathBuf>,
}

/// Format of the credentials saved to the file
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCredentials {
    /// Provider name → access token
    sessions: HashMap<String, String>,
}

impl MultiStorageRepository {
    /// Creates a new MultiStorageRepository (with persistence).
    ///
    /// Credentials are saved as JSON at the given path.
    /// If the file already exists, it is loaded and restored.
    ///
    /// # Arguments
    ///
    /// * `registry` - FetcherRegistry holding the registered providers
    /// * `default_provider` - storage provider used by default
    /// * `credentials_path` - path where credentials are saved
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

        // Load the existing file if present
        repo.load_credentials()?;

        Ok(repo)
    }

    /// Creates a MultiStorageRepository for tests (no persistence).
    ///
    /// Credentials are kept only in memory and are lost when the app exits.
    ///
    /// # Arguments
    ///
    /// * `registry` - FetcherRegistry holding the registered providers
    /// * `default_provider` - storage provider used by default
    pub fn in_memory(registry: Arc<FetcherRegistry>, default_provider: impl Into<String>) -> Self {
        Self::create(registry, default_provider.into(), None)
    }

    /// Internal constructor
    fn create(
        registry: Arc<FetcherRegistry>,
        default_provider: String,
        credentials_path: Option<PathBuf>,
    ) -> Self {
        let mut auth_sessions = HashMap::new();

        // Local storage is connected by default (no auth required)
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

    /// Connects a storage provider (registers an auth session).
    ///
    /// Called when the user selects e.g. "Connect Google Drive" in the UI.
    /// If persistence is enabled, it is automatically saved to the file.
    pub fn connect(
        &self,
        provider: impl Into<String>,
        auth: AuthSession,
    ) -> Result<(), ContentRepositoryError> {
        let provider = provider.into();

        if self.inner.registry.resolve(&provider).is_none() {
            return Err(ContentRepositoryError::Storage(format!(
                "unknown storage provider: {provider}"
            )));
        }

        {
            let mut sessions = self.inner.auth_sessions.write().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;
            sessions.insert(provider, auth);
        }

        // Save if persistence is enabled
        self.save_credentials()?;

        Ok(())
    }

    /// Disconnects a storage provider (removes the auth session).
    ///
    /// If persistence is enabled, it is automatically removed from the file.
    pub fn disconnect(&self, provider: &str) -> Result<(), ContentRepositoryError> {
        {
            let mut sessions = self.inner.auth_sessions.write().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;
            sessions.remove(provider);
        }

        // Save if persistence is enabled
        self.save_credentials()?;

        Ok(())
    }

    /// Saves credentials to the file.
    ///
    /// Saved only when `credentials_path` is set.
    pub fn save_credentials(&self) -> Result<(), ContentRepositoryError> {
        let path = match &self.inner.credentials_path {
            Some(p) => p,
            None => return Ok(()), // Do nothing if persistence is disabled
        };

        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        // Save only non-local-storage sessions (local needs no auth)
        let persisted = PersistedCredentials {
            sessions: sessions
                .iter()
                .filter(|(k, _)| *k != "local" && *k != "local-mobile")
                .map(|(k, v)| (k.clone(), v.access_token.clone()))
                .collect(),
        };

        // Create the parent directory
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ContentRepositoryError::Storage(format!(
                    "failed to create credentials directory: {e}"
                ))
            })?;
        }

        // Save as JSON
        let json = serde_json::to_string_pretty(&persisted).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to serialize credentials: {e}"))
        })?;

        std::fs::write(path, json).map_err(|e| {
            ContentRepositoryError::Storage(format!("failed to write credentials file: {e}"))
        })?;

        Ok(())
    }

    /// Loads credentials from the file.
    ///
    /// Loaded only when `credentials_path` is set and the file exists.
    fn load_credentials(&self) -> Result<(), ContentRepositoryError> {
        let path = match &self.inner.credentials_path {
            Some(p) => p,
            None => return Ok(()), // Do nothing if persistence is disabled
        };

        // Skip if the file does not exist
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

        // Add the loaded sessions (only those present in the registry)
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

    /// Returns the list of connected providers.
    pub fn connected_providers(&self) -> Result<Vec<String>, ContentRepositoryError> {
        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        Ok(sessions.keys().cloned().collect())
    }

    /// Returns the current default provider.
    pub fn default_provider(&self) -> Result<String, ContentRepositoryError> {
        let default =
            self.inner.default_provider.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        Ok(default.clone())
    }

    /// Saves content to the specified storage provider.
    pub fn save_to(
        &self,
        provider: &str,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        let (storage_provider, auth) = self.get_provider_and_auth(provider)?;
        let path = Self::content_path(provider, content_id)?;

        let data = serde_json::to_vec(content)
            .map_err(|e| ContentRepositoryError::Storage(format!("serialization error: {e}")))?;

        tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(async { storage_provider.save(&auth, &path, &data).await })
                .map_err(|e| ContentRepositoryError::Storage(e.message))
        })
    }

    /// Fetches content from the specified storage provider.
    pub fn find_from(
        &self,
        provider: &str,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        let (storage_provider, auth) = self.get_provider_and_auth(provider)?;
        let path = Self::content_path(provider, content_id)?;

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

    /// Returns the provider and its auth session.
    fn get_provider_and_auth(
        &self,
        provider: &str,
    ) -> Result<(Arc<dyn StorageProvider>, AuthSession), ContentRepositoryError> {
        let storage_provider = self.inner.registry.resolve(provider).ok_or_else(|| {
            ContentRepositoryError::Storage(format!(
                "storage provider '{provider}' not found in registry"
            ))
        })?;

        let sessions =
            self.inner.auth_sessions.read().map_err(|e| {
                ContentRepositoryError::Storage(format!("failed to acquire lock: {e}"))
            })?;

        let auth = sessions.get(provider).ok_or_else(|| {
            ContentRepositoryError::Storage(format!(
                "storage provider '{provider}' is not connected. Call connect() first."
            ))
        })?;

        Ok((storage_provider, auth.clone()))
    }

    /// Builds a storage path from a content ID.
    ///
    /// The ID is limited to characters usable as-is in a single file name (ASCII lowercase,
    /// digits, `-`, `_`). If alternative spellings such as `./<id>`, `x/../<id>`, or uppercase
    /// (on case-insensitive file systems) reached the same record, the callers' per-file locks,
    /// keyed by string, would treat them as different, letting writes to the same file run
    /// concurrently. Paths pointing outside the directory are not allowed either.
    fn content_path(
        provider: &str,
        content_id: &ContentId,
    ) -> Result<String, ContentRepositoryError> {
        let id = content_id.as_str();
        let plain = !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !plain {
            return Err(ContentRepositoryError::Storage(format!(
                "invalid content id {id:?}: only lowercase letters, digits, '-' and '_' are allowed"
            )));
        }
        Ok(format!("{provider}://content/{id}.json"))
    }
}

/// ContentRepository trait implementation (uses the default provider)
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

/// MultiStorageContentRepository trait implementation
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
    // Test helper functions
    // ========================================================================

    /// Creates a FetcherRegistry for tests.
    ///
    /// Includes a local provider whose base_path is the given temp directory.
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

    /// Creates a Content for tests.
    fn create_test_content(id: &str) -> Content {
        serde_json::from_value(serde_json::json!({
            "raw_id": id,
            "series_id": id,
            // v2: ContentId derived from the ciphertext (encCid)
            // Tests mainly check compatibility, so fix it to the same value as plainCid.
            "encrypted_id": id,
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
    // MultiStorageRepository tests
    // ========================================================================

    #[test]
    fn test_multi_storage_repository_default_provider() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let registry = create_test_registry(&temp_dir);

        let repo = MultiStorageRepository::in_memory(registry, "local");

        // Check the default provider
        assert_eq!(repo.default_provider().unwrap(), "local");

        // Local is connected automatically
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

        // Save to the default provider (local)
        repo.save(&content_id, &content)
            .expect("failed to save content");

        // Fetch from the default provider (local)
        let found = repo
            .find_by_id(&content_id)
            .expect("failed to find content")
            .expect("content should exist");

        assert_eq!(found.raw_id(), content.raw_id());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi_storage_repository_save_to_specific_provider() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let registry = create_test_registry(&temp_dir);
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let content_id = ContentId::new("specific-provider-test".to_string());
        let content = create_test_content("specific-provider-test");

        // Save with "local" specified explicitly
        repo.save_to("local", &content_id, &content)
            .expect("failed to save content");

        // Fetch with "local" specified explicitly
        let found = repo
            .find_from("local", &content_id)
            .expect("failed to find content")
            .expect("content should exist");

        assert_eq!(found.raw_id(), content.raw_id());
    }

    #[test]
    fn test_multi_storage_repository_not_connected_provider() {
        let registry = Arc::new(init_registry_default());
        let repo = MultiStorageRepository::in_memory(registry, "local");

        let content_id = ContentId::new("test".to_string());
        let content = create_test_content("test");

        // google-drive is not connected
        let result = repo.save_to("google-drive", &content_id, &content);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not connected"));
    }

    #[test]
    fn test_multi_storage_repository_connect_and_disconnect() {
        let registry = Arc::new(init_registry_default());
        let repo = MultiStorageRepository::in_memory(registry, "local");

        // Connect Google Drive
        let auth = AuthSession {
            access_token: "test-token".to_string(),
        };
        repo.connect("google-drive", auth).unwrap();

        // Included in the connected providers
        let connected = repo.connected_providers().unwrap();
        assert!(connected.contains(&"google-drive".to_string()));

        // Disconnect
        repo.disconnect("google-drive").unwrap();

        // Removed from the connected providers
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

        // Connecting to a nonexistent provider is an error
        let result = repo.connect("unknown-provider", auth);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown storage provider"));
    }

    // ========================================================================
    // Persistence tests
    // ========================================================================

    #[test]
    fn test_multi_storage_repository_persistence_save_and_load() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let credentials_path = temp_dir.path().join("credentials.json");

        let registry = Arc::new(init_registry_default());

        // Create a repository with persistence
        let repo = MultiStorageRepository::new(registry.clone(), "local", &credentials_path)
            .expect("failed to create repo");

        // Connect Google Drive
        let auth = AuthSession {
            access_token: "test-google-token".to_string(),
        };
        repo.connect("google-drive", auth).unwrap();

        // Verify that the file was created
        assert!(credentials_path.exists());

        // Create a new repository and load from the file
        let repo2 = MultiStorageRepository::new(registry, "local", &credentials_path)
            .expect("failed to create repo2");

        // Verify that Google Drive is connected
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

        // Connect
        repo.connect(
            "google-drive",
            AuthSession {
                access_token: "token".into(),
            },
        )
        .unwrap();

        // Disconnect
        repo.disconnect("google-drive").unwrap();

        // Create a new repository and load from the file
        let repo2 = MultiStorageRepository::new(registry, "local", &credentials_path)
            .expect("failed to create repo2");

        // Verify that Google Drive is not connected
        let connected = repo2.connected_providers().unwrap();
        assert!(!connected.contains(&"google-drive".to_string()));
    }

    #[test]
    fn test_multi_storage_repository_in_memory() {
        let registry = Arc::new(init_registry_default());

        // Create without persistence (in_memory)
        let repo = MultiStorageRepository::in_memory(registry, "local");

        // Connecting does not error (no file is created)
        repo.connect(
            "google-drive",
            AuthSession {
                access_token: "token".into(),
            },
        )
        .unwrap();

        // Disconnecting does not error
        repo.disconnect("google-drive").unwrap();
    }
}
