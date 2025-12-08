use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::infrastructure::{AuthSession, StorageProvider, FetchError};
use crate::infrastructure::config::LocalConfig;

pub struct LocalMobileProvider {
    pub base_path: Option<PathBuf>,
}

impl LocalMobileProvider {
    pub fn new(config: &LocalConfig) -> Self {
        Self {
            base_path: config.base_path.as_ref().map(PathBuf::from),
        }
    }

    fn resolve_local_path(&self, path: &str) -> Result<PathBuf, FetchError> {
        // TODO: This is a hack to get the path from the URI.
        const PREFIX: &str = "local-mobile://";

        if !path.starts_with(PREFIX) {
            return Err(FetchError {
                message: format!("unsupported local URI: {path}"),
            });
        }

        let without_scheme = &path[PREFIX.len()..];
        if without_scheme.is_empty() {
            return Err(FetchError {
                message: "local URI is missing a filesystem path".into(),
            });
        }

        let mut resolved = PathBuf::from(without_scheme);

        if resolved.is_relative() {
            if let Some(base) = &self.base_path {
                resolved = base.join(resolved);
            }
        }

        Ok(resolved)
    }

    fn read_file_bytes(path: &Path) -> Result<Vec<u8>, FetchError> {
        fs::read(path).map_err(|err| FetchError {
            message: format!("failed to read {}: {err}", path.display()),
        })
    }

    fn file_metadata(path: &Path) -> Result<(u64, SystemTime), FetchError> {
        let metadata = fs::metadata(path).map_err(|err| FetchError {
            message: format!("failed to inspect {}: {err}", path.display()),
        })?;

        let modified = metadata.modified().map_err(|err| FetchError {
            message: format!("failed to read modified time for {}: {err}", path.display()),
        })?;

        Ok((metadata.len(), modified))
    }

    fn write_file_bytes(path: &Path, data: &[u8]) -> Result<(), FetchError> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| FetchError {
                message: format!("failed to create directory for {}: {err}", path.display()),
            })?;
        }

        fs::write(path, data).map_err(|err| FetchError {
            message: format!("failed to write {}: {err}", path.display()),
        })
    }
}

#[async_trait::async_trait]
impl StorageProvider for LocalMobileProvider {
    async fn fetch(&self, _auth: &AuthSession, path: &str) -> Result<Vec<u8>, FetchError> {
        let resolved = self.resolve_local_path(path)?;
        Self::read_file_bytes(&resolved)
    }

    async fn size_and_mtime(&self, _auth: &AuthSession, path: &str) -> Result<(u64, SystemTime), FetchError> {
        let resolved = self.resolve_local_path(path)?;
        Self::file_metadata(&resolved)
    }

    async fn save(&self, _auth: &AuthSession, path: &str, data: &[u8]) -> Result<(), FetchError> {
        let resolved = self.resolve_local_path(path)?;
        Self::write_file_bytes(&resolved, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use crate::infrastructure::config::LocalConfig;
    use tempfile::{NamedTempFile, TempDir};

    fn make_auth() -> AuthSession {
        AuthSession { access_token: "test_token".to_string() }
    }

    fn make_provider() -> LocalMobileProvider {
        LocalMobileProvider::new(&LocalConfig::default())
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_fetch_success() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "hello local mobile").unwrap();
        let path = format!("local-mobile://{}", tmp.path().display());

        let provider = make_provider();
        let bytes = provider.fetch(&make_auth(), &path).await.unwrap();

        assert!(String::from_utf8(bytes).unwrap().contains("hello local mobile"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_fetch_missing_file() {
        let provider = make_provider();
        let bad_path = "local-mobile:///missing/mobile/file";

        let result = provider.fetch(&make_auth(), bad_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("failed to read"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_size_and_mtime_success() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "abc").unwrap();
        let path = format!("local-mobile://{}", tmp.path().display());

        let provider = make_provider();
        let (size, _mtime) = provider.size_and_mtime(&make_auth(), &path).await.unwrap();

        assert_eq!(size, 3);
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_unsupported_uri() {
        let provider = make_provider();
        let result = provider.fetch(&make_auth(), "unsupported://path").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unsupported local URI"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_empty_path() {
        let provider = make_provider();
        let result = provider.fetch(&make_auth(), "local-mobile://").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("missing a filesystem path"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_size_and_mtime_missing_file() {
        let provider = make_provider();
        let bad_path = "local-mobile:///definitely/missing/file";

        let result = provider.size_and_mtime(&make_auth(), bad_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("failed to inspect"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_size_and_mtime_unsupported_uri() {
        let provider = make_provider();
        let result = provider.size_and_mtime(&make_auth(), "unsupported://path").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unsupported local URI"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_size_and_mtime_empty_path() {
        let provider = make_provider();
        let result = provider.size_and_mtime(&make_auth(), "local-mobile://").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("missing a filesystem path"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_save_success() {
        let tmp = NamedTempFile::new().unwrap();
        let path = format!("local-mobile://{}", tmp.path().display());
        let data = b"test save data mobile";

        let provider = make_provider();
        provider.save(&make_auth(), &path, data).await.unwrap();

        // Verify the file was written
        let saved_data = fs::read(tmp.path()).unwrap();
        assert_eq!(saved_data, data);
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_save_unsupported_uri() {
        let provider = make_provider();
        let result = provider.save(&make_auth(), "unsupported://path", b"data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unsupported local URI"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_save_empty_path() {
        let provider = make_provider();
        let result = provider.save(&make_auth(), "local-mobile://", b"data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("missing a filesystem path"));
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_save_with_parent_directories() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("subdir").join("file.txt");
        let path = format!("local-mobile://{}", file_path.display());
        let data = b"test data in subdirectory mobile";

        let provider = make_provider();
        provider.save(&make_auth(), &path, data).await.unwrap();

        // Verify the file was written and parent directory was created
        assert!(file_path.exists());
        let saved_data = fs::read(&file_path).unwrap();
        assert_eq!(saved_data, data);
    }

    #[tokio::test]
    async fn test_local_mobile_fetcher_resolves_relative_with_base_path() {
        let dir = TempDir::new().unwrap();
        let config = LocalConfig { base_path: Some(dir.path().to_string_lossy().into_owned()) };
        let provider = LocalMobileProvider::new(&config);
        let relative_path = "local-mobile://nested/file.txt";
        let data = b"content";

        provider.save(&make_auth(), relative_path, data).await.unwrap();

        let expected_path = dir.path().join("nested").join("file.txt");
        let saved_data = fs::read(expected_path).unwrap();
        assert_eq!(saved_data, data);
    }
}
