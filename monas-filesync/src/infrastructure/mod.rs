pub mod providers;
pub mod registry;
pub mod repository;
pub mod path;
pub mod config;

pub use config::{FilesyncConfig, ConfigError};

use std::fmt;
use std::time::SystemTime;

pub use path::{ExternalFilePath, ParsePathError};

pub type FetchResult<T> = Result<T, FetchError>;

#[derive(Debug, Clone)]
pub struct FetchError {
    pub message: String,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FetchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_error_display() {
        let error = FetchError {
            message: "test error message".to_string(),
        };
        assert_eq!(format!("{}", error), "test error message");
    }
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub access_token: String,
}

#[async_trait::async_trait]
pub trait StorageProvider: Send + Sync {
    async fn fetch(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>>;
    async fn size_and_mtime(&self, auth: &AuthSession, path: &str) -> FetchResult<(u64, SystemTime)>;
    async fn save(&self, auth: &AuthSession, path: &str, data: &[u8]) -> FetchResult<()>;
}
