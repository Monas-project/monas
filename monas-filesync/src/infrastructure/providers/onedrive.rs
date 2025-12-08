use std::time::SystemTime;

use crate::infrastructure::{StorageProvider, FetchError, AuthSession};
use crate::infrastructure::config::OneDriveConfig;

pub struct OneDriveProvider {
    pub api_endpoint: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl OneDriveProvider {
    pub fn new(config: &OneDriveConfig) -> Self {
        Self {
            api_endpoint: config.api_endpoint.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
        }
    }
}

#[async_trait::async_trait]
impl StorageProvider for OneDriveProvider {
    async fn fetch(&self, _auth: &AuthSession, _path: &str) -> Result<Vec<u8>, crate::infrastructure::FetchError> {
        Err(FetchError { message: "OneDrive provider not implemented".into() })
    }

    async fn size_and_mtime(&self, _auth: &AuthSession, _path: &str) -> Result<(u64, SystemTime), crate::infrastructure::FetchError> {
        Err(FetchError { message: "OneDrive size_and_mtime not implemented".into() })
    }

    async fn save(&self, _auth: &AuthSession, _path: &str, _data: &[u8]) -> Result<(), crate::infrastructure::FetchError> {
        Err(FetchError { message: "OneDrive save not implemented".into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::AuthSession;
    use crate::infrastructure::config::OneDriveConfig;

    #[tokio::test]
    async fn test_onedrive_provider_fetch() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.fetch(&auth, "onedrive://item456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("OneDrive provider not implemented"));
    }

    #[tokio::test]
    async fn test_onedrive_provider_size_and_mtime() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.size_and_mtime(&auth, "onedrive://item456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("OneDrive size_and_mtime not implemented"));
    }

    #[tokio::test]
    async fn test_onedrive_provider_save() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.save(&auth, "onedrive://item456", b"test data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("OneDrive save not implemented"));
    }

    #[test]
    fn test_onedrive_provider_stores_config() {
        let mut config = OneDriveConfig::default();
        config.api_endpoint = "https://example.graph".into();
        config.client_id = Some("client".into());
        config.client_secret = Some("secret".into());

        let provider = OneDriveProvider::new(&config);
        assert_eq!(provider.api_endpoint, "https://example.graph");
        assert_eq!(provider.client_id.as_deref(), Some("client"));
        assert_eq!(provider.client_secret.as_deref(), Some("secret"));
    }
}
