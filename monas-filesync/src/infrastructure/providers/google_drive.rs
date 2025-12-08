use std::time::SystemTime;

#[cfg(feature = "cloud-connectivity")]
use std::time::Duration;

use crate::infrastructure::config::GoogleDriveConfig;
use crate::infrastructure::{AuthSession, FetchError, FetchResult, StorageProvider};

#[cfg(feature = "cloud-connectivity")]
use reqwest::Client;
#[cfg(feature = "cloud-connectivity")]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub struct GoogleDriveProvider {
    pub api_endpoint: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    #[cfg(feature = "cloud-connectivity")]
    http_client: Client,
}

impl GoogleDriveProvider {
    pub fn new(config: &GoogleDriveConfig) -> Self {
        Self {
            api_endpoint: config.api_endpoint.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            #[cfg(feature = "cloud-connectivity")]
            http_client: Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("failed to create reqwest client"),
        }
    }

    #[cfg_attr(not(feature = "cloud-connectivity"), allow(dead_code))]
    fn extract_file_id(path: &str) -> FetchResult<&str> {
        const PREFIX: &str = "google-drive://";
        if !path.starts_with(PREFIX) {
            return Err(FetchError {
                message: format!("unsupported Google Drive URI: {path}"),
            });
        }

        let id = &path[PREFIX.len()..];
        if id.is_empty() {
            return Err(FetchError {
                message: "Google Drive URI is missing a file id".into(),
            });
        }

        Ok(id)
    }

    fn feature_disabled_error(op: &str) -> FetchError {
        FetchError {
            message: format!(
                "Google Drive {op} requires enabling the `cloud-connectivity` feature"
            ),
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    fn trim_endpoint(&self) -> &str {
        self.api_endpoint.trim_end_matches('/')
    }

    #[cfg(feature = "cloud-connectivity")]
    fn file_content_url(&self, file_id: &str) -> String {
        format!("{}/files/{}?alt=media", self.trim_endpoint(), file_id)
    }

    #[cfg(feature = "cloud-connectivity")]
    fn file_metadata_url(&self, file_id: &str) -> String {
        format!(
            "{}/files/{}?fields=size,modifiedTime",
            self.trim_endpoint(),
            file_id
        )
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_remote(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>> {
        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing Google Drive access token".into(),
            });
        }

        let file_id = Self::extract_file_id(path)?;
        let url = self.file_content_url(file_id);

        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive fetch request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("Google Drive fetch failed with status {}", resp.status()),
            });
        }

        let bytes = resp.bytes().await.map_err(|err| FetchError {
            message: format!("failed to read Google Drive response body: {err}"),
        })?;

        Ok(bytes.to_vec())
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_metadata(
        &self,
        auth: &AuthSession,
        path: &str,
    ) -> FetchResult<(u64, SystemTime)> {
        #[derive(serde::Deserialize)]
        struct Metadata {
            size: Option<String>,
            #[serde(rename = "modifiedTime")]
            modified_time: Option<String>,
        }

        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing Google Drive access token".into(),
            });
        }

        let file_id = Self::extract_file_id(path)?;
        let url = self.file_metadata_url(file_id);

        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive metadata request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("Google Drive metadata failed with status {}", resp.status()),
            });
        }

        let metadata: Metadata = resp.json().await.map_err(|err| FetchError {
            message: format!("failed to parse Google Drive metadata: {err}"),
        })?;

        let size = metadata
            .size
            .ok_or_else(|| FetchError {
                message: "Google Drive metadata missing size".into(),
            })?
            .parse::<u64>()
            .map_err(|err| FetchError {
                message: format!("invalid Google Drive size value: {err}"),
            })?;

        let modified_str = metadata.modified_time.ok_or_else(|| FetchError {
            message: "Google Drive metadata missing modifiedTime".into(),
        })?;

        let parsed = OffsetDateTime::parse(&modified_str, &Rfc3339).map_err(|err| FetchError {
            message: format!("failed to parse modifiedTime: {err}"),
        })?;

        let timestamp = parsed.unix_timestamp();
        let system_time = if timestamp >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64)
        } else {
            SystemTime::UNIX_EPOCH
                .checked_sub(Duration::from_secs(timestamp.unsigned_abs()))
                .unwrap_or(SystemTime::UNIX_EPOCH)
        };

        Ok((size, system_time))
    }
}

#[async_trait::async_trait]
impl StorageProvider for GoogleDriveProvider {
    async fn fetch(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>> {
        #[cfg(feature = "cloud-connectivity")]
        {
            return self.fetch_remote(auth, path).await;
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path);
            Err(Self::feature_disabled_error("fetch"))
        }
    }

    async fn size_and_mtime(
        &self,
        auth: &AuthSession,
        path: &str,
    ) -> FetchResult<(u64, SystemTime)> {
        #[cfg(feature = "cloud-connectivity")]
        {
            return self.fetch_metadata(auth, path).await;
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path);
            Err(Self::feature_disabled_error("size_and_mtime"))
        }
    }

    async fn save(&self, _auth: &AuthSession, _path: &str, _data: &[u8]) -> FetchResult<()> {
        Err(FetchError {
            message: "Google Drive save is not yet supported".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::GoogleDriveConfig;

    #[tokio::test]
    async fn test_google_drive_provider_fetch() {
        let provider = GoogleDriveProvider::new(&GoogleDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.fetch(&auth, "google-drive://file123").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[tokio::test]
    async fn test_google_drive_provider_size_and_mtime() {
        let provider = GoogleDriveProvider::new(&GoogleDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider
            .size_and_mtime(&auth, "google-drive://file123")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[tokio::test]
    async fn test_google_drive_provider_save() {
        let provider = GoogleDriveProvider::new(&GoogleDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider
            .save(&auth, "google-drive://file123", b"test data")
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("Google Drive save is not yet supported"));
    }

    #[test]
    fn test_google_drive_provider_stores_config() {
        let mut config = GoogleDriveConfig::default();
        config.api_endpoint = "https://example.com".into();
        config.client_id = Some("client".into());
        config.client_secret = Some("secret".into());

        let provider = GoogleDriveProvider::new(&config);
        assert_eq!(provider.api_endpoint, "https://example.com");
        assert_eq!(provider.client_id.as_deref(), Some("client"));
        assert_eq!(provider.client_secret.as_deref(), Some("secret"));
    }

    #[test]
    fn test_extract_file_id_success() {
        let id = GoogleDriveProvider::extract_file_id("google-drive://abc").unwrap();
        assert_eq!(id, "abc");
    }

    #[test]
    fn test_extract_file_id_errors() {
        let err = GoogleDriveProvider::extract_file_id("invalid://abc").unwrap_err();
        assert!(err.message.contains("unsupported"));

        let err = GoogleDriveProvider::extract_file_id("google-drive://").unwrap_err();
        assert!(err.message.contains("missing a file id"));
    }
}
