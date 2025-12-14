use std::time::SystemTime;

#[cfg(feature = "cloud-connectivity")]
use std::time::Duration;

use crate::infrastructure::config::OneDriveConfig;
use crate::infrastructure::{AuthSession, FetchError, FetchResult, StorageProvider};

#[cfg(feature = "cloud-connectivity")]
use reqwest::Client;
#[cfg(feature = "cloud-connectivity")]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub struct OneDriveProvider {
    pub api_endpoint: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    #[cfg(feature = "cloud-connectivity")]
    http_client: Client,
}

impl OneDriveProvider {
    pub fn new(config: &OneDriveConfig) -> Self {
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
    fn extract_item_id(path: &str) -> FetchResult<&str> {
        const PREFIX: &str = "onedrive://";
        if !path.starts_with(PREFIX) {
            return Err(FetchError {
                message: format!("unsupported OneDrive URI: {path}"),
            });
        }

        let id = &path[PREFIX.len()..];
        if id.is_empty() {
            return Err(FetchError {
                message: "OneDrive URI is missing an item id".into(),
            });
        }

        Ok(id)
    }

    fn feature_disabled_error(op: &str) -> FetchError {
        FetchError {
            message: format!("OneDrive {op} requires enabling the `cloud-connectivity` feature"),
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    fn trim_endpoint(&self) -> &str {
        self.api_endpoint.trim_end_matches('/')
    }

    #[cfg(feature = "cloud-connectivity")]
    fn item_content_url(&self, item_id: &str) -> String {
        format!("{}/drive/items/{}/content", self.trim_endpoint(), item_id)
    }

    #[cfg(feature = "cloud-connectivity")]
    fn item_metadata_url(&self, item_id: &str) -> String {
        format!(
            "{}/drive/items/{}?select=size,lastModifiedDateTime",
            self.trim_endpoint(),
            item_id
        )
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_remote(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>> {
        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing OneDrive access token".into(),
            });
        }

        let item_id = Self::extract_item_id(path)?;
        let url = self.item_content_url(item_id);

        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("OneDrive fetch request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("OneDrive fetch failed with status {}", resp.status()),
            });
        }

        let bytes = resp.bytes().await.map_err(|err| FetchError {
            message: format!("failed to read OneDrive response body: {err}"),
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
            size: Option<u64>,
            #[serde(rename = "lastModifiedDateTime")]
            last_modified: Option<String>,
        }

        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing OneDrive access token".into(),
            });
        }

        let item_id = Self::extract_item_id(path)?;
        let url = self.item_metadata_url(item_id);

        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("OneDrive metadata request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("OneDrive metadata failed with status {}", resp.status()),
            });
        }

        let metadata: Metadata = resp.json().await.map_err(|err| FetchError {
            message: format!("failed to parse OneDrive metadata: {err}"),
        })?;

        let size = metadata.size.ok_or_else(|| FetchError {
            message: "OneDrive metadata missing size".into(),
        })?;

        let modified_str = metadata.last_modified.ok_or_else(|| FetchError {
            message: "OneDrive metadata missing lastModifiedDateTime".into(),
        })?;

        let parsed = OffsetDateTime::parse(&modified_str, &Rfc3339).map_err(|err| FetchError {
            message: format!("failed to parse lastModifiedDateTime: {err}"),
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

    #[cfg(feature = "cloud-connectivity")]
    async fn save_remote(&self, auth: &AuthSession, path: &str, data: &[u8]) -> FetchResult<()> {
        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing OneDrive access token".into(),
            });
        }

        let item_id = Self::extract_item_id(path)?;
        let url = self.item_content_url(item_id);

        let resp = self
            .http_client
            .put(url)
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("OneDrive save request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("OneDrive save failed with status {}", resp.status()),
            });
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageProvider for OneDriveProvider {
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

    async fn save(&self, auth: &AuthSession, path: &str, data: &[u8]) -> FetchResult<()> {
        #[cfg(feature = "cloud-connectivity")]
        {
            return self.save_remote(auth, path, data).await;
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path, data);
            Err(Self::feature_disabled_error("save"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::OneDriveConfig;
    use crate::infrastructure::AuthSession;

    #[tokio::test]
    async fn test_onedrive_provider_fetch() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.fetch(&auth, "onedrive://item456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[tokio::test]
    async fn test_onedrive_provider_size_and_mtime() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.size_and_mtime(&auth, "onedrive://item456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[tokio::test]
    async fn test_onedrive_provider_save() {
        let provider = OneDriveProvider::new(&OneDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider
            .save(&auth, "onedrive://item456", b"test data")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[test]
    fn test_onedrive_provider_stores_config() {
        let config = OneDriveConfig {
            api_endpoint: "https://example.graph".into(),
            client_id: Some("client".into()),
            client_secret: Some("secret".into()),
        };

        let provider = OneDriveProvider::new(&config);
        assert_eq!(provider.api_endpoint, "https://example.graph");
        assert_eq!(provider.client_id.as_deref(), Some("client"));
        assert_eq!(provider.client_secret.as_deref(), Some("secret"));
    }

    #[test]
    fn test_extract_item_id_success() {
        let id = OneDriveProvider::extract_item_id("onedrive://abc").unwrap();
        assert_eq!(id, "abc");
    }

    #[test]
    fn test_extract_item_id_errors() {
        let err = OneDriveProvider::extract_item_id("invalid://abc").unwrap_err();
        assert!(err.message.contains("unsupported"));

        let err = OneDriveProvider::extract_item_id("onedrive://").unwrap_err();
        assert!(err.message.contains("missing an item id"));
    }
}
