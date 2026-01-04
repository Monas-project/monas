use std::time::SystemTime;

#[cfg(feature = "cloud-connectivity")]
use std::time::Duration;

use crate::infrastructure::config::GoogleDriveConfig;
use crate::infrastructure::{AuthSession, FetchError, FetchResult, StorageProvider};

#[cfg(feature = "cloud-connectivity")]
use reqwest::Client;
#[cfg(feature = "cloud-connectivity")]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Parsed path information
#[derive(Debug, PartialEq)]
enum PathInfo<'a> {
    /// Legacy format: direct file ID
    ById(&'a str),
    /// New format: folder name and filename
    ByName { folder: &'a str, filename: &'a str },
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Deserialize)]
struct FileItem {
    id: String,
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Deserialize)]
struct FileList {
    files: Vec<FileItem>,
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Deserialize)]
struct Metadata {
    size: Option<String>,
    #[serde(rename = "modifiedTime")]
    modified_time: Option<String>,
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Serialize)]
struct CreateFolderRequest<'a> {
    name: &'a str,
    #[serde(rename = "mimeType")]
    mime_type: &'a str,
    parents: Vec<&'a str>,
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Deserialize)]
struct CreateResponse {
    id: String,
}

#[cfg(feature = "cloud-connectivity")]
#[derive(serde::Serialize)]
struct FileMetadata<'a> {
    name: &'a str,
    parents: Vec<&'a str>,
}

pub struct GoogleDriveProvider {
    pub api_endpoint: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub root_folder_id: Option<String>,
    #[cfg(feature = "cloud-connectivity")]
    http_client: Client,
}

impl GoogleDriveProvider {
    pub fn new(config: &GoogleDriveConfig) -> Self {
        Self {
            api_endpoint: config.api_endpoint.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            root_folder_id: config.root_folder_id.clone(),
            #[cfg(feature = "cloud-connectivity")]
            http_client: Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("failed to create reqwest client"),
        }
    }

    /// Parses a Google Drive path and returns (folder_path, filename) or just file_id.
    ///
    /// Supported formats:
    /// - `google-drive://content/filename.json` -> PathInfo::ByName { folder: "content", filename: "filename.json" }
    /// - `google-drive://file_id` -> PathInfo::ById("file_id")
    #[cfg_attr(not(feature = "cloud-connectivity"), allow(dead_code))]
    fn parse_path(path: &str) -> FetchResult<PathInfo<'_>> {
        const PREFIX: &str = "google-drive://";
        if !path.starts_with(PREFIX) {
            return Err(FetchError {
                message: format!("unsupported Google Drive URI: {path}"),
            });
        }

        let rest = &path[PREFIX.len()..];
        if rest.is_empty() {
            return Err(FetchError {
                message: "Google Drive URI is missing a path".into(),
            });
        }

        // Check if it's a path with folder/filename format
        if let Some(slash_pos) = rest.find('/') {
            let folder = &rest[..slash_pos];
            let filename = &rest[slash_pos + 1..];
            if filename.is_empty() {
                return Err(FetchError {
                    message: "Google Drive URI is missing a filename".into(),
                });
            }
            Ok(PathInfo::ByName { folder, filename })
        } else {
            // Legacy format: just a file ID
            Ok(PathInfo::ById(rest))
        }
    }

    #[allow(dead_code)]
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
    fn upload_endpoint(&self) -> String {
        let trimmed = self.trim_endpoint();
        if trimmed.contains("/upload/") {
            trimmed.to_string()
        } else if let Some(idx) = trimmed.find("/drive/") {
            let prefix = &trimmed[..idx];
            let suffix = &trimmed[idx + "/drive/".len()..];
            format!("{prefix}/upload/drive/{suffix}")
        } else {
            format!("{trimmed}/upload")
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    fn file_upload_url(&self, file_id: &str) -> String {
        let base = self.upload_endpoint();
        format!(
            "{}/files/{}?uploadType=media",
            base.trim_end_matches('/'),
            file_id
        )
    }

    /// Validate and extract access token from auth session
    #[cfg(feature = "cloud-connectivity")]
    fn validate_token<'a>(&self, auth: &'a AuthSession) -> FetchResult<&'a str> {
        let token = auth.access_token.trim();
        if token.is_empty() {
            return Err(FetchError {
                message: "missing Google Drive access token".into(),
            });
        }
        Ok(token)
    }

    /// Execute a GET request and parse JSON response
    #[cfg(feature = "cloud-connectivity")]
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        url: &str,
        error_context: &str,
    ) -> FetchResult<T> {
        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive {error_context} request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!(
                    "Google Drive {} failed with status {}",
                    error_context,
                    resp.status()
                ),
            });
        }

        resp.json().await.map_err(|err| FetchError {
            message: format!("failed to parse {error_context} response: {err}"),
        })
    }

    /// Execute a GET request and return raw bytes
    #[cfg(feature = "cloud-connectivity")]
    async fn get_bytes(&self, token: &str, url: &str, error_context: &str) -> FetchResult<Vec<u8>> {
        let resp = self
            .http_client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive {error_context} request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!(
                    "Google Drive {} failed with status {}",
                    error_context,
                    resp.status()
                ),
            });
        }

        resp.bytes()
            .await
            .map_err(|err| FetchError {
                message: format!("failed to read {error_context} response body: {err}"),
            })
            .map(|b| b.to_vec())
    }

    /// Resolve file ID from path (supports both ById and ByName formats)
    #[cfg(feature = "cloud-connectivity")]
    async fn resolve_file_id(&self, token: &str, path: &str) -> FetchResult<String> {
        match Self::parse_path(path)? {
            PathInfo::ById(id) => Ok(id.to_string()),
            PathInfo::ByName { folder, filename } => {
                let folder_id =
                    self.find_folder(token, folder)
                        .await?
                        .ok_or_else(|| FetchError {
                            message: format!("Google Drive folder not found: {folder}"),
                        })?;

                self.find_file_in_folder(token, &folder_id, filename)
                    .await?
                    .ok_or_else(|| FetchError {
                        message: format!("Google Drive file not found: {folder}/{filename}"),
                    })
            }
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_remote(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>> {
        let token = self.validate_token(auth)?;
        let file_id = self.resolve_file_id(token, path).await?;
        let url = self.file_content_url(&file_id);
        self.get_bytes(token, &url, "fetch").await
    }

    /// Search for folders by name in a parent folder
    #[cfg(feature = "cloud-connectivity")]
    async fn search_folders(
        &self,
        token: &str,
        folder_name: &str,
        parent_id: &str,
    ) -> FetchResult<FileList> {
        // Escape single quotes in folder_name to prevent query injection
        let escaped_folder_name = folder_name.replace('\'', "\\'");
        let query = format!(
            "name='{escaped_folder_name}' and mimeType='application/vnd.google-apps.folder' and '{parent_id}' in parents and trashed=false"
        );
        let url = format!(
            "{}/files?q={}&fields=files(id,name)",
            self.trim_endpoint(),
            urlencoding::encode(&query)
        );

        self.get_json(token, &url, "folder search").await
    }

    /// Find a folder by name (without creating it)
    #[cfg(feature = "cloud-connectivity")]
    async fn find_folder(&self, token: &str, folder_name: &str) -> FetchResult<Option<String>> {
        let parent_id = self.root_folder_id.as_deref().unwrap_or("root");
        let list = self.search_folders(token, folder_name, parent_id).await?;
        Ok(list.files.into_iter().next().map(|f| f.id))
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_metadata(
        &self,
        auth: &AuthSession,
        path: &str,
    ) -> FetchResult<(u64, SystemTime)> {
        let token = self.validate_token(auth)?;
        let file_id = self.resolve_file_id(token, path).await?;
        let url = self.file_metadata_url(&file_id);

        let metadata: Metadata = self.get_json(token, &url, "metadata").await?;

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

    #[cfg(feature = "cloud-connectivity")]
    async fn save_remote(&self, auth: &AuthSession, path: &str, data: &[u8]) -> FetchResult<()> {
        let token = self.validate_token(auth)?;

        match Self::parse_path(path)? {
            PathInfo::ById(file_id) => {
                // Legacy mode: update existing file by ID
                self.update_file_by_id(token, file_id, data).await
            }
            PathInfo::ByName { folder, filename } => {
                // New mode: search for file, create if not found
                self.save_by_name(token, folder, filename, data).await
            }
        }
    }

    /// Update an existing file by its ID (PATCH)
    #[cfg(feature = "cloud-connectivity")]
    async fn update_file_by_id(&self, token: &str, file_id: &str, data: &[u8]) -> FetchResult<()> {
        let url = self.file_upload_url(file_id);

        let resp = self
            .http_client
            .patch(url)
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive update request failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!("Google Drive update failed with status {}", resp.status()),
            });
        }

        Ok(())
    }

    /// Save file by folder name and filename (search → create or update)
    #[cfg(feature = "cloud-connectivity")]
    async fn save_by_name(
        &self,
        token: &str,
        folder: &str,
        filename: &str,
        data: &[u8],
    ) -> FetchResult<()> {
        // Get folder ID (create folder only if it doesn't exist)
        let folder_id = self.get_or_create_folder_id(token, folder).await?;

        // Search for existing file in the folder
        if let Some(file_id) = self
            .find_file_in_folder(token, &folder_id, filename)
            .await?
        {
            // File exists, update it
            self.update_file_by_id(token, &file_id, data).await
        } else {
            // File doesn't exist, create it
            self.create_file(token, &folder_id, filename, data).await
        }
    }

    /// Get folder ID, creating the folder if it doesn't exist
    #[cfg(feature = "cloud-connectivity")]
    async fn get_or_create_folder_id(&self, token: &str, folder_name: &str) -> FetchResult<String> {
        // Try to find existing folder
        if let Some(folder_id) = self.find_folder(token, folder_name).await? {
            return Ok(folder_id);
        }

        // Folder doesn't exist, create it
        let parent_id = self.root_folder_id.as_deref().unwrap_or("root");
        self.create_folder(token, parent_id, folder_name).await
    }

    /// Create a new folder
    #[cfg(feature = "cloud-connectivity")]
    async fn create_folder(
        &self,
        token: &str,
        parent_id: &str,
        folder_name: &str,
    ) -> FetchResult<String> {
        let url = format!("{}/files", self.trim_endpoint());

        let body = CreateFolderRequest {
            name: folder_name,
            mime_type: "application/vnd.google-apps.folder",
            parents: vec![parent_id],
        };

        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive folder creation failed: {err}"),
            })?;

        if !resp.status().is_success() {
            return Err(FetchError {
                message: format!(
                    "Google Drive folder creation failed with status {}",
                    resp.status()
                ),
            });
        }

        let created: CreateResponse = resp.json().await.map_err(|err| FetchError {
            message: format!("failed to parse folder creation response: {err}"),
        })?;

        Ok(created.id)
    }

    /// Search for a file by name within a folder
    #[cfg(feature = "cloud-connectivity")]
    async fn find_file_in_folder(
        &self,
        token: &str,
        folder_id: &str,
        filename: &str,
    ) -> FetchResult<Option<String>> {
        // Escape single quotes in filename to prevent query injection
        let escaped_filename = filename.replace('\'', "\\'");
        let query =
            format!("name='{escaped_filename}' and '{folder_id}' in parents and trashed=false");
        let url = format!(
            "{}/files?q={}&fields=files(id,name)",
            self.trim_endpoint(),
            urlencoding::encode(&query)
        );

        let list: FileList = self.get_json(token, &url, "file search").await?;
        Ok(list.files.into_iter().next().map(|f| f.id))
    }

    /// Create a new file with content
    #[cfg(feature = "cloud-connectivity")]
    async fn create_file(
        &self,
        token: &str,
        folder_id: &str,
        filename: &str,
        data: &[u8],
    ) -> FetchResult<()> {
        // Use multipart upload for creating file with content
        let upload_url = format!("{}/files?uploadType=multipart", self.upload_endpoint());

        // Build multipart body
        let metadata = FileMetadata {
            name: filename,
            parents: vec![folder_id],
        };
        let metadata_json = serde_json::to_string(&metadata).map_err(|err| FetchError {
            message: format!("failed to serialize file metadata: {err}"),
        })?;

        // Create multipart form
        let form = reqwest::multipart::Form::new()
            .part(
                "metadata",
                reqwest::multipart::Part::text(metadata_json)
                    .mime_str("application/json")
                    .map_err(|err| FetchError {
                        message: format!("failed to set metadata mime type: {err}"),
                    })?,
            )
            .part(
                "media",
                reqwest::multipart::Part::bytes(data.to_vec())
                    .mime_str("application/octet-stream")
                    .map_err(|err| FetchError {
                        message: format!("failed to set media mime type: {err}"),
                    })?,
            );

        let resp = self
            .http_client
            .post(&upload_url)
            .bearer_auth(token)
            .multipart(form)
            .send()
            .await
            .map_err(|err| FetchError {
                message: format!("Google Drive file creation failed: {err}"),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(FetchError {
                message: format!("Google Drive file creation failed with status {status}: {body}"),
            });
        }

        Ok(())
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
    use crate::infrastructure::config::GoogleDriveConfig;

    #[tokio::test]
    #[cfg(not(feature = "cloud-connectivity"))]
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
    #[cfg(not(feature = "cloud-connectivity"))]
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
    #[cfg(not(feature = "cloud-connectivity"))]
    async fn test_google_drive_provider_save() {
        let provider = GoogleDriveProvider::new(&GoogleDriveConfig::default());
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider
            .save(&auth, "google-drive://file123", b"test data")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[test]
    fn test_google_drive_provider_stores_config() {
        let config = GoogleDriveConfig {
            api_endpoint: "https://example.com".into(),
            client_id: Some("client".into()),
            client_secret: Some("secret".into()),
            root_folder_id: Some("root123".into()),
        };

        let provider = GoogleDriveProvider::new(&config);
        assert_eq!(provider.api_endpoint, "https://example.com");
        assert_eq!(provider.client_id.as_deref(), Some("client"));
        assert_eq!(provider.client_secret.as_deref(), Some("secret"));
        assert_eq!(provider.root_folder_id.as_deref(), Some("root123"));
    }

    #[test]
    fn test_parse_path_by_id() {
        let result = GoogleDriveProvider::parse_path("google-drive://abc123").unwrap();
        assert_eq!(result, PathInfo::ById("abc123"));
    }

    #[test]
    fn test_parse_path_by_name() {
        let result = GoogleDriveProvider::parse_path("google-drive://content/file.json").unwrap();
        assert_eq!(
            result,
            PathInfo::ByName {
                folder: "content",
                filename: "file.json"
            }
        );
    }

    #[test]
    fn test_parse_path_errors() {
        let err = GoogleDriveProvider::parse_path("invalid://abc").unwrap_err();
        assert!(err.message.contains("unsupported"));

        let err = GoogleDriveProvider::parse_path("google-drive://").unwrap_err();
        assert!(err.message.contains("missing a path"));

        let err = GoogleDriveProvider::parse_path("google-drive://folder/").unwrap_err();
        assert!(err.message.contains("missing a filename"));
    }
}
