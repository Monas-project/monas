//! Configuration management for storage providers

use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesyncConfig {
    /// IPFS provider configuration
    #[serde(default)]
    pub ipfs: IpfsConfig,

    /// Google Drive provider configuration
    #[serde(default)]
    pub google_drive: GoogleDriveConfig,

    /// OneDrive provider configuration
    #[serde(default)]
    pub onedrive: OneDriveConfig,

    /// Local storage configuration
    #[serde(default)]
    pub local: LocalConfig,
}

impl FilesyncConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;

        toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Load configuration from a TOML file and override values with environment variables
    pub fn from_file_with_env<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut config = Self::from_file(path)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Build configuration only from environment variables (falling back to defaults)
    pub fn from_env() -> Self {
        let mut config = Self::default();
        config.apply_env_overrides();
        config
    }

    /// Load configuration from a TOML string
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        std::fs::write(path, content).map_err(|e| ConfigError::IoError(e.to_string()))
    }

    /// Override configuration values with environment variables
    pub fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_with(|key| env::var(key).ok());
    }

    fn apply_env_overrides_with<F>(&mut self, mut lookup: F)
    where
        F: FnMut(&str) -> Option<String>,
    {
        if let Some(value) = lookup("MONAS_IPFS_GATEWAY") {
            self.ipfs.gateway = value;
        }

        if let Some(value) = lookup("MONAS_GOOGLE_DRIVE_API_ENDPOINT") {
            self.google_drive.api_endpoint = value;
        }
        if let Some(value) = lookup("MONAS_GOOGLE_DRIVE_CLIENT_ID") {
            self.google_drive.client_id = Some(value);
        }
        if let Some(value) = lookup("MONAS_GOOGLE_DRIVE_CLIENT_SECRET") {
            self.google_drive.client_secret = Some(value);
        }
        if let Some(value) = lookup("MONAS_GOOGLE_DRIVE_ROOT_FOLDER_ID") {
            self.google_drive.root_folder_id = Some(value);
        }
        if let Some(value) = lookup("MONAS_ONEDRIVE_API_ENDPOINT") {
            self.onedrive.api_endpoint = value;
        }
        if let Some(value) = lookup("MONAS_ONEDRIVE_CLIENT_ID") {
            self.onedrive.client_id = Some(value);
        }
        if let Some(value) = lookup("MONAS_ONEDRIVE_CLIENT_SECRET") {
            self.onedrive.client_secret = Some(value);
        }
        if let Some(value) = lookup("MONAS_LOCAL_BASE_PATH") {
            self.local.base_path = Some(value);
        }
    }
}

/// IPFS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS gateway URL (e.g., "https://ipfs.io")
    #[serde(default = "default_ipfs_gateway")]
    pub gateway: String,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            gateway: default_ipfs_gateway(),
        }
    }
}

fn default_ipfs_gateway() -> String {
    "https://ipfs.io".to_string()
}

/// Google Drive provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleDriveConfig {
    /// Google Drive API endpoint
    #[serde(default = "default_google_drive_endpoint")]
    pub api_endpoint: String,

    /// Client ID for OAuth (optional, for future implementation)
    #[serde(default)]
    pub client_id: Option<String>,

    /// Client secret for OAuth (optional, for future implementation)
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Root folder ID where files will be stored (optional).
    /// If not set, files will be created in the user's root Drive folder.
    #[serde(default)]
    pub root_folder_id: Option<String>,
}

impl Default for GoogleDriveConfig {
    fn default() -> Self {
        Self {
            api_endpoint: default_google_drive_endpoint(),
            client_id: None,
            client_secret: None,
            root_folder_id: None,
        }
    }
}

fn default_google_drive_endpoint() -> String {
    "https://www.googleapis.com/drive/v3".to_string()
}

/// OneDrive provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneDriveConfig {
    /// Microsoft Graph API endpoint
    #[serde(default = "default_onedrive_endpoint")]
    pub api_endpoint: String,

    /// Client ID for OAuth (optional, for future implementation)
    #[serde(default)]
    pub client_id: Option<String>,

    /// Client secret for OAuth (optional, for future implementation)
    #[serde(default)]
    pub client_secret: Option<String>,
}

impl Default for OneDriveConfig {
    fn default() -> Self {
        Self {
            api_endpoint: default_onedrive_endpoint(),
            client_id: None,
            client_secret: None,
        }
    }
}

fn default_onedrive_endpoint() -> String {
    "https://graph.microsoft.com/v1.0".to_string()
}

/// Local storage configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalConfig {
    /// Base path for local storage (optional)
    #[serde(default)]
    pub base_path: Option<String>,
}

/// Configuration error types
#[derive(Debug, Clone)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(msg) => write!(f, "IO error: {msg}"),
            ConfigError::ParseError(msg) => write!(f, "Parse error: {msg}"),
            ConfigError::SerializeError(msg) => write!(f, "Serialize error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use tempfile::NamedTempFile;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env_vars<T, F>(pairs: &[(&str, &str)], test: F) -> T
    where
        F: FnOnce() -> T,
    {
        let _guard = env_lock().lock().expect("env lock poisoned");
        let snapshot: Vec<(String, Option<String>)> = pairs
            .iter()
            .map(|(key, _)| ((*key).to_string(), env::var(key).ok()))
            .collect();

        unsafe {
            for (key, value) in pairs {
                env::set_var(key, value);
            }
        }

        let result = test();

        unsafe {
            for (key, value) in snapshot {
                match value {
                    Some(original) => env::set_var(&key, original),
                    None => env::remove_var(&key),
                }
            }
        }

        result
    }

    #[test]
    fn test_config_default() {
        let config = FilesyncConfig::default();
        assert_eq!(config.ipfs.gateway, "https://ipfs.io");
        assert_eq!(
            config.google_drive.api_endpoint,
            "https://www.googleapis.com/drive/v3"
        );
        assert_eq!(
            config.onedrive.api_endpoint,
            "https://graph.microsoft.com/v1.0"
        );
    }

    #[test]
    fn test_config_from_str() {
        let toml_content = r#"
[ipfs]
gateway = "https://custom-ipfs.io"

[google_drive]
api_endpoint = "https://custom.googleapis.com"
client_id = "test-client-id"

[onedrive]
api_endpoint = "https://custom.graph.microsoft.com"

[local]
base_path = "/custom/path"
"#;

        let config = FilesyncConfig::from_toml_str(toml_content).unwrap();
        assert_eq!(config.ipfs.gateway, "https://custom-ipfs.io");
        assert_eq!(
            config.google_drive.api_endpoint,
            "https://custom.googleapis.com"
        );
        assert_eq!(
            config.google_drive.client_id,
            Some("test-client-id".to_string())
        );
        assert_eq!(
            config.onedrive.api_endpoint,
            "https://custom.graph.microsoft.com"
        );
        assert_eq!(config.local.base_path, Some("/custom/path".to_string()));
    }

    #[test]
    fn test_config_partial() {
        // Partial config should use defaults for missing fields
        let toml_content = r#"
[ipfs]
gateway = "https://custom-ipfs.io"
"#;

        let config = FilesyncConfig::from_toml_str(toml_content).unwrap();
        assert_eq!(config.ipfs.gateway, "https://custom-ipfs.io");
        // Other fields should use defaults
        assert_eq!(
            config.google_drive.api_endpoint,
            "https://www.googleapis.com/drive/v3"
        );
    }

    #[test]
    fn test_config_invalid_toml() {
        let invalid_toml = "invalid toml content [";
        let result = FilesyncConfig::from_toml_str(invalid_toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_env_overrides() {
        let mut config = FilesyncConfig::default();
        config.apply_env_overrides_with(|key| match key {
            "MONAS_IPFS_GATEWAY" => Some("https://env-ipfs.io".into()),
            "MONAS_GOOGLE_DRIVE_API_ENDPOINT" => Some("https://env.googleapis.com/drive/v3".into()),
            "MONAS_GOOGLE_DRIVE_CLIENT_ID" => Some("env-google-client-id".into()),
            "MONAS_GOOGLE_DRIVE_CLIENT_SECRET" => Some("google-secret".into()),
            "MONAS_ONEDRIVE_API_ENDPOINT" => Some("https://env.graph.microsoft.com".into()),
            "MONAS_ONEDRIVE_CLIENT_ID" => Some("env-onedrive-client-id".into()),
            "MONAS_ONEDRIVE_CLIENT_SECRET" => Some("onedrive-secret".into()),
            "MONAS_LOCAL_BASE_PATH" => Some("/env/path".into()),
            _ => None,
        });

        assert_eq!(config.ipfs.gateway, "https://env-ipfs.io");
        assert_eq!(
            config.google_drive.api_endpoint,
            "https://env.googleapis.com/drive/v3"
        );
        assert_eq!(
            config.google_drive.client_id,
            Some("env-google-client-id".into())
        );
        assert_eq!(
            config.google_drive.client_secret,
            Some("google-secret".into())
        );
        assert_eq!(
            config.onedrive.api_endpoint,
            "https://env.graph.microsoft.com"
        );
        assert_eq!(
            config.onedrive.client_id,
            Some("env-onedrive-client-id".into())
        );
        assert_eq!(
            config.onedrive.client_secret,
            Some("onedrive-secret".into())
        );
        assert_eq!(config.local.base_path, Some("/env/path".into()));
    }

    #[test]
    fn test_from_env_uses_environment_variables() {
        with_env_vars(
            &[
                ("MONAS_IPFS_GATEWAY", "https://env-ipfs.io"),
                ("MONAS_LOCAL_BASE_PATH", "/tmp/env_local"),
            ],
            || {
                let config = FilesyncConfig::from_env();
                assert_eq!(config.ipfs.gateway, "https://env-ipfs.io");
                assert_eq!(config.local.base_path, Some("/tmp/env_local".into()));
            },
        );
    }

    #[test]
    fn test_from_file_with_env_overrides_file_values() {
        let mut tmp = NamedTempFile::new().expect("temp file");
        writeln!(
            tmp,
            r#"
[ipfs]
gateway = "https://file-ipfs.io"

[local]
base_path = "/file/path"
"#
        )
        .unwrap();

        with_env_vars(
            &[
                ("MONAS_IPFS_GATEWAY", "https://env-ipfs.io"),
                ("MONAS_LOCAL_BASE_PATH", "/env/path"),
            ],
            || {
                let config = FilesyncConfig::from_file_with_env(tmp.path()).expect("config");
                assert_eq!(config.ipfs.gateway, "https://env-ipfs.io");
                assert_eq!(config.local.base_path, Some("/env/path".into()));
            },
        );
    }
}
