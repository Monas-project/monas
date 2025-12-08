//! Configuration management for storage providers

use serde::{Deserialize, Serialize};
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
}

impl Default for GoogleDriveConfig {
    fn default() -> Self {
        Self {
            api_endpoint: default_google_drive_endpoint(),
            client_id: None,
            client_secret: None,
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
}
