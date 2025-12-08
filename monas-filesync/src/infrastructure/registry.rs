use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::{FilesyncConfig, StorageProvider};

pub struct FetcherRegistry(RwLock<HashMap<&'static str, Arc<dyn StorageProvider>>>);

impl Default for FetcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FetcherRegistry {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn register(&self, scheme: &'static str, f: impl StorageProvider + 'static) {
        self.0.write().unwrap().insert(scheme, Arc::new(f));
    }

    pub fn resolve(&self, scheme: &str) -> Option<Arc<dyn StorageProvider>> {
        self.0.read().unwrap().get(scheme).cloned()
    }

    /// Initialize registry from configuration
    pub fn from_config(config: &FilesyncConfig) -> Self {
        let registry = Self::new();

        // Register IPFS provider
        use crate::infrastructure::providers::ipfs::IpfsProvider;
        registry.register("ipfs", IpfsProvider::new(config.ipfs.gateway.clone()));

        // Register Google Drive provider
        use crate::infrastructure::providers::google_drive::GoogleDriveProvider;
        registry.register(
            "google-drive",
            GoogleDriveProvider::new(&config.google_drive),
        );

        // Register OneDrive provider
        use crate::infrastructure::providers::onedrive::OneDriveProvider;
        registry.register("onedrive", OneDriveProvider::new(&config.onedrive));

        // Register Local Desktop provider
        use crate::infrastructure::providers::local_desktop::LocalDesktopProvider;
        registry.register("local", LocalDesktopProvider::new(&config.local));

        // Register Local Mobile provider
        use crate::infrastructure::providers::local_mobile::LocalMobileProvider;
        registry.register("local-mobile", LocalMobileProvider::new(&config.local));

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::{GoogleDriveConfig, OneDriveConfig};
    use crate::infrastructure::providers::google_drive::GoogleDriveProvider;
    use crate::infrastructure::providers::onedrive::OneDriveProvider;

    #[test]
    fn test_registry_new() {
        let registry = FetcherRegistry::new();
        assert!(registry.resolve("google-drive").is_none());
    }

    #[test]
    fn test_registry_register_and_resolve() {
        let registry = FetcherRegistry::new();
        let provider = GoogleDriveProvider::new(&GoogleDriveConfig::default());

        registry.register("google-drive", provider);

        let resolved = registry.resolve("google-drive");
        assert!(resolved.is_some());
    }

    #[test]
    fn test_registry_resolve_unregistered() {
        let registry = FetcherRegistry::new();
        let resolved = registry.resolve("unknown");
        assert!(resolved.is_none());
    }

    #[test]
    fn test_registry_multiple_schemes() {
        let registry = FetcherRegistry::new();

        registry.register(
            "google-drive",
            GoogleDriveProvider::new(&GoogleDriveConfig::default()),
        );
        registry.register(
            "onedrive",
            OneDriveProvider::new(&OneDriveConfig::default()),
        );
        registry.register(
            "ipfs",
            crate::infrastructure::providers::ipfs::IpfsProvider::new("https://ipfs.io"),
        );

        assert!(registry.resolve("google-drive").is_some());
        assert!(registry.resolve("onedrive").is_some());
        assert!(registry.resolve("ipfs").is_some());
        assert!(registry.resolve("unknown").is_none());
    }

    #[test]
    fn test_registry_overwrite() {
        let registry = FetcherRegistry::new();

        registry.register(
            "google-drive",
            GoogleDriveProvider::new(&GoogleDriveConfig::default()),
        );
        let first = registry.resolve("google-drive");

        registry.register(
            "google-drive",
            GoogleDriveProvider::new(&GoogleDriveConfig::default()),
        );
        let second = registry.resolve("google-drive");

        assert!(first.is_some());
        assert!(second.is_some());
    }

    #[test]
    fn test_registry_from_config() {
        let config = FilesyncConfig::default();
        let registry = FetcherRegistry::from_config(&config);

        assert!(registry.resolve("ipfs").is_some());
        assert!(registry.resolve("google-drive").is_some());
        assert!(registry.resolve("onedrive").is_some());
        assert!(registry.resolve("local").is_some());
        assert!(registry.resolve("local-mobile").is_some());
    }

    #[test]
    fn test_registry_from_custom_config() {
        let toml_content = r#"
[ipfs]
gateway = "https://custom-ipfs.io"
"#;
        let config = FilesyncConfig::from_toml_str(toml_content).unwrap();
        let registry = FetcherRegistry::from_config(&config);

        assert!(registry.resolve("ipfs").is_some());
    }
}
