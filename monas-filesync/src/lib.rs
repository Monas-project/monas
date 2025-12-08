pub mod infrastructure;

pub use infrastructure::{
    FilesyncConfig, ConfigError, StorageProvider, AuthSession, FetchError,
    registry::FetcherRegistry,
};

/// Initialize a registry from a configuration file
pub fn init_registry_from_file<P: AsRef<std::path::Path>>(
    config_path: P,
) -> Result<FetcherRegistry, ConfigError> {
    let config = FilesyncConfig::from_file(config_path)?;
    Ok(FetcherRegistry::from_config(&config))
}

/// Initialize a registry from a configuration string
pub fn init_registry_from_str(config_str: &str) -> Result<FetcherRegistry, ConfigError> {
    let config = FilesyncConfig::from_toml_str(config_str)?;
    Ok(FetcherRegistry::from_config(&config))
}

/// Initialize a registry with default configuration
pub fn init_registry_default() -> FetcherRegistry {
    let config = FilesyncConfig::default();
    FetcherRegistry::from_config(&config)
}
