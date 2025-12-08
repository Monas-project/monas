use std::time::SystemTime;

use crate::infrastructure::{StorageProvider, FetchError, AuthSession};

pub struct IpfsProvider { pub gateway: String }

impl IpfsProvider { pub fn new(gateway: impl Into<String>) -> Self { Self { gateway: gateway.into() } } }

#[async_trait::async_trait]
impl StorageProvider for IpfsProvider {
    async fn fetch(&self, _auth: &AuthSession, _path: &str) -> Result<Vec<u8>, crate::infrastructure::FetchError> {
        Err(FetchError { message: "IPFS provider not implemented".into() })
    }

    async fn size_and_mtime(&self, _auth: &AuthSession, _path: &str) -> Result<(u64, SystemTime), crate::infrastructure::FetchError> {
        Err(FetchError { message: "IPFS size_and_mtime not implemented".into() })
    }

    async fn save(&self, _auth: &AuthSession, _path: &str, _data: &[u8]) -> Result<(), crate::infrastructure::FetchError> {
        Err(FetchError { message: "IPFS save not implemented".into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::AuthSession;

    #[test]
    fn test_ipfs_provider_new() {
        let provider = IpfsProvider::new("https://ipfs.io");
        assert_eq!(provider.gateway, "https://ipfs.io");
        
        // Test with String type
        let gateway = String::from("https://gateway.ipfs.io");
        let provider = IpfsProvider::new(gateway.clone());
        assert_eq!(provider.gateway, gateway);
    }

    #[tokio::test]
    async fn test_ipfs_provider_fetch() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.fetch(&auth, "ipfs://QmHash").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("IPFS provider not implemented"));
    }

    #[tokio::test]
    async fn test_ipfs_provider_size_and_mtime() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.size_and_mtime(&auth, "ipfs://QmHash").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("IPFS size_and_mtime not implemented"));
    }

    #[tokio::test]
    async fn test_ipfs_provider_save() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession { access_token: "test_token".to_string() };
        
        let result = provider.save(&auth, "ipfs://QmHash", b"test data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("IPFS save not implemented"));
    }
}
