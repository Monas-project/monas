use crate::domain::delegation::DelegatedCapability;
use crate::infrastructure::key_pair::KeyAlgorithm;

pub enum KeyTypeMapper {
    K256,
    P256,
}

impl From<KeyTypeMapper> for KeyAlgorithm {
    fn from(mapper: KeyTypeMapper) -> Self {
        match mapper {
            KeyTypeMapper::K256 => KeyAlgorithm::K256,
            KeyTypeMapper::P256 => KeyAlgorithm::P256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssueDelegatedTokenRequest {
    pub recipient_public_key: Vec<u8>,
    pub content_id: String,
    pub capabilities: Vec<DelegatedCapability>,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone)]
pub struct IssueDelegatedTokenResult {
    pub delegated_token: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub jti: String,
}
