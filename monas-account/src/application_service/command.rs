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

/// Request to issue a membership proof: an owner-signed token attesting that a
/// specific state node (`member_node_id`) is a legitimate member/host of a
/// content. Used by the verified read path so a responding node can prove it is
/// a real member without exposing the member list
/// (`docs/design/read-response-integrity.md` §5.1.b).
#[derive(Debug, Clone)]
pub struct IssueMemberProofRequest {
    /// Identity of the member state node this proof is issued to (the token's
    /// `aud`). This is the node's self-identifier (e.g. `node:<node_id>`).
    pub member_node_id: String,
    pub content_id: String,
    pub ttl_secs: u64,
}
