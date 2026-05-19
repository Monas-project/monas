use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedCapability {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationClaims {
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub att: Vec<DelegationCapabilityClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCapabilityClaim {
    pub with: String,
    pub can: String,
}
