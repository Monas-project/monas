use crate::application_service::port::AccountKeyStoreError;
use crate::infrastructure::jwt_signer::JwtSignerError;
use crate::infrastructure::key_pair::KeyPairError;

#[derive(Debug, thiserror::Error)]
pub enum AccountServiceError {
    #[error("persistence error: {0}")]
    PersistenceError(String),

    #[error("key store error: {0}")]
    KeyStore(#[from] AccountKeyStoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("stored account key not found")]
    NotFound,
    #[error("key-store error: {0}")]
    KeyStore(#[from] AccountKeyStoreError),
    #[error("invalid secret key: {0}")]
    InvalidKey(#[from] KeyPairError),
}

#[derive(Debug, thiserror::Error)]
pub enum IssueDelegatedTokenError {
    #[error("stored account key not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("unsupported key algorithm for delegated token issuing: {0}")]
    UnsupportedAlgorithm(String),
    #[error("key-store error: {0}")]
    KeyStore(#[from] AccountKeyStoreError),
    #[error("invalid key: {0}")]
    InvalidKey(#[from] KeyPairError),
    #[error("failed to create jwt: {0}")]
    JwtSigning(#[from] JwtSignerError),
    #[error("failed to get system time: {0}")]
    Time(String),
}
