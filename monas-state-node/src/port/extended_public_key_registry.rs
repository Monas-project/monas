//! Extended public key registry with key_id support.
//!
//! This trait extends PublicKeyRegistry to support key_id-based operations
//! needed for authentication with key IDs like "user:alice" or "node:node123".

use crate::port::public_key_registry::PublicKeyRegistry;
use anyhow::Result;
use async_trait::async_trait;

/// Extended registry for managing public keys with key_id support.
///
/// This trait extends the basic PublicKeyRegistry to support
/// key_id-based operations needed for authentication systems that
/// use key identifiers like "user:alice" or "service:indexer".
#[async_trait]
pub trait ExtendedPublicKeyRegistry: PublicKeyRegistry {
    /// Register a public key with a specific key_id.
    ///
    /// This allows registering keys with identifiers like "user:alice"
    /// or "service:indexer" for authentication purposes.
    async fn register_public_key_for_key_id(
        &self,
        key_id: String,
        public_key: Vec<u8>,
    ) -> Result<()>;

    /// Get a public key by its key_id.
    ///
    /// Retrieves the public key associated with a key identifier.
    /// Supports both direct lookup and "monas:" prefix fallback.
    async fn get_public_key_by_key_id(&self, key_id: &str) -> Result<Option<Vec<u8>>>;

    /// Remove a public key by its key_id.
    ///
    /// Removes the public key associated with a key identifier.
    async fn remove_public_key_by_key_id(&self, key_id: &str) -> Result<bool>;
}

/// Signature verification context for authentication.
///
/// This structure contains all the information needed to verify
/// a request signature, including the message, signature, and
/// metadata for replay attack prevention.
#[derive(Debug, Clone)]
pub struct SignatureContext {
    /// The operation being performed
    pub operation: String,
    /// The message that was signed
    pub message: String,
    /// The signature bytes
    pub signature: Vec<u8>,
    /// Unix timestamp (for replay attack prevention)
    pub timestamp: Option<u64>,
}

impl SignatureContext {
    /// Create a new signature context
    pub fn new(operation: String, message: String, signature: Vec<u8>) -> Self {
        Self {
            operation,
            message,
            signature,
            timestamp: None,
        }
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}
