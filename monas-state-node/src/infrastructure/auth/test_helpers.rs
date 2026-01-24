//! Test helpers for authentication and authorization testing.
//!
//! This module provides utilities for generating test keys, signing tokens,
//! and managing test public keys. These utilities are only available in test builds.

#[cfg(test)]
use super::share_token::*;
#[cfg(test)]
use p256::ecdsa::{signature::Signer, SigningKey};
#[cfg(test)]
use p256::SecretKey;
#[cfg(test)]
use rand::rngs::OsRng;
#[cfg(test)]
use std::collections::HashMap;

/// Test key pair for P256/ES256 signing
#[cfg(test)]
pub struct TestKeyPair {
    secret_key: SigningKey,
    public_key_bytes: Vec<u8>,
    key_id: String,
}

#[cfg(test)]
impl TestKeyPair {
    /// Generate a new P256 key pair for testing
    ///
    /// # Arguments
    /// * `identity_type` - The type of identity ("user", "node", "service")
    /// * `name` - The name/identifier for this identity
    ///
    /// # Returns
    /// A new TestKeyPair with key ID format: "monas:type:name" (e.g., "monas:user:alice")
    pub fn generate(identity_type: &str, name: &str) -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret);
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key (65 bytes: 0x04 + X + Y)
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let key_id = format!("monas:{}:{}", identity_type, name);

        Self {
            secret_key: signing_key,
            public_key_bytes,
            key_id,
        }
    }

    /// Get the key ID for this key pair
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the public key bytes (uncompressed format, 65 bytes)
    pub fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Sign a message with this key pair
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The signature bytes
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: p256::ecdsa::Signature = self.secret_key.sign(message);
        signature.to_vec()
    }

    /// Create a ShareToken signed by this key pair
    ///
    /// # Arguments
    /// * `recipient` - The recipient key pair (for aud field)
    /// * `resource` - The resource URI (e.g., "monas://content/abc123")
    /// * `capabilities` - List of capabilities to grant
    /// * `expires_in_secs` - Optional expiration time in seconds from now
    ///
    /// # Returns
    /// A signed ShareToken
    pub fn create_share_token(
        &self,
        recipient: &TestKeyPair,
        resource: &str,
        capabilities: Vec<CapabilityAction>,
        expires_in_secs: Option<u64>,
    ) -> ShareToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = ShareTokenHeader::default();

        let payload = ShareTokenPayload {
            iss: self.key_id.clone(),
            aud: recipient.key_id.clone(),
            exp: expires_in_secs.map(|s| now + s),
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            att: capabilities
                .iter()
                .map(|cap| Capability {
                    with: resource.to_string(),
                    can: cap.clone(),
                })
                .collect(),
            fct: None,
        };

        // Create token without signature first
        let mut token = ShareToken {
            header,
            payload,
            signature: Vec::new(),
        };

        // Sign the token
        let message = token.signing_message().unwrap();
        token.signature = self.sign(&message);

        token
    }

    /// Sign a request using this key pair
    ///
    /// The request signature format is: "{iss}:{aud}:{jti}"
    ///
    /// # Arguments
    /// * `share_token` - The ShareToken being used for the request
    ///
    /// # Returns
    /// The request signature bytes
    pub fn sign_request(&self, share_token: &ShareToken) -> Vec<u8> {
        let message = format!(
            "{}:{}:{}",
            share_token.payload.iss, share_token.payload.aud, share_token.payload.jti
        );
        self.sign(message.as_bytes())
    }
}

/// Test public key repository for mocking account registry
#[cfg(test)]
pub struct TestPublicKeyRepository {
    keys: HashMap<String, Vec<u8>>,
}

#[cfg(test)]
impl TestPublicKeyRepository {
    /// Create a new empty test repository
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register a public key for a key ID
    ///
    /// # Arguments
    /// * `key_id` - The key ID to register (format: "monas:type:id")
    /// * `public_key` - The public key bytes (uncompressed format)
    pub fn register(&mut self, key_id: &str, public_key: Vec<u8>) {
        self.keys.insert(key_id.to_string(), public_key);
    }

    /// Get the public key for a key ID
    ///
    /// # Arguments
    /// * `key_id` - The key ID to look up
    ///
    /// # Returns
    /// The public key bytes if found, None otherwise
    pub fn get(&self, key_id: &str) -> Option<&Vec<u8>> {
        self.keys.get(key_id)
    }

    /// Check if a key ID is registered
    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Remove a key ID registration
    pub fn remove(&mut self, key_id: &str) -> Option<Vec<u8>> {
        self.keys.remove(key_id)
    }

    /// Get all registered key IDs
    pub fn all_key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
impl Default for TestPublicKeyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let alice = TestKeyPair::generate("user", "alice");
        assert_eq!(alice.key_id(), "monas:user:alice");
        assert_eq!(alice.public_key().len(), 65); // Uncompressed P256 key
        assert_eq!(alice.public_key()[0], 0x04); // Uncompressed format marker
    }

    #[test]
    fn test_sign_message() {
        let alice = TestKeyPair::generate("user", "alice");
        let message = b"test message";
        let signature = alice.sign(message);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_create_share_token() {
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        let token = alice.create_share_token(
            &bob,
            "monas://content/test123",
            vec![CapabilityAction::Read],
            Some(3600),
        );

        assert_eq!(token.payload.iss, "monas:user:alice");
        assert_eq!(token.payload.aud, "monas:user:bob");
        assert_eq!(token.payload.att.len(), 1);
        assert_eq!(token.payload.att[0].with, "monas://content/test123");
        assert_eq!(token.payload.att[0].can, CapabilityAction::Read);
        assert!(token.payload.exp.is_some());
        assert!(!token.signature.is_empty());
    }

    #[test]
    fn test_sign_request() {
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        let token = alice.create_share_token(
            &bob,
            "monas://content/test123",
            vec![CapabilityAction::Read],
            None,
        );

        let request_sig = bob.sign_request(&token);
        assert!(!request_sig.is_empty());
    }

    #[test]
    fn test_public_key_repository() {
        let mut repo = TestPublicKeyRepository::new();
        let alice = TestKeyPair::generate("user", "alice");

        assert!(!repo.contains(alice.key_id()));

        repo.register(alice.key_id(), alice.public_key().to_vec());
        assert!(repo.contains(alice.key_id()));

        let retrieved = repo.get(alice.key_id()).unwrap();
        assert_eq!(retrieved, alice.public_key());

        let all_key_ids = repo.all_key_ids();
        assert_eq!(all_key_ids.len(), 1);
        assert!(all_key_ids.contains(&alice.key_id()));

        repo.remove(alice.key_id());
        assert!(!repo.contains(alice.key_id()));
    }

    #[test]
    fn test_verify_token_signature() {
        use super::super::signature_verifier::SignatureVerifier;

        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        let token = alice.create_share_token(
            &bob,
            "monas://content/test123",
            vec![CapabilityAction::Read],
            None,
        );

        // Verify the signature
        let result =
            SignatureVerifier::verify_share_token_signature(&token, alice.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_capabilities() {
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        let token = alice.create_share_token(
            &bob,
            "monas://content/test123",
            vec![
                CapabilityAction::Read,
                CapabilityAction::Write,
                CapabilityAction::Share,
            ],
            Some(7200),
        );

        assert_eq!(token.payload.att.len(), 3);
        assert!(token
            .payload
            .att
            .iter()
            .any(|c| c.can == CapabilityAction::Read));
        assert!(token
            .payload
            .att
            .iter()
            .any(|c| c.can == CapabilityAction::Write));
        assert!(token
            .payload
            .att
            .iter()
            .any(|c| c.can == CapabilityAction::Share));
    }
}
