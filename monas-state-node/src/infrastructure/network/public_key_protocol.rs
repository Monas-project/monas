//! RequestResponse protocol for node public key exchange.
//!
//! This protocol allows nodes to query each other for their P-256 public keys,
//! enabling proper verification of NodeId = hash(public_key).

use serde::{Deserialize, Serialize};

/// Request for a node's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRequest {
    /// The requesting node's ID (for logging/tracking).
    pub requesting_node: String,
    /// Optional: specific NodeIds to request (empty = request sender's key).
    pub requested_nodes: Vec<String>,
}

/// Response containing node public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    /// Map of NodeId -> P-256 public key (uncompressed, 65 bytes).
    pub public_keys: Vec<NodePublicKey>,
}

/// A node's public key with proof of ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePublicKey {
    /// The node's ID (should match hash of public_key).
    pub node_id: String,
    /// P-256 public key in uncompressed format (65 bytes).
    pub public_key: Vec<u8>,
    /// ECDSA signature of the node_id using the corresponding private key.
    /// This proves the node owns the private key for this public key.
    pub signature: Vec<u8>,
    /// Timestamp when this key was generated/signed.
    pub timestamp: u64,
}

impl NodePublicKey {
    /// Create a new NodePublicKey with signature proof.
    pub fn new(
        node_id: String,
        public_key: Vec<u8>,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Result<Self, anyhow::Error> {
        use p256::ecdsa::signature::Signer;

        // Create message: "node-key:<node_id>:<timestamp>"
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let message = format!("node-key:{}:{}", node_id, timestamp);

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());

        Ok(Self {
            node_id,
            public_key,
            signature: signature.to_der().as_bytes().to_vec(),
            timestamp,
        })
    }

    /// Verify the signature proves ownership of the public key.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        // Verify public key format
        if self.public_key.len() != 65 || self.public_key[0] != 0x04 {
            return Err(anyhow::anyhow!("Invalid P-256 uncompressed public key format"));
        }

        // Verify NodeId matches public key hash
        let expected_node_id = crate::domain::value_objects::NodeId::from_public_key(&self.public_key)?;
        if expected_node_id.as_str() != self.node_id {
            return Err(anyhow::anyhow!(
                "NodeId mismatch: expected {}, got {}",
                expected_node_id.as_str(),
                self.node_id
            ));
        }

        // Parse public key
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.public_key)?;

        // Recreate the message
        let message = format!("node-key:{}:{}", self.node_id, self.timestamp);

        // Parse and verify signature
        let signature = Signature::from_der(&self.signature)?;
        verifying_key.verify(message.as_bytes(), &signature)?;

        Ok(())
    }
}