//! Recipient-side store of pinned sender public keys (TOFU).
//!
//! A share's KeyEnvelope is wrapped in HPKE Auth mode, and the recipient unwraps it with
//! "the expected sender public key" (success = proof that the holder of that key created it).
//! For each content, this store pins the sender public key of the first successful unwrap
//! (TOFU), and afterwards verifies envelopes only with the pinned key.
//!
//! It also records the CEK key generation (key_epoch) and **the CEK of that generation itself**.
//! Envelopes older than the recorded generation are rejected (prevents replay attacks that
//! resend an old envelope after a rotation to roll back the CEK).
//!
//! ## Why the CEK lives here
//!
//! The invariant to protect is "the triple of sender key, generation, and CEK is always
//! consistent", not just the generation number. If the triple is split across separate stores
//! and committed separately, it breaks under the following interleaving even if the
//! generation is protected by CAS:
//!
//! 1. The epoch N handler reads the pin (epoch N-1)
//! 2. The epoch N+1 handler advances the pin to N+1 and saves the new CEK
//! 3. The epoch N handler writes back only the CEK via a path such as "reprocessing the same
//!    generation"
//! 4. The result is `pin = N+1, CEK = N`, and subsequent decryption fails
//!
//! Putting the triple in one record and swapping it with a single compare-and-swap makes this
//! interleaving structurally impossible. The CEK store is treated as a cache derived from this
//! authoritative record (a failed write can be recovered by reprocessing).
//!
//! The key is the content id as seen by the recipient (local).

#[derive(Debug, thiserror::Error)]
pub enum SenderKeyPinStoreError {
    #[error("sender key pin store error: {0}")]
    Storage(String),
}

/// The pinned sender public key, and the latest key generation and CEK accepted from that sender.
///
/// These three are always swapped in the same commit. They must not be updated individually
/// (see the interleaving in the module doc).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyPin {
    /// Sender public key bytes (P-256 uncompressed form).
    pub sender_public_key: Vec<u8>,
    /// key_epoch of the last successfully unwrapped envelope.
    pub key_epoch: u64,
    /// CEK of generation `key_epoch`. Exists only locally on this device and never goes out to
    /// the network.
    ///
    /// `None` when read from an old record (a format without the CEK).
    /// In that case it is filled in by the next accepted envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cek: Option<Vec<u8>>,
}

/// Contains the CEK, so `Debug` does not print key material. This keeps the CEK from leaking
/// even if the record ends up in logs or panic messages.
impl std::fmt::Debug for SenderKeyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderKeyPin")
            .field("sender_public_key", &self.sender_public_key)
            .field("key_epoch", &self.key_epoch)
            .field(
                "cek",
                &self.cek.as_ref().map(|_| "<redacted>").unwrap_or("None"),
            )
            .finish()
    }
}

/// Persistence port for `content_id -> (sender public key, last accepted key_epoch, that epoch's CEK)`.
pub trait SenderKeyPinStore: Send + Sync {
    fn load(&self, content_id: &str) -> Result<Option<SenderKeyPin>, SenderKeyPinStoreError>;
    fn save(&self, content_id: &str, pin: &SenderKeyPin) -> Result<(), SenderKeyPinStoreError>;

    /// compare-and-advance: advances to `pin` only if the current value equals `expected`.
    /// Returns "whether it advanced".
    ///
    /// With concurrent envelope processing (e.g. epochs N / N+1 around a rotation running at the
    /// same time), an unconditional save based on "the pin as of load" would let an older epoch
    /// that completes later roll back the newer record. The triple is a single record, so once
    /// this CAS succeeds the sender key, generation, and CEK have all been swapped at once.
    fn compare_and_save(
        &self,
        content_id: &str,
        expected: Option<&SenderKeyPin>,
        pin: &SenderKeyPin,
    ) -> Result<bool, SenderKeyPinStoreError>;
}
