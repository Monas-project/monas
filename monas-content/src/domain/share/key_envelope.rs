use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// CEK wrap information for a single recipient.
///
/// - Holds, per `key_id`, the HPKE-wrapped CEK and the `enc` produced during wrapping.
/// - The actual HPKE algorithm and parameters are delegated to the infra layer; this only handles
///   the resulting bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRecipientKey {
    key_id: KeyId,
    enc: Vec<u8>,
    wrapped_cek: Vec<u8>,
}

impl WrappedRecipientKey {
    pub fn new(key_id: KeyId, enc: Vec<u8>, wrapped_cek: Vec<u8>) -> Self {
        Self {
            key_id,
            enc,
            wrapped_cek,
        }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    pub fn wrapped_cek(&self) -> &[u8] {
        &self.wrapped_cek
    }
}

/// Algorithm indicating how the CEK was wrapped.
///
/// - Only HPKE is expected in this phase, but it is defined as an enum for future extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// CEK wrap via HPKE.
    HpkeV1,
}

/// An "envelope" for delivering a CEK.
///
/// - Bundles the `content_id` and `sender_key_id` at a point in time, the CEK wrap information for
///   one recipient, and the encrypted content body.
/// - Intended for use cases, such as local environments, where decryption should be completed from a
///   single package alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelope {
    content_id: ContentId,
    key_wrap_algorithm: KeyWrapAlgorithm,
    sender_key_id: KeyId,
    recipient: WrappedRecipientKey,
    ciphertext: Vec<u8>,
    /// CEK key epoch. Incremented by 1 on each rotation (re-encryption due to revoke).
    /// Bound to the wrap AAD so it cannot be tampered with; recipients reject envelopes older than
    /// the recorded epoch to prevent rollback (replay) to an old CEK.
    key_epoch: u64,
}

impl KeyEnvelope {
    pub fn new(
        content_id: ContentId,
        key_wrap_algorithm: KeyWrapAlgorithm,
        sender_key_id: KeyId,
        recipient: WrappedRecipientKey,
        ciphertext: Vec<u8>,
        key_epoch: u64,
    ) -> Self {
        Self {
            content_id,
            key_wrap_algorithm,
            sender_key_id,
            recipient,
            ciphertext,
            key_epoch,
        }
    }

    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    pub fn key_wrap_algorithm(&self) -> &KeyWrapAlgorithm {
        &self.key_wrap_algorithm
    }

    pub fn sender_key_id(&self) -> &KeyId {
        &self.sender_key_id
    }

    pub fn recipient(&self) -> &WrappedRecipientKey {
        &self.recipient
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content_id::ContentId;

    fn cid() -> ContentId {
        ContentId::new("test-content-id".into())
    }

    fn key_id(bytes: &[u8]) -> KeyId {
        KeyId::new(bytes.to_vec())
    }

    #[test]
    fn new_creates_envelope_for_single_recipient() {
        let recipient = WrappedRecipientKey::new(key_id(&[4, 5, 6]), vec![0x01], vec![0x02]);
        let env = KeyEnvelope::new(
            cid(),
            KeyWrapAlgorithm::HpkeV1,
            key_id(&[1, 2, 3]),
            recipient,
            vec![0xAA, 0xBB],
            3,
        );

        assert!(matches!(env.key_wrap_algorithm(), KeyWrapAlgorithm::HpkeV1));
        assert_eq!(env.recipient().key_id().as_bytes(), &[4, 5, 6]);
        assert_eq!(env.ciphertext(), &[0xAA, 0xBB]);
        assert_eq!(env.key_epoch(), 3);
    }
}
