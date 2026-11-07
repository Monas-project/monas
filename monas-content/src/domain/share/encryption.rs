use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// Port for wrapping a CEK with a recipient's public key / unwrapping it with a private key
/// (HPKE, etc.).
///
/// - The concrete HPKE algorithm is delegated to the infra-layer implementation.
/// - Resolving KeyId -> PublicKeyBytes / PrivateKeyBytes is left to the application layer or
///   another port; this port is responsible only for the pure cryptographic operation of
///   "generating / restoring (enc, wrapped_cek) from public / private key bytes and a CEK".
#[derive(Debug)]
pub enum KeyWrappingError {
    /// A cryptographic operation failed (wraps errors from hpke-rs, etc.).
    CryptoError(String),
    /// An input value (key, parameter, etc.) is invalid.
    InvalidInput(String),
    /// Other errors.
    Other(String),
}

/// Associated data (AAD) cryptographically bound to the CEK wrap.
///
/// Mixing `(content_id, recipient_key_id, key_epoch)` into the wrap computation makes it
/// impossible to tamper with "which content, which recipient, and which key epoch" an envelope's
/// wrap is for. An envelope with any of these fields rewritten fails to unwrap (decrypt) at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeAad<'a> {
    pub content_id: &'a ContentId,
    pub recipient_key_id: &'a KeyId,
    pub key_epoch: u64,
}

impl EnvelopeAad<'_> {
    /// Byte representation of the AAD. Fields are concatenated with length prefixes to
    /// eliminate concatenation ambiguity (shifting field boundaries).
    pub fn to_bytes(&self) -> Vec<u8> {
        let cid = self.content_id.as_str().as_bytes();
        let kid = self.recipient_key_id.as_bytes();
        let mut out = Vec::with_capacity(4 + cid.len() + 4 + kid.len() + 8);
        out.extend_from_slice(&(cid.len() as u32).to_be_bytes());
        out.extend_from_slice(cid);
        out.extend_from_slice(&(kid.len() as u32).to_be_bytes());
        out.extend_from_slice(kid);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out
    }
}

/// Port for wrapping a CEK with a recipient's public key and unwrapping it with a private key.
///
/// Wrapping must be sender-authenticated (equivalent to HPKE Auth mode):
/// the sender's private key is mixed into the wrap computation, and the recipient unwraps using
/// the sender's public key. If the sender is not genuine, unwrap (decryption) fails, so no
/// separate signature is needed.
pub trait KeyWrapping {
    /// Wraps a single CEK for the given recipient public key.
    ///
    /// - `cek`: the shared key used to encrypt the content body.
    /// - `recipient_public_key`: the recipient's public key bytes.
    /// - `sender_private_key`: the sender's private key bytes (used for sender authentication).
    /// - `aad`: associated data bound to the wrap (content ID, recipient key id, key epoch).
    ///
    /// The returned tuple is `(enc, wrapped_cek)`.
    fn wrap_cek(
        &self,
        cek: &ContentEncryptionKey,
        recipient_public_key: &[u8],
        sender_private_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyWrappingError>;

    /// Unwraps a single CEK using the given recipient private key.
    ///
    /// - `enc`: the HPKE sender's public value.
    /// - `wrapped_cek`: the HPKE-wrapped CEK bytes.
    /// - `recipient_private_key`: the recipient's private key bytes.
    /// - `sender_public_key`: the sender's public key bytes. A successful unwrap proves that
    ///   the envelope was created by the holder of this key.
    /// - `aad`: the same associated data used at wrap time. If it does not match, unwrap fails.
    fn unwrap_cek(
        &self,
        enc: &[u8],
        wrapped_cek: &[u8],
        recipient_private_key: &[u8],
        sender_public_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<ContentEncryptionKey, KeyWrappingError>;
}
