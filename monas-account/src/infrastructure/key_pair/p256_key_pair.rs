use crate::domain::account::AccountKeyPair;
use p256::ecdsa::signature::digest::Digest;
use p256::ecdsa::signature::DigestSigner;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, FieldBytes};
use sha3::Keccak256;

#[derive(Clone)]
pub struct P256KeyPair {
    secret_key: SigningKey,
    public_key_point: EncodedPoint,
    secret_key_field_key: FieldBytes,
}

impl P256KeyPair {
    pub fn generate() -> Self {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        let public_key_point = public_key.to_encoded_point(false);
        let secret_key_field_key = secret_key.to_bytes();
        Self {
            secret_key,
            public_key_point,
            secret_key_field_key,
        }
    }
}

impl AccountKeyPair for P256KeyPair {
    fn public_key_bytes(&self) -> &[u8] {
        self.public_key_point.as_bytes()
    }

    fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key_field_key.as_ref()
    }

    fn sign(&self, message: &[u8]) -> (Vec<u8>, Option<u8>) {
        let (signature, _) = self
            .secret_key
            .sign_digest(Keccak256::new_with_prefix(message));
        (signature.to_vec(), None)
    }
}

impl PartialEq for P256KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}

#[cfg(test)]
mod p256_key_pair_tests {
    use crate::domain::account::AccountKeyPair;
    use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;
    use k256::ecdsa::{Signature, VerifyingKey};
    use p256::ecdsa::signature::DigestVerifier;
    use sha3::{Digest, Keccak256};

    #[test]
    fn generate_has_valid_sizes() {
        let kp = P256KeyPair::generate();

        assert_eq!(kp.public_key_bytes().len(), 65);
        assert_eq!(kp.secret_key_bytes().len(), 32);
    }

    #[test]
    fn sign_and_verify() {
        let p256 = P256KeyPair::generate();
        let message = b"test message";

        let (sig_bytes, _rec_id) = p256.sign(message);

        let signature =
            Signature::from_slice(sig_bytes.as_slice()).expect("invalid signature bytes");

        let verifying_key = VerifyingKey::from_sec1_bytes(p256.public_key_bytes())
            .expect("invalid public key bytes");

        verifying_key
            .verify_digest(Keccak256::new_with_prefix(message), &signature)
            .expect("signature should verify");
    }

    #[test]
    fn different_message_gives_different_signature() {
        let p256 = P256KeyPair::generate();
        let (sig1, _) = p256.sign(b"same");
        let (sig2, _) = p256.sign(b"different");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn same_message_gives_same_signature() {
        let p256 = P256KeyPair::generate();
        let (sig1, _) = p256.sign(b"same");
        let (sig2, _) = p256.sign(b"same");
        assert_eq!(sig1, sig2);
    }
}
