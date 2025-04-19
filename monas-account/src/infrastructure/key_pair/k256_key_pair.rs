use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use k256::{EncodedPoint, FieldBytes};
use k256::ecdsa::signature::DigestSigner;
use k256::sha2::Digest;
use p256::ecdsa::Signature;
use sha3::Keccak256;
use crate::domain::account::AccountKeyPair;

#[derive(Clone)]
pub struct K256KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
    public_key_point: EncodedPoint,
    secret_key_field_key: FieldBytes,
}

impl K256KeyPair {
    pub fn generate() -> K256KeyPair {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        let public_key_point = public_key.to_encoded_point(false);
        let secret_key_field_key = secret_key.to_bytes();
        K256KeyPair {
            secret_key,
            public_key,
            public_key_point,
            secret_key_field_key
        }
    }
}

impl PartialEq for K256KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}

impl AccountKeyPair for K256KeyPair {
    fn sign(&self, message: &[u8]) -> (Vec<u8>, Option<u8>) {
        self.secret_key
            .sign_digest(Keccak256::new_with_prefix(message));
    }

    fn public_key_bytes(&self) -> &[u8] {
        self.public_key_point.as_bytes()
    }

    fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key_field_key.as_ref()
    }
}

#[cfg(test)]
mod k256_key_pair_tests {
    use k256::ecdsa::signature::DigestVerifier;
    use k256::ecdsa::VerifyingKey;
    use sha3::{Digest, Keccak256};
    use crate::domain::account::AccountKeyPair;
    use crate::infrastructure::key_pair::k256_key_pair::K256KeyPair;
    use crate::infrastructure::key_pair::KeyPair::K256KeyPair;

    #[test]
    fn generate_has_valid_sizes() {
        let kp = K256KeyPair::generate();

        assert_eq!(kp.public_key_bytes().len(), 65);
        assert_eq!(kp.secret_key_bytes().len(), 32);
    }

    #[test]
    fn sign_and_verify() {
        let k256 = K256KeyPair::generate();
        let message = b"test message";

        let (signature, _) = k256.sign(message);

        // Change to k256::VerifyingKey
        let verify_key = VerifyingKey::from_sec1_bytes(k256.public_key_bytes()).unwrap();
        verify_key
            .verify_digest(Keccak256::new_with_prefix(message), &signature)
            .unwrap();
    }

    #[test]
    fn different_message_gives_different_signature() {
        let kp = K256KeyPair::generate();
        let (sig1, _) = kp.sign(b"same");
        let (sig2, _) = kp.sign(b"different");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn same_message_gives_same_signature() {
        let kp = K256KeyPair::generate();
        let (sig1, _) = kp.sign(b"same");
        let (sig2, _) = kp.sign(b"same");
        assert_eq!(sig1, sig2);
    }
}