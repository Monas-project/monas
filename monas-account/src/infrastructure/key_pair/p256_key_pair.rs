use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, FieldBytes};
use p256::ecdsa::signature::digest::Digest;
use p256::ecdsa::signature::DigestSigner;
use sha3::Keccak256;
use crate::domain::account::AccountKeyPair;

#[derive(Clone)]
pub struct P256KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
    public_key_point: EncodedPoint,
    secret_key_field_key: FieldBytes,
}

impl P256KeyPair {
    pub fn generate() -> Self {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        let public_key_point = public_key.to_encoded_point(false);
        let secret_key_field_key = secret_key.to_bytes();
        Self { secret_key, public_key, public_key_point, secret_key_field_key }
    }
}

impl AccountKeyPair for P256KeyPair {
    type Signature = Signature;
    type RecoveryId = ();

    fn public_key_bytes(&self) -> &[u8] {
        self.public_key_point.as_bytes()
    }

    fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key_field_key.as_ref()
    }

    fn sign(&self, message: &[u8]) -> (Self::Signature, Self::RecoveryId) {
        let sig = self
            .secret_key
            .sign_digest(Keccak256::new_with_prefix(message));
        (sig, ())
    }
}

impl PartialEq for P256KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}


#[cfg(test)]
mod p256_key_pair_tests {
    use k256::ecdsa::VerifyingKey;
    use sha3::{Digest, Keccak256};
    use p256::ecdsa::{signature::DigestVerifier};
    use crate::domain::account::AccountKeyPair;
    use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;

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

        let (signature, _) = p256.sign(message);

        // Change to p256::VerifyingKey
        let verify_key = VerifyingKey::from_sec1_bytes(p256.public_key_bytes()).unwrap();
        verify_key
            .verify_digest(Keccak256::new_with_prefix(message), &signature)
            .unwrap();
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