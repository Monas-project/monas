use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;

#[derive(Clone)]
pub struct P256KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
}

impl P256KeyPair {
    pub fn secret_key(&self) -> &SigningKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    pub fn generate() -> P256KeyPair {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        P256KeyPair {
            secret_key,
            public_key,
        }
    }
}

impl PartialEq for P256KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}

#[cfg(test)]
mod p256_key_pair_tests {
    use p256::ecdsa::VerifyingKey;
    use crate::infrastructure::key_pair::{KeyPair, KeyType};

    #[test]
    fn key_pair_p256_generate_test() {
        let p256 = KeyPair::generate(KeyType::P256);
        use sha3::{Digest, Keccak256};
        let target = b"test signature target";

        match p256 {
            KeyPair::P256KeyPair(p256_key_pair) => {
                let digest = Keccak256::new_with_prefix(target);
                let (signature, recovery_id) = p256_key_pair
                    .secret_key
                    .sign_digest_recoverable(digest)
                    .unwrap();

                let recovered_key = VerifyingKey::recover_from_digest(
                    Keccak256::new_with_prefix(target),
                    &signature,
                    recovery_id,
                )
                    .unwrap();

                let encoded_point = p256_key_pair.public_key.to_owned().to_encoded_point(false);
                let expected_key_bytes = encoded_point.as_bytes();
                let expected_key = VerifyingKey::from_sec1_bytes(expected_key_bytes).unwrap();
                assert_eq!(recovered_key, expected_key);
            }
            _ => {
                panic!("not p256 key type");
            }
        }
    }
}