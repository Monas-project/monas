pub mod k256_key_pair;
pub mod p256_key_pair;

use crate::domain::account::AccountKeyPair;
use crate::infrastructure::key_pair::k256_key_pair::K256KeyPair;
use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;
use std::fmt::Debug;

#[derive(Clone, PartialEq)]
pub enum KeyPair {
    K256KeyPair(K256KeyPair),
    P256KeyPair(P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyAlgorithm {
    K256,
    P256,
}

pub struct KeyPairGenerateFactory;

impl KeyPairGenerateFactory {
    pub fn generate(key_type: KeyAlgorithm) -> Box<dyn AccountKeyPair> {
        match key_type {
            KeyAlgorithm::K256 => Box::new(K256KeyPair::generate()),
            KeyAlgorithm::P256 => Box::new(P256KeyPair::generate()),
        }
    }

    /// 永続化された鍵バイト列から鍵ペアを復元する。
    pub fn from_key_bytes(
        key_type: KeyAlgorithm,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> Result<Box<dyn AccountKeyPair>, KeyPairError> {
        match key_type {
            KeyAlgorithm::K256 => Ok(Box::new(K256KeyPair::from_key_bytes(
                public_key, secret_key,
            )?)),
            KeyAlgorithm::P256 => Ok(Box::new(P256KeyPair::from_key_bytes(
                public_key, secret_key,
            )?)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyPairError {
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),
}

#[cfg(test)]
mod key_pair_tests {
    use crate::infrastructure::key_pair::{KeyAlgorithm, KeyPairGenerateFactory};

    #[test]
    fn key_pair_k256_generate_test() {
        let k256 = KeyPairGenerateFactory::generate(KeyAlgorithm::K256);
        assert_eq!(k256.public_key_bytes().len(), 65);
        assert_eq!(k256.secret_key_bytes().len(), 32);
    }

    #[test]
    fn key_pair_p256_generate_test() {
        let p256 = KeyPairGenerateFactory::generate(KeyAlgorithm::P256);
        assert_eq!(p256.public_key_bytes().len(), 65);
        assert_eq!(p256.secret_key_bytes().len(), 32);
    }
}
