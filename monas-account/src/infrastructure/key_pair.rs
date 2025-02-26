pub mod k256_key_pair;
pub mod p256_key_pair;

use crate::infrastructure::key_pair::k256_key_pair::K256KeyPair;
use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;
use std::fmt::Debug;

#[derive(Clone)]
pub enum KeyPair {
    K256KeyPair(K256KeyPair),
    P256KeyPair(P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    K256,
    P256,
}

impl KeyPair {
    pub fn generate(key_type: KeyType) -> KeyPair {
        match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(K256KeyPair::generate()),
            KeyType::P256 => KeyPair::P256KeyPair(P256KeyPair::generate()),
        }
    }
}

#[cfg(test)]
mod key_pair_tests {
    use crate::infrastructure::key_pair::{KeyPair, KeyType};

    #[test]
    fn key_pair_k256_generate_test() {
        let k256 = KeyPair::generate(KeyType::K256);
        assert!(matches!(k256, KeyPair::K256KeyPair(_)));
    }

    #[test]
    fn key_pair_p256_generate_test() {
        let p256 = KeyPair::generate(KeyType::P256);
        assert!(matches!(p256, KeyPair::P256KeyPair(_)));
    }
}
