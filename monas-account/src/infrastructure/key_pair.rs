pub mod k256_key_pair;
pub mod p256_key_pair;

use std::fmt::Debug;
use crate::infrastructure::key_pair::k256_key_pair::K256KeyPair;
use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;

pub enum KeyPair {
    K256KeyPair(K256KeyPair),
    P256KeyPair(P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}


#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    K256,
    P256
}

impl KeyPair {
    pub fn generate(key_type: KeyType) -> KeyPair {
        match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(K256KeyPair::generate()),
            KeyType::P256 => KeyPair::P256KeyPair(P256KeyPair::generate())
        }
    }
}

#[cfg(test)]
mod key_pair_tests {
    use crate::infrastructure::key_pair::{KeyPair, KeyType};

    #[test]
    fn key_pair_k256_generate_test() {
        let k256 = KeyPair::generate(KeyType::K256);
        match k256 {
            KeyPair::K256KeyPair(k256_key_pair) => {
                assert!(k256_key_pair.public_key());
                assert!(k256_key_pair.secret_key());
            }
            _ => {
                panic!("not k256 key type");
            }
        }
    }
}
