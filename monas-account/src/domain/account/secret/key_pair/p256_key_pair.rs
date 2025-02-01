use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;

#[derive(Clone)]
pub struct P256KeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey
}

impl P256KeyPair {
    pub fn generate() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&private_key);
        P256KeyPair {
            private_key,
            public_key
        }
    }
}
