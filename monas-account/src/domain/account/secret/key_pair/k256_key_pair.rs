use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;

#[derive(Clone)]
pub struct K256KeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey
}

impl K256KeyPair {
    pub fn generate() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&private_key);
        K256KeyPair {
            private_key,
            public_key
        }
    }
}
