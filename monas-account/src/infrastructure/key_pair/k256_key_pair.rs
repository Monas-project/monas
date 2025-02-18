use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;

#[derive(Clone)]
pub struct K256KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
}

impl K256KeyPair {
    pub fn secret_key(&self) -> &SigningKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    pub(crate) fn generate() -> K256KeyPair {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        K256KeyPair { secret_key, public_key }
    }
}

impl PartialEq for K256KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}