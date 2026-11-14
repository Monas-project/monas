pub struct Account {
    key_pair: Box<dyn AccountKeyPair>,
}

/// Simple domain model assuming account = key pair.
/// Persistence and deletion (removing the key from storage) are the infrastructure layer's
/// responsibility; the domain focuses on "being able to sign" and "access to key material".
impl Account {
    /// Builds an account from an already generated key pair.
    pub fn new(key_pair: Box<dyn AccountKeyPair>) -> Self {
        Account { key_pair }
    }

    /// Signs a message.
    pub fn sign(&self, msg: &[u8]) -> (Vec<u8>, Option<u8>) {
        self.key_pair.sign(msg)
    }

    /// Access to the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key_bytes()
    }

    /// Access to the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.key_pair.secret_key_bytes()
    }
}

pub trait AccountKeyPair: Send + Sync {
    fn sign(&self, msg: &[u8]) -> (Vec<u8>, Option<u8>);
    fn public_key_bytes(&self) -> &[u8];

    fn secret_key_bytes(&self) -> &[u8];
}

#[cfg(test)]
mod account_tests {
    use super::*;
    use crate::infrastructure::key_pair::KeyAlgorithm::K256;
    use crate::infrastructure::key_pair::KeyPairGenerateFactory;

    #[test]
    fn create_account_and_use_key_material() {
        let account = Account::new(KeyPairGenerateFactory::generate(K256));

        // Check that the public and secret key sizes are as expected
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);

        // Check that a signature can be generated successfully
        let message = b"test message";
        let (sig, _rec_id) = account.sign(message);
        assert!(!sig.is_empty());
    }
}
