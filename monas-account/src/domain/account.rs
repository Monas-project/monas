use std::fmt::Debug;
use std::ops::Deref;

pub struct Account {
    key_pair: Box<dyn AccountKeyPair>,
    deleted: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AccountError {
    AccountAlreadyDeleted,
}

impl Account {
    pub fn init(key_pair: Box<dyn AccountKeyPair>) -> Self {
        Account {
            key_pair,
            deleted: false,
        }
    }

    pub fn regenerate_keypair(
        &self,
        key_pair: Box<dyn AccountKeyPair>,
    ) -> Result<Account, AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
        Ok(Self::init(key_pair))
    }

    //ContentNodeに通達する
    pub fn delete(&mut self) -> Result<(), AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
        self.deleted = true;
        Ok(())
    }

    pub fn keypair(&self) -> &dyn AccountKeyPair {
        self.key_pair.deref()
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
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
    fn regenerate_key_pair() {
        let account = Account::init(KeyPairGenerateFactory::generate(K256));

        let key_pair_before = account.key_pair.public_key_bytes();

        account
            .regenerate_keypair(KeyPairGenerateFactory::generate(K256))
            .unwrap();

        let key_pair_after = account.key_pair.public_key_bytes();

        assert!(!key_pair_before.eq(key_pair_after));

        assert!(!account.is_deleted());
    }

    #[test]
    fn throw_error_regenerate_key_pair_when_account_was_deleted() {
        let mut account = Account::init(KeyPairGenerateFactory::generate(K256));

        account.delete().unwrap();
        assert!(account.is_deleted());
        let result = account.regenerate_keypair(KeyPairGenerateFactory::generate(K256));
        matches!(result, Err(AccountError::AccountAlreadyDeleted));
    }

    #[test]
    fn delete_account() {
        let mut account = Account::init(KeyPairGenerateFactory::generate(K256));
        account.delete().unwrap();
        assert!(account.is_deleted());
    }
}
