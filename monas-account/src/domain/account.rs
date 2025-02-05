use secret::key_pair::{KeyPair, KeyType};
use crate::domain::account::secret::key_pair::k256_key_pair::K256KeyPair;
use crate::domain::account::secret::key_pair::p256_key_pair::P256KeyPair;

pub(crate) mod secret;

pub struct Account {
    key_pair: KeyPair,
    deleted: bool,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum AccountError {
    AccountAlreadyDeleted,
}


impl Account {

    pub fn regenerate_keypair(&mut self) -> Result<(), AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
       self.key_pair = self.key_pair.generate();
        Ok(())
    }

    pub fn delete(&mut self) -> Result<(), AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
        self.deleted = true;
        Ok(())
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.key_pair
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}

struct AccountFactory;

impl AccountFactory {
    pub fn create(key_type: KeyType) -> Account {
        let key_pair = match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(K256KeyPair::generate()),
            KeyType::P256 => KeyPair::P256KeyPair(P256KeyPair::generate())
        };
        Account {
            key_pair,
            deleted: false,
        }
    }
}

#[cfg(test)]
mod account_tests {
    use crate::domain::account::secret::key_pair::KeyType::K256;
    use super::*;
    #[test]
    fn create_account() {
        let account = AccountFactory::create(K256);
        let is_created_key_type =
            match &account.key_pair {
                KeyPair::K256KeyPair(k256) => true,
                _ => false,
            }.clone();
        assert_eq!(is_created_key_type, true);
        assert_eq!(account.is_deleted(), false);
    }

    #[test]
    fn regenerate_key_pair() {
        let mut account = AccountFactory::create(K256);

        let key_pair_before =
            match &account.key_pair {
                KeyPair::K256KeyPair(k256) => k256.secret_key(),
                _ => panic!("unexpected public key detected"),
            }.clone();

        account.regenerate_keypair().unwrap();

        let key_pair_after = match &account.key_pair {
            KeyPair::K256KeyPair(k256) => k256.secret_key(),
            _ => panic!("unexpected public key detected"),
        };

        assert!(!key_pair_before.eq(key_pair_after));

        assert_eq!(account.is_deleted(), false);
    }

    #[test]
    fn throw_error_regenerate_key_pair_when_account_was_deleted() {
        let mut account = AccountFactory::create(K256);
        account.delete().unwrap();
        assert!(account.is_deleted());
        assert_eq!(account.regenerate_keypair(), Err(AccountError::AccountAlreadyDeleted));
    }

    fn delete_account() {
        let mut account = AccountFactory::create(K256);
        account.delete().unwrap();
        assert!(account.is_deleted());
    }
}