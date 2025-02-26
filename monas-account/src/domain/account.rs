use crate::infrastructure::key_pair::KeyPair;

#[derive(Clone)]
pub struct Account {
    key_pair: KeyPair,
    deleted: bool,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum AccountError {
    AccountAlreadyDeleted,
}

impl Account {
    pub fn init(key_pair: &KeyPair) -> Self {
        Account {
            key_pair: key_pair.clone(),
            deleted: false,
        }
    }

    pub fn regenerate_keypair(&mut self, key_pair: KeyPair) -> Result<(), AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
        self.key_pair = key_pair;
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

#[cfg(test)]
mod account_tests {
    use super::*;
    use crate::infrastructure::key_pair::KeyType::K256;

    #[test]
    fn regenerate_key_pair() {
        let mut account = Account::init(&KeyPair::generate(K256));

        let key_pair_before = match &account.key_pair {
            KeyPair::K256KeyPair(k256) => k256.secret_key(),
            _ => panic!("unexpected public key detected"),
        }
        .clone();

        account.regenerate_keypair(KeyPair::generate(K256)).unwrap();

        let key_pair_after = match &account.key_pair {
            KeyPair::K256KeyPair(k256) => k256.secret_key(),
            _ => panic!("unexpected public key detected"),
        };

        assert!(!key_pair_before.eq(key_pair_after));

        assert_eq!(account.is_deleted(), false);
    }

    #[test]
    fn throw_error_regenerate_key_pair_when_account_was_deleted() {
        let mut account = Account::init(&KeyPair::generate(K256));

        account.delete().unwrap();
        assert!(account.is_deleted());
        assert_eq!(
            account.regenerate_keypair(KeyPair::generate(K256)),
            Err(AccountError::AccountAlreadyDeleted)
        );
    }

    #[test]
    fn delete_account() {
        let mut account = Account::init(&KeyPair::generate(K256));
        account.delete().unwrap();
        assert!(account.is_deleted());
    }
}
