use secret::key_pair::{KeyPair, KeyType};

mod secret;

#[derive(Clone)]
pub struct Account {
    keypair: KeyPair,
    deleted: bool,
}

pub enum AccountError {
    AccountAlreadyDeleted,
}


impl Account {
    pub fn create(&mut self, key_type: KeyType) -> Account {
        let keypair = KeyPair::generate(key_type);
        Account {
            keypair,
            deleted: false,
        }
    }

    pub fn regenerate_keypair(&mut self, key_type: KeyType) -> Result<(), AccountError> {
        if self.deleted {
            return Err(AccountError::AccountAlreadyDeleted);
        }
        self.keypair = KeyPair::generate(key_type);
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
        &self.keypair
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}