use crate::domain::account::Account;
use crate::infrastructure::key_pair::{KeyPair, KeyType};

#[derive(Debug)]
pub enum AccountServiceError {
    PersistenceError(String),
}

pub struct AccountService;

pub enum KeyTypeMapper {
    K256,
    P256,
}

impl From<KeyTypeMapper> for KeyType {
    fn from(mapper: KeyTypeMapper) -> Self {
        match mapper {
            KeyTypeMapper::K256 => KeyType::K256,
            KeyTypeMapper::P256 => KeyType::P256,
        }
    }
}

impl AccountService {
    pub fn create(key_type: KeyTypeMapper) -> Result<Account, AccountServiceError> {
        let generated_key_pair = KeyPair::generate(key_type.into());
        Ok(Account::init(&generated_key_pair))
    }
}

#[cfg(test)]
mod account_application_tests {
    use crate::application_service::account_service::{AccountService, KeyTypeMapper};
    use crate::infrastructure::key_pair::KeyPair;

    #[test]
    fn create_account() {
        let account = AccountService::create(KeyTypeMapper::K256).unwrap();

        let is_created_key_pair = matches!(account.keypair(), KeyPair::K256KeyPair(_));
        assert!(is_created_key_type);
        assert!(!account.is_deleted());
    }
}

#[cfg(test)]
mod key_type_mapper_tests {
    use crate::application_service::account_service::KeyTypeMapper;
    use crate::infrastructure::key_pair::KeyType;

    #[test]
    fn to_p256_test() {
        let key_type: KeyType = KeyType::from(KeyTypeMapper::P256);
        assert_eq!(key_type, KeyType::P256);
    }

    #[test]
    fn to_k256_test() {
        let key_type: KeyType = KeyType::from(KeyTypeMapper::K256);
        assert_eq!(key_type, KeyType::K256);
    }
}
