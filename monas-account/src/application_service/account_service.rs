use crate::domain::account::Account;
use crate::infrastructure::key_pair::{KeyAlgorithm, KeyPairGenerateFactory};

#[derive(Debug)]
pub enum AccountServiceError {
    PersistenceError(String),
}

pub struct AccountService;

pub enum KeyTypeMapper {
    K256,
    P256,
}

impl From<KeyTypeMapper> for KeyAlgorithm {
    fn from(mapper: KeyTypeMapper) -> Self {
        match mapper {
            KeyTypeMapper::K256 => KeyAlgorithm::K256,
            KeyTypeMapper::P256 => KeyAlgorithm::P256,
        }
    }
}

impl AccountService {
    pub fn create(key_type: KeyTypeMapper) -> Result<Account, AccountServiceError> {
        let generated_key_pair = KeyPairGenerateFactory::generate(key_type.into());
        Ok(Account::init(generated_key_pair))
    }
}

#[cfg(test)]
mod account_application_tests {
    use crate::application_service::account_service::{AccountService, KeyTypeMapper};
    use crate::infrastructure::key_pair::KeyAlgorithm::K256;
    use crate::infrastructure::key_pair::KeyPairGenerateFactory;

    #[test]
    fn create_account() {
        let account = AccountService::create(KeyTypeMapper::K256).unwrap();
        let expected = KeyPairGenerateFactory::generate(K256).public_key_bytes();

        let is_created_key_type = matches!(account.keypair().public_key_bytes(), expected);
        assert!(is_created_key_type);
        assert!(!account.is_deleted());
    }
}

#[cfg(test)]
mod key_type_mapper_tests {
    use crate::application_service::account_service::KeyTypeMapper;
    use crate::infrastructure::key_pair::KeyAlgorithm;

    #[test]
    fn to_p256_test() {
        let key_type: KeyAlgorithm = KeyAlgorithm::from(KeyTypeMapper::P256);
        assert_eq!(key_type, KeyAlgorithm::P256);
    }

    #[test]
    fn to_k256_test() {
        let key_type: KeyAlgorithm = KeyAlgorithm::from(KeyTypeMapper::K256);
        assert_eq!(key_type, KeyAlgorithm::K256);
    }
}
