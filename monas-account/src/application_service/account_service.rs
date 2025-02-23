use crate::domain::account::Account;
use crate::infrastructure::key_pair::{KeyPair, KeyType};

struct AccountService;

impl AccountService {
    pub fn create(key_type: KeyType) -> Account {
        Account::init(KeyPair::generate(key_type))
    }
}

#[cfg(test)]
mod account_application_tests {
    use crate::application_service::account_service::AccountService;
    use crate::infrastructure::key_pair::{KeyPair, KeyType};

    #[test]
    fn create_account() {
        let account = AccountService::create(KeyType::K256);

        let is_created_key_type =
            match &account.keypair() {
                KeyPair::K256KeyPair(_) => true,
                _ => false,
            }.clone();
        assert_eq!(is_created_key_type, true);
        assert_eq!(account.is_deleted(), false);
    }
}