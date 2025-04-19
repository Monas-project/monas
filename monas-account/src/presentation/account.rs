use crate::application_service::account_service::{
    AccountService, AccountServiceError, KeyTypeMapper,
};
use crate::domain::account::Account;

pub struct ReqArguments {
    pub generating_key_type: KeyTypeMapper,
}

pub struct Response {
    pub generated_key_pair: GeneratedKeyPair,
}

pub struct GeneratedKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl GeneratedKeyPair {
    pub fn new(
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    pub fn secret_key(&self) -> &[u8] {
        self.secret_key.as_slice()
    }
}

pub fn create(args: ReqArguments) -> Result<Response, AccountServiceError> {
    match AccountService::create(args.generating_key_type) {
        Ok(account) => Ok(to_response(account)),
        Err(e) => Err(e),
    }
}

fn to_response(account: Account) -> Response {
    let key_pair = account.keypair();
    let generated_key_pair = GeneratedKeyPair::new(
        Vec::from(key_pair.public_key_bytes()),
        Vec::from(key_pair.secret_key_bytes())
    );
    Response {
        generated_key_pair
    }
}

#[cfg(test)]
mod account_presentation_tests {
    use super::*;

    #[test]
    fn account_create_test() {
        let args = ReqArguments {
            generating_key_type: KeyTypeMapper::K256,
        };
        let result = create(args).unwrap();
        println!("{:?}", result.generated_key_pair.public_key);
        assert!(!result.generated_key_pair.public_key.is_empty());
    }
}
