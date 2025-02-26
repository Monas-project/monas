use crate::application_service::account_service::{
    AccountService, AccountServiceError, KeyTypeMapper,
};
use crate::domain::account::Account;
use crate::infrastructure::key_pair::KeyPair;

pub struct ReqArguments {
    pub generating_key_type: KeyTypeMapper,
}

pub struct Response {
    generated_key_pair: GeneratedKeyPair,
}

pub struct GeneratedKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl GeneratedKeyPair {
    pub fn public_key(key_pair: &KeyPair) -> Vec<u8> {
        match key_pair {
            KeyPair::P256KeyPair(key_pair) => Vec::from(key_pair.public_key().to_sec1_bytes()),
            KeyPair::K256KeyPair(key_pair) => Vec::from(key_pair.public_key().to_sec1_bytes()),
        }
    }

    pub fn secret_key(key_pair: &KeyPair) -> Vec<u8> {
        //TODO
        String::from("please implement").into_bytes()
    }
}

fn to_response(account: Account) -> Response {
    let key_pair = account.keypair();
    Response {
        generated_key_pair: GeneratedKeyPair {
            public_key: GeneratedKeyPair::public_key(key_pair),
            secret_key: GeneratedKeyPair::secret_key(key_pair),
        },
    }
}

pub fn create(args: ReqArguments) -> Result<Response, AccountServiceError> {
    match AccountService::create(args.generating_key_type) {
        Ok(account) => Ok(to_response(account)),
        Err(e) => Err(e),
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
