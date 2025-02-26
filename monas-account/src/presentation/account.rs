use crate::application_service::account_service::{
    AccountService, AccountServiceError, KeyTypeMapper,
};
use crate::domain::account::Account;

pub struct ReqParam {
    pub key_type: KeyTypeMapper,
    pub username: Option<String>,
}

pub fn create(req: ReqParam) -> Result<Account, AccountServiceError> {
    Ok(AccountService::create(req.key_type)?)
}
