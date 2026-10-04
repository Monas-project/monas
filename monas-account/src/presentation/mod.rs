use crate::application_service::AccountService;
use crate::infrastructure::key_store::InMemoryAccountKeyStore;
use axum::Router;
use std::sync::Arc;

pub mod account;

#[derive(Clone)]
pub struct AppState {
    pub account_service: AccountService<InMemoryAccountKeyStore>,
}

pub fn create_router() -> Router {
    let state = Arc::new(AppState {
        account_service: AccountService {
            key_store: InMemoryAccountKeyStore::default(),
        },
    });

    Router::new().merge(account::routes()).with_state(state)
}
