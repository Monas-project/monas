use std::sync::Arc;
use axum::Router;
use crate::infrastructure::key_store::InMemoryAccountKeyStore;

pub mod account;

#[derive(Clone)]
pub struct AppState {
    pub key_store: InMemoryAccountKeyStore,
}

pub fn create_router() -> Router {
    let state = Arc::new(AppState {
        key_store: InMemoryAccountKeyStore::default(),
    });

    Router::new()
        .merge(account::routes())
        .with_state(state)
}
