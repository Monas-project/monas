//! Thin async wrappers for safely calling the sync API of `MonasController` on a
//! tokio runtime.
//!
//! Background:
//! `MonasController` uses `ureq` (sync HTTP) internally, so its methods are sync.
//! Calling them directly from an axum (tokio) handler blocks a tokio worker thread for the
//! whole HTTP round trip, so concurrent requests hit the tokio worker count + queue directly.
//!
//! This module provides an `_async` variant for each public sync method, which runs the
//! sync variant on the blocking pool via `tokio::task::spawn_blocking`.
//! As long as callers (the gateway) use only this async API, ureq's sync I/O does not
//! block tokio workers.
//!
//! The sync API can still be called directly, but always use the async wrappers when
//! calling from a tokio runtime.

use std::sync::Arc;

use crate::common::{ApiError, ApiResponse, StateNodeAuthContext};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};
use crate::models::keypair::{
    CreateSigningAccountOutput, GenerateKeypairInput, GenerateKeypairOutput,
};
use crate::models::share::{
    DecryptSharedContentInput, DecryptSharedContentOutput, RevokeShareInput, RevokeShareOutput,
    ShareContentInput, ShareContentOutput, UpdateSharePermissionInput, UpdateSharePermissionOutput,
    UpdateSharedContentInput, UpdateSharedContentOutput,
};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    PullContentFromStateNodeInput, PullContentFromStateNodeOutput, ReadContentFromStateNodeInput,
    ReadContentFromStateNodeOutput, VerifyIntegrityInput, VerifyIntegrityOutput,
};

use super::MonasController;

/// Helper that builds the error returned to the caller when `spawn_blocking` panics.
fn map_join_error<T>(err: tokio::task::JoinError, trace_id: String) -> ApiResponse<T> {
    let msg = if err.is_panic() {
        "blocking task panicked".to_string()
    } else if err.is_cancelled() {
        "blocking task was cancelled".to_string()
    } else {
        format!("blocking task failed: {err}")
    };
    ApiResponse::error(ApiError::Internal(msg), trace_id)
}

/// Creates a dummy id borrowing the `generate_trace_id` prefix, so the internal trace_id stays
/// consistent on the `JoinError` path too.
fn fallback_trace_id() -> String {
    crate::common::generate_trace_id()
}

impl MonasController {
    /// Async variant of `create_content`. Calls the sync variant via `spawn_blocking`.
    pub async fn create_content_async(
        self: Arc<Self>,
        input: CreateContentInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<CreateContentOutput> {
        match tokio::task::spawn_blocking(move || self.create_content(input, auth.as_ref())).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `get_content`.
    pub async fn get_content_async(
        self: Arc<Self>,
        input: GetContentInput,
    ) -> ApiResponse<GetContentOutput> {
        match tokio::task::spawn_blocking(move || self.get_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `update_content`.
    pub async fn update_content_async(
        self: Arc<Self>,
        input: UpdateContentInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<UpdateContentOutput> {
        match tokio::task::spawn_blocking(move || self.update_content(input, auth.as_ref())).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `delete_content`.
    pub async fn delete_content_async(
        self: Arc<Self>,
        input: DeleteContentInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<DeleteContentOutput> {
        match tokio::task::spawn_blocking(move || self.delete_content(input, auth.as_ref())).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `share_content`.
    pub async fn share_content_async(
        self: Arc<Self>,
        input: ShareContentInput,
    ) -> ApiResponse<ShareContentOutput> {
        match tokio::task::spawn_blocking(move || self.share_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `revoke_share`.
    pub async fn revoke_share_async(
        self: Arc<Self>,
        input: RevokeShareInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<RevokeShareOutput> {
        match tokio::task::spawn_blocking(move || self.revoke_share(input, auth.as_ref())).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `update_share_permission`.
    pub async fn update_share_permission_async(
        self: Arc<Self>,
        input: UpdateSharePermissionInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<UpdateSharePermissionOutput> {
        match tokio::task::spawn_blocking(move || {
            self.update_share_permission(input, auth.as_ref())
        })
        .await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `decrypt_shared_content`.
    pub async fn decrypt_shared_content_async(
        self: Arc<Self>,
        input: DecryptSharedContentInput,
    ) -> ApiResponse<DecryptSharedContentOutput> {
        match tokio::task::spawn_blocking(move || self.decrypt_shared_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `pull_content_from_state_node`.
    pub async fn pull_content_from_state_node_async(
        self: Arc<Self>,
        input: PullContentFromStateNodeInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<PullContentFromStateNodeOutput> {
        match tokio::task::spawn_blocking(move || {
            self.pull_content_from_state_node(input, auth.as_ref())
        })
        .await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `update_shared_content`.
    pub async fn update_shared_content_async(
        self: Arc<Self>,
        input: UpdateSharedContentInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<UpdateSharedContentOutput> {
        match tokio::task::spawn_blocking(move || self.update_shared_content(input, auth.as_ref()))
            .await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `create_signing_account`.
    pub async fn create_signing_account_async(
        self: Arc<Self>,
    ) -> ApiResponse<CreateSigningAccountOutput> {
        match tokio::task::spawn_blocking(move || self.create_signing_account()).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `generate_keypair`.
    /// (It does not call HTTP, but is wrapped the same way to move CPU-bound key generation off
    /// the tokio workers.)
    pub async fn generate_keypair_async(
        self: Arc<Self>,
        input: GenerateKeypairInput,
    ) -> ApiResponse<GenerateKeypairOutput> {
        match tokio::task::spawn_blocking(move || self.generate_keypair(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `get_latest_version`.
    pub async fn get_latest_version_async(
        self: Arc<Self>,
        input: GetLatestVersionInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<GetLatestVersionOutput> {
        match tokio::task::spawn_blocking(move || self.get_latest_version(input, auth.as_ref()))
            .await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `get_history`.
    pub async fn get_history_async(
        self: Arc<Self>,
        input: GetHistoryInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<GetHistoryOutput> {
        match tokio::task::spawn_blocking(move || self.get_history(input, auth.as_ref())).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `read_content_from_state_node`.
    pub async fn read_content_from_state_node_async(
        self: Arc<Self>,
        input: ReadContentFromStateNodeInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<ReadContentFromStateNodeOutput> {
        match tokio::task::spawn_blocking(move || {
            self.read_content_from_state_node(input, auth.as_ref())
        })
        .await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// Async variant of `verify_integrity`.
    pub async fn verify_integrity_async(
        self: Arc<Self>,
        input: VerifyIntegrityInput,
        auth: Option<StateNodeAuthContext>,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        match tokio::task::spawn_blocking(move || self.verify_integrity(input, auth.as_ref())).await
        {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }
}
