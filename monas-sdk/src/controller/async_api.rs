//! `MonasController` の sync API を tokio runtime 上で安全に呼び出すための
//! 薄い async ラッパー群。
//!
//! 背景:
//! `MonasController` は内部で `ureq` (sync HTTP) を使っており、メソッドは sync。
//! axum (tokio) ハンドラから直接呼ぶと、HTTP の往復中ずっと tokio worker thread が
//! ブロックされ、同時リクエスト数が tokio worker 数 + キューに直撃する。
//!
//! このモジュールは各 public sync メソッドに `_async` 版を提供し、
//! `tokio::task::spawn_blocking` 経由で sync 版を blocking pool に流す。
//! 呼び出し側 (gateway) はこちらの async API だけを使えば、ureq の sync I/O が
//! tokio worker をブロックしない。
//!
//! sync API は引き続き直接呼べるが、tokio runtime 上で呼ぶときは必ず
//! async ラッパー側を使うこと。

use std::sync::Arc;

use crate::common::{ApiError, ApiResponse, StateNodeAuthContext};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};
use crate::models::keypair::{GenerateKeypairInput, GenerateKeypairOutput};
use crate::models::share::{
    DecryptSharedContentInput, DecryptSharedContentOutput, RevokeShareInput, RevokeShareOutput,
    ShareContentInput, ShareContentOutput,
};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    VerifyIntegrityInput, VerifyIntegrityOutput,
};

use super::MonasController;

/// `spawn_blocking` 内で panic した場合に caller へ返すエラーを生成するヘルパ。
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

/// 内部の trace_id を `JoinError` 経路でも一貫させるため、
/// `generate_trace_id` の prefix を借用したダミー id を作る。
fn fallback_trace_id() -> String {
    crate::common::generate_trace_id()
}

impl MonasController {
    /// `create_content` の async 版。`spawn_blocking` 経由で sync 版を呼ぶ。
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

    /// `get_content` の async 版。
    pub async fn get_content_async(
        self: Arc<Self>,
        input: GetContentInput,
    ) -> ApiResponse<GetContentOutput> {
        match tokio::task::spawn_blocking(move || self.get_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// `update_content` の async 版。
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

    /// `delete_content` の async 版。
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

    /// `share_content` の async 版。
    pub async fn share_content_async(
        self: Arc<Self>,
        input: ShareContentInput,
    ) -> ApiResponse<ShareContentOutput> {
        match tokio::task::spawn_blocking(move || self.share_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// `revoke_share` の async 版。
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

    /// `decrypt_shared_content` の async 版。
    pub async fn decrypt_shared_content_async(
        self: Arc<Self>,
        input: DecryptSharedContentInput,
    ) -> ApiResponse<DecryptSharedContentOutput> {
        match tokio::task::spawn_blocking(move || self.decrypt_shared_content(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// `generate_keypair` の async 版。
    /// (HTTP は呼ばないが、CPU bound な鍵生成を tokio worker から外すため同様に wrap する。)
    pub async fn generate_keypair_async(
        self: Arc<Self>,
        input: GenerateKeypairInput,
    ) -> ApiResponse<GenerateKeypairOutput> {
        match tokio::task::spawn_blocking(move || self.generate_keypair(input)).await {
            Ok(resp) => resp,
            Err(e) => map_join_error(e, fallback_trace_id()),
        }
    }

    /// `get_latest_version` の async 版。
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

    /// `get_history` の async 版。
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

    /// `verify_integrity` の async 版。
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
