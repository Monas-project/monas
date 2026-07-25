use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::{Digest, Sha256};

use crate::common::{
    encode_base64url, generate_trace_id, ApiError, ApiResponse, StateNodeAuthContext,
};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    ReadContentFromStateNodeInput, ReadContentFromStateNodeOutput, VerifyIntegrityInput,
    VerifyIntegrityOutput,
};
use crate::models::state_node::{StateNodeContentDataResponse, StateNodeContentHistoryResponse};

use super::MonasController;

/// read 単調性チェックの記録先
/// (`docs/design.md` §10「read応答の完全性検証」の単調性)。
pub(super) type DynLastSeenStore = std::sync::Arc<
    dyn monas_content::infrastructure::last_seen_version_store::LastSeenVersionStore,
>;

/// 単調性チェックの祖先探索で fetch する Node 数の上限。
///
/// 前回 read から `MAX_MONOTONICITY_FETCHES` 版を超えて履歴が進んでいた場合、
/// 探索は fail-closed で中断される(`AncestorWalkOutcome::BoundExceeded`)。
/// 攻撃者が偽の深い DAG を返してクライアントに際限なく fetch させる DoS を防ぐ。
const MAX_MONOTONICITY_FETCHES: usize = 256;

/// `walk_ancestors_for` の結果。
#[derive(Debug, PartialEq, Eq)]
enum AncestorWalkOutcome {
    /// `target` が祖先に見つかった = 今回の版は前回受理した版の子孫(単調)。
    FoundTarget,
    /// DAG を(bound 内で)出し尽くしたが `target` が祖先にいない
    /// = 後退(ロールバック/stale relay の固定)。
    Exhausted,
    /// fetch 上限に達した。fail-closed で拒否する。
    BoundExceeded,
}

/// 今回読んだ版の親 CID 群から祖先 DAG を辿り、`target`(前回受理した版)が
/// 祖先に含まれるかを判定する。
///
/// `fetch_parents(cid)` は「その CID の Node を取得し、**CID 再計算で検証した上で**
/// parents を返す」こと。検証済みの親のみを辿ることで、攻撃者が偽の親リンクで
/// `target` を「祖先に見せかける」ことはできない(偽 Node は CID が一致しない)。
fn walk_ancestors_for(
    start_parents: &[String],
    target: &str,
    max_fetches: usize,
    mut fetch_parents: impl FnMut(&str) -> Result<Vec<String>, String>,
) -> Result<AncestorWalkOutcome, String> {
    use std::collections::{HashSet, VecDeque};

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<String> = VecDeque::new();
    for p in start_parents {
        if visited.insert(p.clone()) {
            frontier.push_back(p.clone());
        }
    }

    let mut fetches = 0usize;
    while let Some(cid) = frontier.pop_front() {
        if cid == target {
            return Ok(AncestorWalkOutcome::FoundTarget);
        }
        if fetches >= max_fetches {
            return Ok(AncestorWalkOutcome::BoundExceeded);
        }
        fetches += 1;
        let parents = fetch_parents(&cid)?;
        for p in parents {
            if visited.insert(p.clone()) {
                frontier.push_back(p);
            }
        }
    }

    Ok(AncestorWalkOutcome::Exhausted)
}

impl MonasController {
    fn validate_state_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    /// State Node の読み取り API 用の認証コンテキストを解決する。
    ///
    /// 呼び出し元が Authorization を明示していればそのまま透過する。
    /// 無ければ書き込み系（create/update/delete）と同じく monas-account で
    /// `read:<content_id>:<timestamp>` に署名し、`user:<hex(pubkey)>` トークンを組み立てる。
    /// State Node 側は読み取り時にこの署名メッセージを検証する
    /// （`verify_read_access` → `verify_caller_signature("read", content_id, ..)`）。
    /// 署名を content_id にバインドすることで、relay 先ノード等に渡った署名を
    /// 他コンテンツの読み取りに再利用されることを防ぐ。
    fn resolve_state_read_auth<T>(
        &self,
        auth: Option<&StateNodeAuthContext>,
        content_id: &str,
        trace_id: &str,
    ) -> Result<Option<StateNodeAuthContext>, ApiResponse<T>> {
        match auth {
            Some(ctx) if ctx.authorization.is_none() => {
                self.prepare_state_node_metadata_auth(auth, "read", content_id, trace_id)
            }
            _ => Ok(auth.cloned()),
        }
    }

    fn state_node_get_string<T>(
        &self,
        url: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<(u16, String), ApiResponse<T>> {
        if let Some(ctx) = auth {
            self.resolve_request_timestamp::<T>(ctx, &trace_id)?;
        }

        let trace_id_for_call = trace_id.clone();
        let resp = Self::attach_state_node_auth(self.agent.get(url), auth)
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| {
                ApiResponse::error(
                    ApiError::from_ureq_error("Failed to call State Node", e),
                    trace_id_for_call,
                )
            })?;

        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                trace_id,
            )
        })?;

        Ok((status, body))
    }
    fn get_state_node_history<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentHistoryResponse, ApiResponse<T>> {
        let url = format!("{}/content/{}/history", self.state_node_url, content_id);

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentHistoryResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    fn get_state_node_version_data<T>(
        &self,
        content_id: &str,
        version: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentDataResponse, ApiResponse<T>> {
        let url = format!(
            "{}/content/{}/version/{}",
            self.state_node_url, content_id, version
        );

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentDataResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    /// コンテンツの最新バージョン（CID）を取得する。
    ///
    /// `auth` は State Node の `GET /content/:id/history` に転送する認証ヘッダ。本番では `Some` が必要。
    pub fn get_latest_version(
        &self,
        input: GetLatestVersionInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetLatestVersionOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetLatestVersionOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetLatestVersionOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        let latest = history
            .versions
            .last()
            .cloned()
            .unwrap_or_else(|| input.content_id.clone());

        ApiResponse::success(
            GetLatestVersionOutput {
                content_id: input.content_id,
                latest_version: latest,
                updated_at: None,
            },
            trace_id,
        )
    }

    /// コンテンツの更新履歴を取得する。
    ///
    /// `auth` は State Node の `GET /content/:id/history` に転送する認証ヘッダ。本番では `Some` が必要。
    pub fn get_history(
        &self,
        input: GetHistoryInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetHistoryOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetHistoryOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetHistoryOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        // limit はState Node側に無いので、SDK側で適用（末尾=最新側を優先）
        let mut versions = history.versions;
        let limit = input.limit as usize;
        if limit > 0 && versions.len() > limit {
            versions = versions[versions.len() - limit..].to_vec();
        }

        ApiResponse::success(
            GetHistoryOutput {
                content_id: input.content_id,
                versions,
            },
            trace_id,
        )
    }

    /// State Node の Node CBOR を取得し、CID 検証済みの親 CID リストを返す。
    /// 単調性チェックの祖先探索用フェッチャ。
    fn fetch_verified_parents(
        &self,
        remote_content_id: &str,
        version_cid: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: &str,
    ) -> Result<Vec<String>, String> {
        let data = self
            .get_state_node_version_data::<()>(
                remote_content_id,
                version_cid,
                auth,
                trace_id.to_string(),
            )
            .map_err(|e| format!("failed to fetch ancestor node {version_cid}: {:?}", e.error))?;

        let node_bytes = BASE64_STANDARD
            .decode(&data.data)
            .map_err(|e| format!("invalid base64 data for ancestor node {version_cid}: {e}"))?;

        let verified = monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            version_cid,
        )
        .map_err(|e| format!("ancestor node {version_cid} failed CID verification: {e}"))?;

        Ok(verified.parents)
    }

    /// State Node から content を読み、検証・復号して平文を返す(検証付き read)。
    ///
    /// `docs/design.md` §10「read応答の完全性検証」の実 read 経路。処理フロー:
    /// 1. `read:{content_id}:{timestamp}` 署名の認証コンテキストを解決
    /// 2. 版を決定(`input.version` 指定があればその版、無ければ履歴の最新)
    /// 3. Node CBOR を取得し、CID 再計算で改ざん検証(コンポーネント A)
    /// 4. 最新読みの場合のみ、単調性チェック(コンポーネント B):
    ///    前回受理した版が今回の版の祖先でなければ後退として拒否
    /// 5. ローカル cek_store から CEK を引き、AES-GCM 復号 + plain CID 照合
    ///
    /// CEK は「自分が作成した content」または「share の KeyEnvelope を処理済みの
    /// content」(`decrypt_shared_content` が保存する)についてローカルに存在する。
    ///
    /// 既知の限界(設計 §2): 正規 member 自身による stale/ロールバックのうち、
    /// クライアントが一度も見ていない範囲は検出できない(否定的事実は証明不能)。
    pub fn read_content_from_state_node(
        &self,
        input: ReadContentFromStateNodeInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<ReadContentFromStateNodeOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }
        if input.local_content_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("local_content_id must not be empty".into()),
                trace_id,
            );
        }

        let auth = match self.resolve_state_read_auth::<ReadContentFromStateNodeOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let auth = auth.as_ref();

        // 版の決定。明示指定が無ければ履歴の最新を読む。
        // 履歴は署名も系列検証も無い(信頼できない)が、ここで版を「選ぶ」だけで、
        // 選ばれた版の中身は CID 検証(A)、新しさは単調性チェック(B)が守る。
        let (version, is_latest_read) = match input.version.clone() {
            Some(v) => (v, false),
            None => {
                let history = match self.get_state_node_history::<ReadContentFromStateNodeOutput>(
                    &input.content_id,
                    auth,
                    trace_id.clone(),
                ) {
                    Ok(h) => h,
                    Err(e) => return e,
                };
                let latest = history
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone());
                (latest, true)
            }
        };

        // Node CBOR の取得 + CID 検証(A)
        let state_node_data = match self
            .get_state_node_version_data::<ReadContentFromStateNodeOutput>(
                &input.content_id,
                &version,
                auth,
                trace_id.clone(),
            ) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                );
            }
        };

        let verified = match monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            &version,
        ) {
            Ok(v) => v,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "state node response failed CID verification (tampered response?): {e}"
                    )),
                    trace_id,
                );
            }
        };

        // 単調性チェック(B)。最新読みのときだけ働く。版を明示指定した read は
        // 「過去の版を意図的に読む」正当な操作なので、A(CID 検証)のみ。
        // ここではチェックのみ行い、last_seen の記録は復号まで含む全検証が
        // 成功した後に行う。チェック通過直後に記録すると、CID は通るが復号
        // できない偽 Node を 1 回受けるだけで pin が汚染され、以後の正規 read
        // が恒久的に Conflict になる(単調性チェックの自壊 DoS)。
        let checked_last_seen = if is_latest_read {
            match self.check_read_monotonicity(
                &input.content_id,
                &version,
                &verified.parents,
                auth,
                &trace_id,
            ) {
                Ok(last_seen) => Some(last_seen),
                Err(e) => return *e,
            }
        } else {
            None
        };

        // CEK ロード + AES-GCM 復号 + plain CID 照合
        let local_content_id =
            monas_content::domain::content_id::ContentId::new(input.local_content_id.clone());
        let plaintext = match self.content_service.verify_and_decrypt_relay_read(
            &node_bytes,
            &version,
            local_content_id,
        ) {
            Ok(read) => read.plaintext,
            Err(e) => {
                return ApiResponse::error(
                    Self::map_verified_read_error(e, &input.local_content_id),
                    trace_id,
                );
            }
        };

        // 全検証成功。last_seen を compare-and-advance で記録する。
        // チェック時に観測した値から動いていた場合(並行 read が先に進めた)は
        // 上書きせずスキップする — 古い版で pin を巻き戻さないため。
        if let Some(expected) = checked_last_seen {
            if expected.as_deref() != Some(version.as_str()) {
                if let Err(e) = self.last_seen_store.compare_and_save(
                    &input.content_id,
                    expected.as_deref(),
                    &version,
                ) {
                    return ApiResponse::error(
                        ApiError::Internal(format!("failed to record last-seen version: {e}")),
                        trace_id,
                    );
                }
            }
        }

        ApiResponse::success(
            ReadContentFromStateNodeOutput {
                content_id: input.content_id,
                local_content_id: input.local_content_id,
                version,
                content: encode_base64url(&plaintext),
            },
            trace_id,
        )
    }

    /// 最新読みの単調性チェック本体。前回受理した版(`last_seen`)が今回の版の
    /// 祖先(または同一)であることを、CID 検証済みの親リンクを辿って確認する。
    /// チェックのみ行い、記録はしない(記録は復号成功後に呼び出し側が
    /// compare-and-advance で行う)。戻り値はチェック時に観測した `last_seen`。
    fn check_read_monotonicity(
        &self,
        remote_content_id: &str,
        version: &str,
        parents: &[String],
        auth: Option<&StateNodeAuthContext>,
        trace_id: &str,
    ) -> Result<Option<String>, Box<ApiResponse<ReadContentFromStateNodeOutput>>> {
        let last_seen = self.last_seen_store.load(remote_content_id).map_err(|e| {
            Box::new(ApiResponse::error(
                ApiError::Internal(format!("failed to load last-seen version: {e}")),
                trace_id.to_string(),
            ))
        })?;

        match last_seen.as_deref() {
            // 初回(記録なし)は TOFU で受理する(記録は復号成功後)。
            None => {}
            // 同じ版を読み直しただけ。
            Some(l) if l == version => {}
            Some(l) => {
                let outcome = walk_ancestors_for(parents, l, MAX_MONOTONICITY_FETCHES, |cid| {
                    self.fetch_verified_parents(remote_content_id, cid, auth, trace_id)
                })
                .map_err(|e| {
                    Box::new(ApiResponse::error(
                        ApiError::Internal(format!("monotonicity ancestor walk failed: {e}")),
                        trace_id.to_string(),
                    ))
                })?;

                match outcome {
                    AncestorWalkOutcome::FoundTarget => {}
                    AncestorWalkOutcome::Exhausted => {
                        return Err(Box::new(ApiResponse::error(
                            ApiError::Conflict(format!(
                                "version regression detected: state node returned {version} as latest, \
                                 but previously accepted version {l} is not among its ancestors \
                                 (possible rollback attack or stale relay)"
                            )),
                            trace_id.to_string(),
                        )));
                    }
                    AncestorWalkOutcome::BoundExceeded => {
                        return Err(Box::new(ApiResponse::error(
                            ApiError::Conflict(format!(
                                "monotonicity check aborted: ancestor walk exceeded \
                                 {MAX_MONOTONICITY_FETCHES} fetches without reaching previously \
                                 accepted version {l}; rejecting read (fail-closed)"
                            )),
                            trace_id.to_string(),
                        )));
                    }
                }
            }
        }

        Ok(last_seen)
    }

    /// `verify_and_decrypt_relay_read` のエラーを、呼び出し側が対処を判断できる
    /// `ApiError` へ写像する。特に「CEK が無い」「CEK が合わない」は
    /// share / rotation / revoke のどの状況かをメッセージで区別する。
    fn map_verified_read_error(
        e: monas_content::application_service::content_service::VerifiedReadError,
        local_content_id: &str,
    ) -> ApiError {
        use monas_content::application_service::content_service::{
            DecryptWithCekError, VerifiedReadError,
        };
        match e {
            VerifiedReadError::NodeVerification(err) => ApiError::Internal(format!(
                "state node response failed CID verification (tampered response?): {err}"
            )),
            VerifiedReadError::KeyStore(err) => {
                ApiError::Internal(format!("CEK store error: {err:?}"))
            }
            VerifiedReadError::MissingKey => ApiError::NotFound(format!(
                "no content encryption key for local content {local_content_id} on this device: \
                 the content was neither created here nor received via share on this device. \
                 Process its share KeyEnvelope (POST /share/decrypt) first."
            )),
            VerifiedReadError::Decrypt(DecryptWithCekError::Domain(_)) => ApiError::Forbidden(
                "decryption failed with the locally stored CEK: the key may be stale after a CEK \
                 rotation, or your access may have been revoked. If you still have access, \
                 re-process the latest share KeyEnvelope to refresh the stored CEK."
                    .to_string(),
            ),
            VerifiedReadError::Decrypt(DecryptWithCekError::ContentIdMismatch {
                expected,
                actual,
            }) => ApiError::Conflict(format!(
                "decrypted content does not match local_content_id (expected {expected}, got \
                 {actual}): the content has likely been updated — pass the local content id that \
                 corresponds to the version being read"
            )),
        }
    }

    /// 取得したコンテンツの整合性を検証する。
    ///
    /// `auth` は State Node の履歴・バージ取得 API に転送する認証ヘッダ。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. コンテンツのハッシュを計算
    /// 2. State Nodeから取得した情報と比較
    /// 3. 一致すれば valid: true
    pub fn verify_integrity(
        &self,
        input: VerifyIntegrityInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let auth = match self.resolve_state_read_auth::<VerifyIntegrityOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let auth = auth.as_ref();

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                );
            }
        };

        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&content_bytes);
            let digest = hasher.finalize();
            format!("{digest:x}")
        };

        let version_to_check = if let Some(v) = input.expected_version.clone() {
            v
        } else {
            match self.get_state_node_history::<VerifyIntegrityOutput>(
                &input.content_id,
                auth,
                trace_id.clone(),
            ) {
                Ok(h) => h
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone()),
                Err(e) => return e,
            }
        };

        let state_node_data = match self.get_state_node_version_data::<VerifyIntegrityOutput>(
            &input.content_id,
            &version_to_check,
            auth,
            trace_id.clone(),
        ) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                );
            }
        };

        // State Node は read 応答として「Node 全体(CBOR)」を返す。まず CID を
        // 再計算して version と一致することを検証し(改ざん検知)、その上で
        // payload の暗号文を取り出す(§8.1)。照合先はクライアントが選択した
        // version に固定する。応答内の version は自己申告なので、それに対して
        // 照合すると任意の Node + その CID を返すだけで検証が通ってしまう。
        let state_bytes = match monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            &version_to_check,
        ) {
            Ok(verified) => verified.ciphertext,
            Err(e) => {
                return ApiResponse::success(
                    VerifyIntegrityOutput {
                        valid: false,
                        computed_hash,
                        reason: Some(format!("state node response failed CID verification: {e}")),
                    },
                    trace_id,
                );
            }
        };

        // State Node が保持するのは SDK が送信した「暗号文」なので、
        // local_content_id があればローカルに保存された暗号文とバイト比較する。
        // （平文 `content` と State Node のバイト列は一致し得ない。）
        let (valid, reason) = if let Some(local_id) = input.local_content_id.as_deref() {
            match self.content_service.fetch_encrypted(
                monas_content::domain::content_id::ContentId::new(local_id.to_string()),
            ) {
                Ok(local_cipher) => {
                    if local_cipher == state_bytes {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(format!(
                                "state node ciphertext differs from local ciphertext (version={version_to_check})"
                            )),
                        )
                    }
                }
                Err(e) => (
                    false,
                    Some(format!(
                        "failed to load local ciphertext for {local_id}: {e}"
                    )),
                ),
            }
        } else {
            let valid = content_bytes == state_bytes;
            (
                valid,
                if valid {
                    None
                } else {
                    Some(format!(
                        "content mismatch with state node (version={version_to_check})"
                    ))
                },
            )
        };

        ApiResponse::success(
            VerifyIntegrityOutput {
                valid,
                computed_hash,
                reason,
            },
            trace_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{walk_ancestors_for, AncestorWalkOutcome};
    use std::collections::HashMap;

    /// cid -> parents のテーブルからフェッチャを作る。
    fn table_fetcher(
        table: HashMap<&'static str, Vec<&'static str>>,
    ) -> impl FnMut(&str) -> Result<Vec<String>, String> {
        move |cid: &str| {
            table
                .get(cid)
                .map(|ps| ps.iter().map(|s| s.to_string()).collect())
                .ok_or_else(|| format!("unknown cid {cid}"))
        }
    }

    #[test]
    fn finds_target_in_direct_parents_without_fetching() {
        // 直接の親に target がいれば fetch は 1 度も要らない
        let mut fetch_count = 0;
        let outcome = walk_ancestors_for(
            &["target".to_string(), "other".to_string()],
            "target",
            10,
            |_| {
                fetch_count += 1;
                Ok(vec![])
            },
        )
        .unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::FoundTarget);
        assert_eq!(fetch_count, 0);
    }

    #[test]
    fn finds_target_deeper_in_chain() {
        // v3 -> v2 -> v1(target) -> genesis
        let outcome = walk_ancestors_for(
            &["v2".to_string()],
            "v1",
            10,
            table_fetcher(HashMap::from([
                ("v2", vec!["v1"]),
                ("v1", vec!["genesis"]),
                ("genesis", vec![]),
            ])),
        )
        .unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::FoundTarget);
    }

    #[test]
    fn exhausted_when_target_not_ancestor() {
        // 後退シナリオ: 古い版の祖先には新しい target がいない
        let outcome = walk_ancestors_for(
            &["genesis".to_string()],
            "newer-version",
            10,
            table_fetcher(HashMap::from([("genesis", vec![])])),
        )
        .unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::Exhausted);
    }

    #[test]
    fn exhausted_immediately_for_genesis_read() {
        // genesis(親なし)を「最新」と偽られたケース: 探索なしで後退確定
        let outcome =
            walk_ancestors_for(&[], "newer-version", 10, |_| panic!("must not fetch")).unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::Exhausted);
    }

    #[test]
    fn bound_exceeded_is_fail_closed() {
        // 際限なく親が続く偽 DAG は上限で打ち切る
        let mut i = 0;
        let outcome = walk_ancestors_for(&["n0".to_string()], "never-found", 5, |_| {
            i += 1;
            Ok(vec![format!("n{i}")])
        })
        .unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::BoundExceeded);
    }

    #[test]
    fn diamond_dag_is_deduplicated() {
        // merge を含む DAG(v3 の親 v2a, v2b が共通祖先 v1 を持つ)でも
        // 同じノードを二度 fetch しない
        let mut fetched: Vec<String> = vec![];
        let outcome = walk_ancestors_for(
            &["v2a".to_string(), "v2b".to_string()],
            "genesis",
            10,
            |cid: &str| {
                fetched.push(cid.to_string());
                Ok(match cid {
                    "v2a" | "v2b" => vec!["v1".to_string()],
                    "v1" => vec!["genesis".to_string()],
                    _ => vec![],
                })
            },
        )
        .unwrap();
        assert_eq!(outcome, AncestorWalkOutcome::FoundTarget);
        // v1 は 1 度だけ fetch される
        assert_eq!(fetched.iter().filter(|c| c.as_str() == "v1").count(), 1);
    }

    #[test]
    fn fetch_error_propagates() {
        let err = walk_ancestors_for(&["v2".to_string()], "v1", 10, |_| {
            Err("network down".to_string())
        })
        .unwrap_err();
        assert!(err.contains("network down"));
    }
}
