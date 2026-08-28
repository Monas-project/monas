//! 一度受理した署名済みリクエストの記録(mutation の再送防止)。
//!
//! 署名内 timestamp の鮮度チェック(5分窓)は「古い署名を無限に使い回せない」
//! ことしか保証しない。窓の中では同じ署名を何度でも通せる。
//!
//! update / delete は冪等ではないので、これは単なる重複ではなく**状態の
//! 巻き戻し**になる。攻撃者が署名済みの旧 ciphertext 更新 A を捕まえておき、
//! 正規の更新 B が入った後に A を再送すると、サーバは A を「その時点の最新版を
//! 親とする新しい操作」として commit する。結果、古い ciphertext が最新版に
//! なってしまう。
//!
//! そこで、受理した mutation リクエストを一意に識別する値を記録し、2度目の
//! 提示を拒否する。識別子は**署名対象メッセージと signer** から導く
//! (`StateNodeService::mutation_request_id`)。メッセージは operation /
//! resource / timestamp / body digest すべてに束縛されているので、これが
//! 一致する = 完全に同じリクエストの再送であり、新しいフィールドをワイヤ形式へ
//! 足す必要もない。
//!
//! **署名バイト列の digest を識別子にしてはならない。** ECDSA は malleable で、
//! 有効な `(r, s)` に対し `(r, n - s)` も同じメッセージ・同じ鍵で検証を通る。
//! 署名を hash すると 1 つの承認済みリクエストが 2 つの識別子を持ち、攻撃者は
//! 捕捉した署名を 1 回変換するだけでこの記録をすり抜けられてしまう。
//!
//! ## 保持期間
//!
//! 記録は署名の鮮度窓(`MAX_REQUEST_AGE_SECS`)を超えたら捨ててよい。窓の外へ
//! 出た署名は、この記録が無くても鮮度チェックで拒否されるからである。よって
//! ストアは無制限には育たず、GC も「期限切れを消す」だけで済む。

use std::collections::HashMap;
use std::sync::Mutex;

/// 署名の鮮度窓。`MonasAccountAdapter` の `MAX_AGE_SECS` と揃えること。
/// これを超えた記録は保持しても意味がない(署名側が先に期限切れになる)。
pub const CONSUMED_REQUEST_RETENTION_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum ConsumedRequestStoreError {
    #[error("consumed request store error: {0}")]
    Storage(String),
}

/// 受理済み mutation リクエストの記録。
pub trait ConsumedRequestStore: Send + Sync {
    /// `request_id` を「今回初めて受理した」ものとして記録する。
    ///
    /// 戻り値が `false` = 既に記録済み(= 再送)。呼び出し側は commit せずに
    /// 拒否すること。記録と判定は不可分でなければならない。同時に届いた同一
    /// リクエストの両方が `true` を受け取ると、二重適用を防げない。
    ///
    /// `now` は**このノードの現在時刻**(Unix 秒)。期限切れ記録の掃除に使う。
    ///
    /// caller が申告した署名内 timestamp を渡してはならない。許容 skew の範囲で
    /// 未来寄りの timestamp を持つ有効なリクエストを先に出せば、まだ鮮度窓の
    /// 中にある記録を早期に掃除させられ、その後で古い署名を再提示できてしまう。
    fn record_if_absent(
        &self,
        request_id: &[u8],
        now: u64,
    ) -> Result<bool, ConsumedRequestStoreError>;
}

/// プロセス内 `HashMap` 実装。
///
/// 記録が揮発してよいのは、保持期間が署名の鮮度窓と同じだからである。
/// ノードが再起動すると窓の中の記録は失われるが、そこで通り得る再送は
/// 「再起動をまたいで 5 分以内に届いた同一署名」に限られる。永続化した
/// 場合との差はこの一点で、fsync のコストを毎 mutation に載せるよりも
/// 割に合うと判断した。
///
/// なお、この記録はノードごとに独立である。複数のレプリカへ同じ署名を送れば
/// それぞれで1回ずつ受理される。CRDT は同じ操作の重複適用に耐えるが、
/// 「どのノードから見ても厳密に1回」を保証するものではない。
#[derive(Default)]
pub struct InMemoryConsumedRequestStore {
    /// request id -> 受理時刻(Unix 秒)
    inner: Mutex<HashMap<Vec<u8>, u64>>,
}

impl ConsumedRequestStore for InMemoryConsumedRequestStore {
    fn record_if_absent(
        &self,
        request_id: &[u8],
        now: u64,
    ) -> Result<bool, ConsumedRequestStoreError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 期限切れの掃除。挿入のたびに走らせるので、ストアのサイズは
        // 「鮮度窓の中に届いた mutation 数」で頭打ちになる。
        guard.retain(|_, accepted_at| {
            now.saturating_sub(*accepted_at) < CONSUMED_REQUEST_RETENTION_SECS
        });

        if guard.contains_key(request_id) {
            return Ok(false);
        }
        guard.insert(request_id.to_vec(), now);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_presentation_is_accepted_and_the_replay_is_not() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"sig-a", now).unwrap());
        assert!(!store.record_if_absent(b"sig-a", now).unwrap());
        // 違う署名は独立
        assert!(store.record_if_absent(b"sig-b", now).unwrap());
    }

    /// GC はサーバ時刻で動くので、caller が timestamp を前後させても
    /// 記録を早期に落とせない。ここでは「時刻が進まない限り記録は消えない」
    /// ことを、時刻を戻す提示も含めて確認する。
    #[test]
    fn out_of_order_presentations_cannot_evict_a_live_record() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"victim", now).unwrap());

        // 別リクエストが「未来寄り」に見える時刻で届いても、呼び出し側は
        // サーバ時刻を渡すので窓は動かない = victim は生き残る。
        assert!(store.record_if_absent(b"other", now).unwrap());
        assert!(
            !store.record_if_absent(b"victim", now).unwrap(),
            "a live record must not be evictable by other traffic"
        );

        // 時刻が戻る向きの提示でも復活しない
        assert!(
            !store.record_if_absent(b"victim", now - 100).unwrap(),
            "an earlier presentation must not resurrect the record"
        );
    }

    /// 鮮度窓を過ぎた記録は捨てられる。捨てても安全なのは、その署名が
    /// 記録の有無によらず鮮度チェックで拒否されるからである。
    #[test]
    fn records_are_dropped_once_the_signature_itself_would_expire() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"sig", now).unwrap());
        assert!(!store.record_if_absent(b"sig", now + 1).unwrap());
        assert!(!store
            .record_if_absent(b"sig", now + CONSUMED_REQUEST_RETENTION_SECS - 1)
            .unwrap());

        // 窓の外。記録は掃除され、ストアは育たない
        assert!(store
            .record_if_absent(b"sig", now + CONSUMED_REQUEST_RETENTION_SECS)
            .unwrap());
        assert_eq!(
            store.inner.lock().unwrap().len(),
            1,
            "expired records must be pruned rather than accumulate"
        );
    }
}
