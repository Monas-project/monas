//! 受信者側の送信者公開鍵ピン(TOFU)ストア。
//!
//! share の KeyEnvelope は HPKE Auth モードでラップされており、受信者は
//! 「期待する送信者の公開鍵」で unwrap する(成功 = その鍵の持ち主が作った証明)。
//! このストアは content ごとに、最初に unwrap に成功した送信者公開鍵を
//! ピン留めし(TOFU)、以後の envelope はピン済みの鍵でのみ検証する。
//!
//! 併せて CEK の鍵世代(key_epoch)と、**その世代の CEK 自体**を記録する。
//! 記録済み世代より古い envelope は拒否する(rotation 後に旧 envelope を
//! 再送して CEK を巻き戻す replay 攻撃の防止)。
//!
//! ## なぜ CEK をここに置くのか
//!
//! 守るべき不変条件は「送信者鍵・世代・CEK の3つ組が常に整合していること」で
//! あって、世代番号だけではない。3つ組を別ストアに分けて別々に commit すると、
//! 世代を CAS で守っても次の interleaving で壊れる:
//!
//! 1. epoch N の処理が pin(epoch N-1)を読む
//! 2. epoch N+1 の処理が pin を N+1 へ進め、新しい CEK を保存する
//! 3. epoch N の処理が「同一世代の再処理」等の経路で CEK だけを書き戻す
//! 4. 結果は `pin = N+1, CEK = N` となり、以後の復号が失敗する
//!
//! 3つ組を1レコードに入れて単一の compare-and-swap で入れ替えれば、この
//! interleaving は構造的に起こり得ない。CEK ストア側は、この権威レコードから
//! 導出されるキャッシュとして扱う(書き損じても再処理で回復できる)。
//!
//! キーは受信者から見た(ローカルの) content id。

#[derive(Debug, thiserror::Error)]
pub enum SenderKeyPinStoreError {
    #[error("sender key pin store error: {0}")]
    Storage(String),
}

/// ピン留めされた送信者公開鍵と、その送信者から受理した最新の鍵世代・CEK。
///
/// この3つは常に同じ commit で入れ替わる。個別に更新してはならない
/// (モジュール doc の interleaving を参照)。
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyPin {
    /// 送信者の公開鍵バイト列(P-256 uncompressed form)。
    pub sender_public_key: Vec<u8>,
    /// 最後に unwrap に成功した envelope の key_epoch。
    pub key_epoch: u64,
    /// `key_epoch` 世代の CEK。この端末のローカルにのみ存在し、ネットワークには出ない。
    ///
    /// 旧レコード(CEK を持たない形式)から読んだ場合は `None` になる。
    /// その場合は次に受理した envelope で埋まる。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cek: Option<Vec<u8>>,
}

/// CEK を含むため、`Debug` は鍵素材を出さない。ログや panic メッセージに
/// レコードが載っても CEK が漏れないようにする。
impl std::fmt::Debug for SenderKeyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderKeyPin")
            .field("sender_public_key", &self.sender_public_key)
            .field("key_epoch", &self.key_epoch)
            .field(
                "cek",
                &self.cek.as_ref().map(|_| "<redacted>").unwrap_or("None"),
            )
            .finish()
    }
}

/// `content_id -> (送信者公開鍵, 最終受理 key_epoch, その世代の CEK)` の永続化ポート。
pub trait SenderKeyPinStore: Send + Sync {
    fn load(&self, content_id: &str) -> Result<Option<SenderKeyPin>, SenderKeyPinStoreError>;
    fn save(&self, content_id: &str, pin: &SenderKeyPin) -> Result<(), SenderKeyPinStoreError>;

    /// compare-and-advance: 現在値が `expected` と一致する場合のみ `pin` へ進める。
    /// 戻り値は「進めたかどうか」。
    ///
    /// envelope の並行処理(rotation 前後の epoch N / N+1 が同時に走る等)で、
    /// 「load した時点の pin」を前提に無条件 save すると、後から完了した古い
    /// epoch が新しいレコードを巻き戻せる。3つ組は1レコードなので、この CAS が
    /// 成功した時点で送信者鍵・世代・CEK は一括で入れ替わっている。
    fn compare_and_save(
        &self,
        content_id: &str,
        expected: Option<&SenderKeyPin>,
        pin: &SenderKeyPin,
    ) -> Result<bool, SenderKeyPinStoreError>;
}
