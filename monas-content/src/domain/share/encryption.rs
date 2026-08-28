use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// CEK を受信者の公開鍵でラップ / 秘密鍵でアンラップ（HPKE など）するためのポート。
///
/// - 具体的な HPKE アルゴリズムは infra 層の実装に委譲する。
/// - KeyId -> PublicKeyBytes / PrivateKeyBytes の解決は application 層や別ポートに任せ、
///   このポートは「公開鍵 / 秘密鍵バイト列と CEK から (enc, wrapped_cek) を生成／復元する」
///   純粋な暗号処理のみを担当する。
#[derive(Debug)]
pub enum KeyWrappingError {
    /// 暗号処理に失敗した場合（hpke-rs などからのエラーをラップ）。
    CryptoError(String),
    /// 入力値（鍵やパラメータなど）が不正な場合。
    InvalidInput(String),
    /// その他のエラー。
    Other(String),
}

/// CEK ラップに暗号学的に束縛する関連データ(AAD)。
///
/// `(content_id, recipient_key_id, key_epoch)` を wrap 計算に混ぜることで、
/// envelope の「どのコンテンツの・誰宛の・どの鍵世代の」ラップかを改ざん不能にする。
/// いずれかのフィールドを書き換えた envelope は unwrap(復号)自体が失敗する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeAad<'a> {
    pub content_id: &'a ContentId,
    pub recipient_key_id: &'a KeyId,
    pub key_epoch: u64,
}

impl EnvelopeAad<'_> {
    /// AAD のバイト列表現。フィールドは長さプレフィクス付きで連結し、
    /// 連結の曖昧さ(フィールド境界の付け替え)を排除する。
    pub fn to_bytes(&self) -> Vec<u8> {
        let cid = self.content_id.as_str().as_bytes();
        let kid = self.recipient_key_id.as_bytes();
        let mut out = Vec::with_capacity(4 + cid.len() + 4 + kid.len() + 8);
        out.extend_from_slice(&(cid.len() as u32).to_be_bytes());
        out.extend_from_slice(cid);
        out.extend_from_slice(&(kid.len() as u32).to_be_bytes());
        out.extend_from_slice(kid);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out
    }
}

/// CEK を受信者の公開鍵でラップし、秘密鍵でアンラップするためのポート。
///
/// ラップは送信者認証付き(HPKE Auth モード相当)であること:
/// 送信者秘密鍵が wrap 計算に混ざり、受信者は送信者の公開鍵を使って unwrap する。
/// 送信者が本物でなければ unwrap(復号)が失敗するため、別途の署名は不要。
pub trait KeyWrapping {
    /// 1 つの CEK を、指定された受信者公開鍵向けにラップする。
    ///
    /// - `cek`: コンテンツ本体の暗号化に用いた共有鍵。
    /// - `recipient_public_key`: 受信者の公開鍵バイト列。
    /// - `sender_private_key`: 送信者の秘密鍵バイト列(送信者認証に用いる)。
    /// - `aad`: wrap に束縛する関連データ(コンテンツ ID・宛先 key id・鍵世代)。
    ///
    /// 戻り値のタプルは `(enc, wrapped_cek)` を表す。
    fn wrap_cek(
        &self,
        cek: &ContentEncryptionKey,
        recipient_public_key: &[u8],
        sender_private_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyWrappingError>;

    /// 1 つの CEK を、指定された受信者秘密鍵を用いてアンラップする。
    ///
    /// - `enc`: HPKE の送信者公開値。
    /// - `wrapped_cek`: HPKE でラップされた CEK のバイト列。
    /// - `recipient_private_key`: 受信者の秘密鍵バイト列。
    /// - `sender_public_key`: 送信者の公開鍵バイト列。unwrap 成功 =
    ///   この鍵の持ち主が作った envelope であることの証明になる。
    /// - `aad`: wrap 時と同一の関連データ。一致しなければ unwrap は失敗する。
    fn unwrap_cek(
        &self,
        enc: &[u8],
        wrapped_cek: &[u8],
        recipient_private_key: &[u8],
        sender_public_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<ContentEncryptionKey, KeyWrappingError>;
}
