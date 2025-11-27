use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content_id::ContentId;

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

/// CEK を受信者の公開鍵でラップし、秘密鍵でアンラップするためのポート。
pub trait KeyWrapping {
    /// 1 つの CEK を、指定された受信者公開鍵向けにラップする。
    ///
    /// - `cek`: コンテンツ本体の暗号化に用いた共有鍵。
    /// - `recipient_public_key`: 受信者の公開鍵バイト列。
    /// - `content_id`: この CEK がひも付くコンテンツ ID。HPKE の info/AAD などに利用できる。
    ///
    /// 戻り値のタプルは `(enc, wrapped_cek)` を表す。
    fn wrap_cek(
        &self,
        cek: &ContentEncryptionKey,
        recipient_public_key: &[u8],
        content_id: &ContentId,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyWrappingError>;
    ///
    /// 1 つの CEK を、指定された受信者秘密鍵を用いてアンラップする。
    ///
    /// - `enc`: HPKE の送信者公開値。
    /// - `wrapped_cek`: HPKE でラップされた CEK のバイト列。
    /// - `recipient_private_key`: 受信者の秘密鍵バイト列。
    /// - `content_id`: この CEK がひも付くコンテンツ ID。HPKE の info/AAD などに利用できる。
    fn unwrap_cek(
        &self,
        enc: &[u8],
        wrapped_cek: &[u8],
        recipient_private_key: &[u8],
        content_id: &ContentId,
    ) -> Result<ContentEncryptionKey, KeyWrappingError>;
}
