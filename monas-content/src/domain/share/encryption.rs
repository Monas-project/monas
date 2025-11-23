use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content_id::ContentId;

/// CEK を受信者の公開鍵でラップ（HPKE など）するためのポート。
///
/// - 具体的な HPKE アルゴリズムは infra 層の実装に委譲する。
/// - KeyId -> PublicKeyBytes の解決は application 層や別ポートに任せ、
///   このポートは「公開鍵バイト列と CEK から (enc, wrapped_cek) を生成する」純粋な暗号処理のみを担当する。
#[derive(Debug)]
pub enum KeyWrappingError {
    /// 暗号処理に失敗した場合（hpke-rs などからのエラーをラップ）。
    CryptoError(String),
    /// その他のエラー。
    Other(String),
}

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
}
