use crate::domain::content_id::ContentId;
use crate::domain::share::{KeyEnvelope, KeyId, Permission};

/// コンテンツを 1 人の受信者と共有するユースケースの入力。
///
/// - クライアントは受信者の公開鍵バイト列を渡すだけでよく、KeyId の生成と保存はアプリケーション側で行う。
#[derive(Debug)]
pub struct GrantShareCommand {
    pub content_id: ContentId,
    pub sender_key_id: KeyId,
    /// 送信者の秘密鍵バイト列。HPKE Auth モードの wrap(送信者認証)に用いる。
    /// 保存はされず、この呼び出しの間だけ使われる。
    pub sender_private_key: Vec<u8>,
    pub recipient_public_key: Vec<u8>,
    pub permission: Permission,
}

/// 共有付与ユースケースの出力。
#[derive(Debug)]
pub struct GrantShareResult {
    pub envelope: KeyEnvelope,
    pub recipient_key_id: KeyId,
}

/// 共有を取り消すユースケースの入力。
#[derive(Debug)]
pub struct RevokeShareCommand {
    pub content_id: ContentId,
    pub sender_key_id: KeyId,
    /// 送信者の秘密鍵バイト列。残存受信者向け KeyEnvelope 再発行の
    /// HPKE Auth モード wrap(送信者認証)に用いる。
    pub sender_private_key: Vec<u8>,
    pub recipient_key_id: KeyId,
}

/// 共有取り消しユースケースの出力。
#[derive(Debug)]
pub struct RevokeShareResult {
    pub content_id: ContentId,
    pub recipient_key_id: KeyId,
    pub envelopes: Vec<KeyEnvelope>,
}
