use crate::application_service::content_service::{ContentEncryptionKeyStore, ContentRepository};
use crate::domain::share::{encryption::KeyWrapping, KeyEnvelope, Share};

use super::{
    GrantShareCommand, GrantShareResult, PublicKeyDirectory, RevokeShareCommand, RevokeShareResult,
    ShareApplicationError, ShareRepository,
};

/// コンテンツ共有ユースケースのアプリケーションサービス。
///
/// - ContentService とは独立に、「共有（ACL と KeyEnvelope 生成）」に責務を限定する。
pub struct ShareService<SR, CR, KS, KD, KW> {
    pub share_repository: SR,
    pub content_repository: CR,
    pub cek_store: KS,
    pub public_key_directory: KD,
    pub key_wrapper: KW,
}

impl<SR, CR, KS, KD, KW> ShareService<SR, CR, KS, KD, KW>
where
    SR: ShareRepository,
    CR: ContentRepository,
    KS: ContentEncryptionKeyStore,
    KD: PublicKeyDirectory,
    KW: KeyWrapping,
{
    /// 指定されたコンテンツに対する現在の共有状態（ACL）を取得する。
    ///
    /// - Share がまだ一度も保存されていない場合は Ok(None) を返す。
    pub fn get_share(
        &self,
        content_id: crate::domain::content_id::ContentId,
    ) -> Result<Option<Share>, ShareApplicationError> {
        self.share_repository
            .load(&content_id)
            .map_err(ShareApplicationError::ShareRepository)
    }

    /// 1 人の受信者に対して共有を付与し、その受信者向けの KeyEnvelope を生成する。
    pub fn grant_share(
        &self,
        cmd: GrantShareCommand,
    ) -> Result<GrantShareResult, ShareApplicationError> {
        // 1. コンテンツ本体と暗号化状態の確認
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(ShareApplicationError::ContentRepository)?
            .ok_or(ShareApplicationError::ContentNotFound)?;

        if content.is_deleted() {
            return Err(ShareApplicationError::ContentDeleted);
        }

        let ciphertext = content
            .encrypted_content()
            .cloned()
            .ok_or(ShareApplicationError::MissingEncryptedContent)?;

        // 2. CEK の取得
        let cek = self
            .cek_store
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ContentEncryptionKeyStore)?
            .ok_or(ShareApplicationError::MissingContentEncryptionKey)?;

        // 3. 受信者公開鍵を登録し、対応する KeyId を発行
        let recipient_key_id = self
            .public_key_directory
            .register_public_key(&cmd.recipient_public_key)
            .map_err(ShareApplicationError::PublicKeyDirectory)?;
        let recipient_public_key = &cmd.recipient_public_key;

        // 4. HPKE で CEK をラップ
        let (enc, wrapped_cek) = self
            .key_wrapper
            .wrap_cek(&cek, &recipient_public_key, &cmd.content_id)
            .map_err(|e| ShareApplicationError::KeyWrapping(format!("{e:?}")))?;

        let wrapped_recipient = crate::domain::share::WrappedRecipientKey::new(
            recipient_key_id.clone(),
            enc,
            wrapped_cek,
        );

        // 5. KeyEnvelope を構築
        let envelope = KeyEnvelope::new(
            cmd.content_id.clone(),
            crate::domain::share::key_envelope::KeyWrapAlgorithm::HpkeV1,
            cmd.sender_key_id.clone(),
            wrapped_recipient,
            ciphertext,
        );

        // 6. Share (ACL) を更新
        let mut share = self
            .share_repository
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ShareRepository)?
            .unwrap_or_else(|| Share::new(cmd.content_id.clone()));

        let event = match cmd.permission {
            crate::domain::share::Permission::Read => share.grant_read(recipient_key_id.clone()),
            crate::domain::share::Permission::Write => share.grant_write(recipient_key_id.clone()),
        }
        .map_err(ShareApplicationError::Share)?;

        // NOTE: 現状では ShareEvent は外に返さず、ACL の保存のみ行う。
        let _ = event;

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        Ok(GrantShareResult {
            envelope,
            recipient_key_id,
        })
    }

    /// 指定された受信者との共有関係を取り消す。
    ///
    /// - ACL のみを更新し、KeyEnvelope の失効やコンテンツ削除はここでは扱わない。
    pub fn revoke_share(
        &self,
        cmd: RevokeShareCommand,
    ) -> Result<RevokeShareResult, ShareApplicationError> {
        let mut share = self
            .share_repository
            .load(&cmd.content_id)
            .map_err(ShareApplicationError::ShareRepository)?
            .ok_or(ShareApplicationError::ContentNotFound)?;

        share
            .revoke(&cmd.recipient_key_id)
            .map_err(ShareApplicationError::Share)?;

        self.share_repository
            .save(&share)
            .map_err(ShareApplicationError::ShareRepository)?;

        Ok(RevokeShareResult {
            content_id: cmd.content_id,
            recipient_key_id: cmd.recipient_key_id,
        })
    }
}
