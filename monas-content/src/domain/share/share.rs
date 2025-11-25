use std::collections::HashMap;

use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// コンテンツに対するアクセス権限。
///
/// - `Write` は常に `Read` を内包するものとして扱う。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Read,
    Write,
}

impl Permission {
    /// 読み取り可能かを判定するヘルパ。
    pub fn can_read(perms: &[Permission]) -> bool {
        perms
            .iter()
            .any(|p| matches!(p, Permission::Read | Permission::Write))
    }

    /// 書き込み可能かを判定するヘルパ。
    pub fn can_write(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(p, Permission::Write))
    }
}

/// 1 人の受信者に対する共有情報。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareRecipient {
    key_id: KeyId,
    permissions: Vec<Permission>,
}

impl ShareRecipient {
    pub fn new(key_id: KeyId, permissions: Vec<Permission>) -> Self {
        Self {
            key_id,
            permissions,
        }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    pub fn update_permissions(&mut self, permissions: Vec<Permission>) {
        self.permissions = permissions;
    }

    pub fn can_read(&self) -> bool {
        Permission::can_read(&self.permissions)
    }

    pub fn can_write(&self) -> bool {
        Permission::can_write(&self.permissions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    AlreadyShared,
    RecipientNotFound,
    InvalidOperation(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareEvent {
    RecipientGranted {
        content_id: ContentId,
        key_id: KeyId,
        permissions: Vec<Permission>,
    },
    RecipientRevoked {
        content_id: ContentId,
        key_id: KeyId,
    },
}

/// 1 つのコンテンツに対する共有状態（ACL）。
///
/// - `serde` によるシリアライズ/デシリアライズをサポートしており、
///   sled などの KVS に JSON 形式で保存できる。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Share {
    content_id: ContentId,
    /// key = KeyId
    recipients: HashMap<KeyId, ShareRecipient>,
}

impl Share {
    /// 指定された content_id に対応する空の Share を生成する。
    ///
    /// - DB 上にレコードが存在しない場合に、アプリケーション層で組み立てる用途を想定。
    pub fn new(content_id: ContentId) -> Self {
        Self {
            content_id,
            recipients: HashMap::new(),
        }
    }

    /// Read 権限の付与。
    ///
    /// - 既に同じ KeyId の受信者が存在する場合は `AlreadyShared` を返す。
    pub fn grant_read(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        self.grant_with_permissions(key_id, vec![Permission::Read])
    }

    /// Write 権限の付与。
    ///
    /// - `Write` は `Read` を内包する前提のため、ドメイン上は `Write` のみを持たせる。
    /// - 既に同じ KeyId の受信者が存在する場合は `AlreadyShared` を返す。
    pub fn grant_write(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        self.grant_with_permissions(key_id, vec![Permission::Write])
    }

    /// 共通の権限付与ロジック。
    ///
    /// - 既に同じ KeyId の受信者が存在する場合は `AlreadyShared` を返す。
    /// - 新しい `ShareRecipient` を追加し、`RecipientGranted` イベントを返す。
    fn grant_with_permissions(
        &mut self,
        key_id: KeyId,
        permissions: Vec<Permission>,
    ) -> Result<ShareEvent, ShareError> {
        if self.recipients.contains_key(&key_id) {
            return Err(ShareError::AlreadyShared);
        }

        let recipient = ShareRecipient::new(key_id.clone(), permissions.clone());
        self.recipients.insert(key_id.clone(), recipient);

        Ok(ShareEvent::RecipientGranted {
            content_id: self.content_id.clone(),
            key_id,
            permissions,
        })
    }

    /// 共有関係の取り消し。
    pub fn revoke(&mut self, key_id: &KeyId) -> Result<ShareEvent, ShareError> {
        if self.recipients.remove(key_id).is_none() {
            return Err(ShareError::RecipientNotFound);
        }

        Ok(ShareEvent::RecipientRevoked {
            content_id: self.content_id.clone(),
            key_id: key_id.clone(),
        })
    }

    /// 指定された受信者の情報を取得する。
    pub fn recipient(&self, key_id: &KeyId) -> Option<&ShareRecipient> {
        self.recipients.get(key_id)
    }

    /// 指定された受信者の権限一覧を取得する。
    pub fn permissions_of(&self, key_id: &KeyId) -> Option<&[Permission]> {
        self.recipients
            .get(key_id)
            .map(|r| r.permissions.as_slice())
    }

    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    pub fn recipients(&self) -> &HashMap<KeyId, ShareRecipient> {
        &self.recipients
    }

    pub fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid() -> ContentId {
        ContentId::new("test-content-id".into())
    }

    fn key_id(bytes: &[u8]) -> KeyId {
        KeyId::new(bytes.to_vec())
    }

    #[test]
    fn grant_read_adds_recipient() {
        let mut share = Share::new(cid());
        let kid = key_id(&[1, 2, 3]);

        let event = share
            .grant_read(kid.clone())
            .expect("grant_read should succeed");

        assert!(matches!(event, ShareEvent::RecipientGranted { .. }));
        let recipient = share.recipient(&kid).expect("recipient should exist");
        assert_eq!(recipient.key_id(), &kid);
        assert_eq!(recipient.permissions(), &[Permission::Read]);
    }

    #[test]
    fn grant_write_adds_recipient_with_write_permission() {
        let mut share = Share::new(cid());
        let kid = key_id(&[4, 5, 6]);

        let event = share
            .grant_write(kid.clone())
            .expect("grant_write should succeed");

        assert!(matches!(event, ShareEvent::RecipientGranted { .. }));
        let recipient = share.recipient(&kid).expect("recipient should exist");
        assert_eq!(recipient.permissions(), &[Permission::Write]);
        assert!(Permission::can_read(recipient.permissions()));
        assert!(Permission::can_write(recipient.permissions()));
    }

    #[test]
    fn double_grant_returns_error() {
        let mut share = Share::new(cid());
        let kid = key_id(&[7, 8, 9]);

        share
            .grant_read(kid.clone())
            .expect("first grant should succeed");
        let err = share
            .grant_read(kid.clone())
            .expect_err("second grant should fail");

        assert!(matches!(err, ShareError::AlreadyShared));
    }

    #[test]
    fn revoke_removes_recipient() {
        let mut share = Share::new(cid());
        let kid = key_id(&[10, 11, 12]);

        share
            .grant_read(kid.clone())
            .expect("grant_read should succeed");
        let event = share.revoke(&kid).expect("revoke should succeed");

        assert!(matches!(event, ShareEvent::RecipientRevoked { .. }));
        assert!(share.recipient(&kid).is_none());
        assert!(share.is_empty());
    }

    #[test]
    fn revoke_unknown_recipient_returns_error() {
        let mut share = Share::new(cid());
        let kid = key_id(&[1, 1, 1]);

        let err = share.revoke(&kid).expect_err("revoke should fail");
        assert!(matches!(err, ShareError::RecipientNotFound));
    }
}
