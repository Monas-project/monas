use std::collections::HashMap;

use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// コンテンツに対するアクセス権限。
///
/// - `Write` は常に `Read` を内包するものとして扱う。
/// - `Owner` は `Read` と `Write` を内包し、権限管理が可能。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Read,
    Write,
    Owner,
}

impl Permission {
    /// 読み取り可能かを判定するヘルパ。
    pub fn can_read(perms: &[Permission]) -> bool {
        perms
            .iter()
            .any(|p| matches!(p, Permission::Read | Permission::Write | Permission::Owner))
    }

    /// 書き込み可能かを判定するヘルパ。
    pub fn can_write(perms: &[Permission]) -> bool {
        perms
            .iter()
            .any(|p| matches!(p, Permission::Write | Permission::Owner))
    }

    /// 権限管理可能かを判定するヘルパ（Owner権限のみ）。
    pub fn can_manage_permissions(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(p, Permission::Owner))
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

    /// 同一の受信者リスト（ACL）を保ったまま、紐づく `content_id` を差し替えた Share を生成する。
    pub fn with_new_content_id(&self, new_content_id: ContentId) -> Self {
        Self {
            content_id: new_content_id,
            recipients: self.recipients.clone(),
        }
    }

    pub fn recipients(&self) -> &HashMap<KeyId, ShareRecipient> {
        &self.recipients
    }

    pub fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }

    /// Owner権限を付与。
    ///
    /// - 既にOwner権限を持つユーザが存在する場合は `InvalidOperation` を返す。
    pub fn grant_owner(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        // 既にOwner権限を持つユーザが存在するか確認
        if self.owner_key_id().is_some() {
            return Err(ShareError::InvalidOperation(
                "Owner already exists".to_string(),
            ));
        }

        // ShareRecipientにOwner権限を追加
        if let Some(recipient) = self.recipients.get_mut(&key_id) {
            // 既存のShareRecipientにOwner権限を追加
            if !recipient.permissions().contains(&Permission::Owner) {
                let mut perms = recipient.permissions().to_vec();
                perms.push(Permission::Owner);
                recipient.update_permissions(perms);
            }
        } else {
            // 新しいShareRecipientを作成してOwner権限を付与
            let recipient = ShareRecipient::new(key_id.clone(), vec![Permission::Owner]);
            self.recipients.insert(key_id.clone(), recipient);
        }

        Ok(ShareEvent::RecipientGranted {
            content_id: self.content_id.clone(),
            key_id,
            permissions: vec![Permission::Owner],
        })
    }

    /// Owner権限を持つKeyIdを取得（ShareRecipientから導出）。
    pub fn owner_key_id(&self) -> Option<&KeyId> {
        self.recipients
            .iter()
            .find(|(_, recipient)| Permission::can_manage_permissions(recipient.permissions()))
            .map(|(key_id, _)| key_id)
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

    #[test]
    fn permission_can_read_includes_owner() {
        assert!(Permission::can_read(&[Permission::Owner]));
        assert!(Permission::can_read(&[Permission::Read]));
        assert!(Permission::can_read(&[Permission::Write]));
        assert!(!Permission::can_read(&[]));
    }

    #[test]
    fn permission_can_write_includes_owner() {
        assert!(Permission::can_write(&[Permission::Owner]));
        assert!(!Permission::can_write(&[Permission::Read]));
        assert!(Permission::can_write(&[Permission::Write]));
        assert!(!Permission::can_write(&[]));
    }

    #[test]
    fn permission_can_manage_permissions_only_owner() {
        assert!(Permission::can_manage_permissions(&[Permission::Owner]));
        assert!(!Permission::can_manage_permissions(&[Permission::Read]));
        assert!(!Permission::can_manage_permissions(&[Permission::Write]));
        assert!(!Permission::can_manage_permissions(&[]));
    }

    #[test]
    fn grant_owner_adds_recipient() {
        let mut share = Share::new(cid());
        let kid = key_id(&[1, 2, 3]);

        let event = share
            .grant_owner(kid.clone())
            .expect("grant_owner should succeed");

        assert!(matches!(event, ShareEvent::RecipientGranted { .. }));
        let recipient = share.recipient(&kid).expect("recipient should exist");
        assert_eq!(recipient.key_id(), &kid);
        assert!(recipient.permissions().contains(&Permission::Owner));
        assert!(Permission::can_manage_permissions(recipient.permissions()));
    }

    #[test]
    fn grant_owner_when_owner_exists_returns_error() {
        let mut share = Share::new(cid());
        let kid1 = key_id(&[1, 2, 3]);
        let kid2 = key_id(&[4, 5, 6]);

        share
            .grant_owner(kid1.clone())
            .expect("first grant_owner should succeed");
        let err = share
            .grant_owner(kid2.clone())
            .expect_err("second grant_owner should fail");

        assert!(matches!(err, ShareError::InvalidOperation(_)));
    }

    #[test]
    fn owner_key_id_returns_correct_key_id() {
        let mut share = Share::new(cid());
        let kid = key_id(&[1, 2, 3]);

        assert!(share.owner_key_id().is_none());

        share
            .grant_owner(kid.clone())
            .expect("grant_owner should succeed");

        assert_eq!(share.owner_key_id(), Some(&kid));
    }

    #[test]
    fn owner_key_id_returns_none_when_no_owner() {
        let share = Share::new(cid());
        assert!(share.owner_key_id().is_none());
    }
}
