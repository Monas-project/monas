use std::collections::HashMap;

use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// Access permission on a content.
///
/// - `Write` is always treated as implying `Read`.
/// - `Owner` implies `Read` and `Write`, and can manage permissions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Read,
    Write,
    Owner,
}

impl Permission {
    /// Helper that checks whether reading is allowed.
    pub fn can_read(perms: &[Permission]) -> bool {
        perms
            .iter()
            .any(|p| matches!(p, Permission::Read | Permission::Write | Permission::Owner))
    }

    /// Helper that checks whether writing is allowed.
    pub fn can_write(perms: &[Permission]) -> bool {
        perms
            .iter()
            .any(|p| matches!(p, Permission::Write | Permission::Owner))
    }

    /// Helper that checks whether managing permissions is allowed (Owner permission only).
    pub fn can_manage_permissions(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(p, Permission::Owner))
    }
}

/// Share information for a single recipient.
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

/// Share state (ACL) for a single content.
///
/// - Supports serialization/deserialization via `serde`, so it can be stored as JSON in a KVS
///   such as sled.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Share {
    content_id: ContentId,
    /// key = KeyId
    recipients: HashMap<KeyId, ShareRecipient>,
    /// Key epoch of the CEK. Incremented by 1 on every rotation (re-encryption due to revoke).
    /// Carried in the KeyEnvelope and used by recipients as the basis for rejecting envelopes
    /// from older epochs (replay prevention).
    #[serde(default)]
    key_epoch: u64,
}

impl Share {
    /// Creates an empty Share for the given content_id.
    ///
    /// - Intended for the application layer to build one when no record exists in the DB.
    pub fn new(content_id: ContentId) -> Self {
        Self {
            content_id,
            recipients: HashMap::new(),
            key_epoch: 0,
        }
    }

    /// Current CEK key epoch.
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Advances the key epoch along with a CEK rotation (re-encryption).
    pub fn bump_key_epoch(&mut self) {
        self.key_epoch += 1;
    }

    /// Grants Read permission.
    ///
    /// - Returns `AlreadyShared` if a recipient with the same KeyId already exists.
    pub fn grant_read(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        self.grant_with_permissions(key_id, vec![Permission::Read])
    }

    /// Grants Write permission.
    ///
    /// - Since `Write` is assumed to imply `Read`, the domain holds only `Write`.
    /// - Returns `AlreadyShared` if a recipient with the same KeyId already exists.
    pub fn grant_write(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        self.grant_with_permissions(key_id, vec![Permission::Write])
    }

    /// Common permission-granting logic.
    ///
    /// - Returns `AlreadyShared` if a recipient with the same KeyId already exists.
    /// - Adds a new `ShareRecipient` and returns a `RecipientGranted` event.
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

    /// Revokes a share relationship.
    pub fn revoke(&mut self, key_id: &KeyId) -> Result<ShareEvent, ShareError> {
        if self.recipients.remove(key_id).is_none() {
            return Err(ShareError::RecipientNotFound);
        }

        Ok(ShareEvent::RecipientRevoked {
            content_id: self.content_id.clone(),
            key_id: key_id.clone(),
        })
    }

    /// Replaces the permissions of an existing recipient.
    ///
    /// - Returns `RecipientNotFound` if the recipient does not exist (granting is done via
    ///   `grant_*`).
    /// - Changes to or from Owner are not handled here (`InvalidOperation`).
    pub fn update_recipient_permissions(
        &mut self,
        key_id: &KeyId,
        permissions: Vec<Permission>,
    ) -> Result<(), ShareError> {
        if permissions.is_empty() || permissions.contains(&Permission::Owner) {
            return Err(ShareError::InvalidOperation(
                "recipient permissions must be read or write".to_string(),
            ));
        }
        let recipient = self
            .recipients
            .get_mut(key_id)
            .ok_or(ShareError::RecipientNotFound)?;
        if recipient.permissions.contains(&Permission::Owner) {
            return Err(ShareError::InvalidOperation(
                "owner permissions cannot be changed".to_string(),
            ));
        }
        recipient.update_permissions(permissions);
        Ok(())
    }

    /// Gets the information of the given recipient.
    pub fn recipient(&self, key_id: &KeyId) -> Option<&ShareRecipient> {
        self.recipients.get(key_id)
    }

    /// Gets the list of permissions of the given recipient.
    pub fn permissions_of(&self, key_id: &KeyId) -> Option<&[Permission]> {
        self.recipients
            .get(key_id)
            .map(|r| r.permissions.as_slice())
    }

    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// Creates a Share with the associated `content_id` replaced, keeping the same recipient
    /// list (ACL).
    pub fn with_new_content_id(&self, new_content_id: ContentId) -> Self {
        Self {
            content_id: new_content_id,
            recipients: self.recipients.clone(),
            key_epoch: self.key_epoch,
        }
    }

    pub fn recipients(&self) -> &HashMap<KeyId, ShareRecipient> {
        &self.recipients
    }

    pub fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }

    /// Grants Owner permission.
    ///
    /// - Returns `InvalidOperation` if a user with Owner permission already exists.
    pub fn grant_owner(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        // Check whether a user with Owner permission already exists
        if self.owner_key_id().is_some() {
            return Err(ShareError::InvalidOperation(
                "Owner already exists".to_string(),
            ));
        }

        // Add Owner permission to the ShareRecipient
        if let Some(recipient) = self.recipients.get_mut(&key_id) {
            // Add Owner permission to the existing ShareRecipient
            if !recipient.permissions().contains(&Permission::Owner) {
                let mut perms = recipient.permissions().to_vec();
                perms.push(Permission::Owner);
                recipient.update_permissions(perms);
            }
        } else {
            // Create a new ShareRecipient and grant it Owner permission
            let recipient = ShareRecipient::new(key_id.clone(), vec![Permission::Owner]);
            self.recipients.insert(key_id.clone(), recipient);
        }

        Ok(ShareEvent::RecipientGranted {
            content_id: self.content_id.clone(),
            key_id,
            permissions: vec![Permission::Owner],
        })
    }

    /// Gets the KeyId with Owner permission (derived from ShareRecipient).
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
    fn update_recipient_permissions_switches_read_and_write() {
        let mut share = Share::new(cid());
        let kid = key_id(&[2, 2, 2]);
        share.grant_read(kid.clone()).expect("grant_read");

        share
            .update_recipient_permissions(&kid, vec![Permission::Write])
            .expect("upgrade");
        assert_eq!(share.permissions_of(&kid), Some(&[Permission::Write][..]));

        share
            .update_recipient_permissions(&kid, vec![Permission::Read])
            .expect("downgrade");
        assert_eq!(share.permissions_of(&kid), Some(&[Permission::Read][..]));
    }

    #[test]
    fn update_recipient_permissions_rejects_unknown_owner_and_empty() {
        let mut share = Share::new(cid());
        let unknown = key_id(&[3, 3, 3]);
        assert!(matches!(
            share.update_recipient_permissions(&unknown, vec![Permission::Read]),
            Err(ShareError::RecipientNotFound)
        ));

        let kid = key_id(&[4, 4, 4]);
        share.grant_read(kid.clone()).expect("grant_read");
        assert!(matches!(
            share.update_recipient_permissions(&kid, vec![Permission::Owner]),
            Err(ShareError::InvalidOperation(_))
        ));
        assert!(matches!(
            share.update_recipient_permissions(&kid, vec![]),
            Err(ShareError::InvalidOperation(_))
        ));

        let owner = key_id(&[5, 5, 5]);
        share.grant_owner(owner.clone()).expect("grant_owner");
        assert!(matches!(
            share.update_recipient_permissions(&owner, vec![Permission::Read]),
            Err(ShareError::InvalidOperation(_))
        ));
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
