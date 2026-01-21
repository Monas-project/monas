//! Authentication and authorization capability types.
//!
//! This module defines capabilities for the State Node domain's access control.
//! These represent what an identity can do with content.
//! The mapping to external authorization systems (UCAN, RBAC, etc.)
//! is handled by the infrastructure layer.

use serde::{Deserialize, Serialize};

/// Capabilities in the State Node domain
///
/// These represent what an identity can do with content.
/// The mapping to external authorization systems (UCAN, RBAC, etc.)
/// is handled by the infrastructure layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthCapability {
    /// Read content data
    ReadContent,

    /// Write/update content data
    WriteContent,

    /// Delete content
    DeleteContent,

    /// Manage content network membership
    ManageMembers,

    /// Share content with others (delegate capabilities)
    ShareContent,

    /// Revoke access from others
    RevokeAccess,

    /// Read content metadata (without reading the actual data)
    ReadMetadata,
}

impl AuthCapability {
    /// Check if this capability implies another capability
    ///
    /// Capability hierarchy:
    /// - WriteContent → ReadContent
    /// - DeleteContent → WriteContent, ReadContent
    /// - ManageMembers → ReadMetadata
    /// - ShareContent → ReadContent
    pub fn implies(&self, other: &AuthCapability) -> bool {
        match (self, other) {
            // WriteContent implies ReadContent
            (AuthCapability::WriteContent, AuthCapability::ReadContent) => true,

            // DeleteContent implies WriteContent and ReadContent
            (AuthCapability::DeleteContent, AuthCapability::WriteContent) => true,
            (AuthCapability::DeleteContent, AuthCapability::ReadContent) => true,

            // ManageMembers implies ReadMetadata
            (AuthCapability::ManageMembers, AuthCapability::ReadMetadata) => true,

            // ShareContent implies ReadContent (you can only share what you can read)
            (AuthCapability::ShareContent, AuthCapability::ReadContent) => true,

            // RevokeAccess implies ShareContent (if you can revoke, you can share)
            (AuthCapability::RevokeAccess, AuthCapability::ShareContent) => true,
            (AuthCapability::RevokeAccess, AuthCapability::ReadContent) => true,

            // Same capability implies itself
            (a, b) if a == b => true,

            _ => false,
        }
    }

    /// Get all capabilities implied by this one (transitive closure)
    pub fn implied_capabilities(&self) -> Vec<AuthCapability> {
        match self {
            AuthCapability::ReadContent => vec![],
            AuthCapability::WriteContent => vec![AuthCapability::ReadContent],
            AuthCapability::DeleteContent => {
                vec![AuthCapability::WriteContent, AuthCapability::ReadContent]
            }
            AuthCapability::ManageMembers => vec![AuthCapability::ReadMetadata],
            AuthCapability::ShareContent => vec![AuthCapability::ReadContent],
            AuthCapability::RevokeAccess => {
                vec![AuthCapability::ShareContent, AuthCapability::ReadContent]
            }
            AuthCapability::ReadMetadata => vec![],
        }
    }

    /// Get all capabilities for owner role
    pub fn owner_capabilities() -> Vec<AuthCapability> {
        vec![
            AuthCapability::ReadContent,
            AuthCapability::WriteContent,
            AuthCapability::DeleteContent,
            AuthCapability::ManageMembers,
            AuthCapability::ShareContent,
            AuthCapability::RevokeAccess,
            AuthCapability::ReadMetadata,
        ]
    }

    /// Get all capabilities for editor role
    pub fn editor_capabilities() -> Vec<AuthCapability> {
        vec![
            AuthCapability::ReadContent,
            AuthCapability::WriteContent,
            AuthCapability::ReadMetadata,
        ]
    }

    /// Get all capabilities for viewer role
    pub fn viewer_capabilities() -> Vec<AuthCapability> {
        vec![AuthCapability::ReadContent, AuthCapability::ReadMetadata]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_implies() {
        assert!(AuthCapability::WriteContent.implies(&AuthCapability::ReadContent));
        assert!(AuthCapability::DeleteContent.implies(&AuthCapability::WriteContent));
        assert!(AuthCapability::DeleteContent.implies(&AuthCapability::ReadContent));
        assert!(!AuthCapability::ReadContent.implies(&AuthCapability::WriteContent));
        assert!(AuthCapability::ManageMembers.implies(&AuthCapability::ReadMetadata));
        assert!(AuthCapability::ShareContent.implies(&AuthCapability::ReadContent));
    }

    #[test]
    fn test_implied_capabilities() {
        let implied = AuthCapability::WriteContent.implied_capabilities();
        assert_eq!(implied.len(), 1);
        assert!(implied.contains(&AuthCapability::ReadContent));

        let implied = AuthCapability::DeleteContent.implied_capabilities();
        assert_eq!(implied.len(), 2);
        assert!(implied.contains(&AuthCapability::WriteContent));
        assert!(implied.contains(&AuthCapability::ReadContent));
    }

    #[test]
    fn test_owner_capabilities() {
        let caps = AuthCapability::owner_capabilities();
        assert_eq!(caps.len(), 7);
        assert!(caps.contains(&AuthCapability::ReadContent));
        assert!(caps.contains(&AuthCapability::WriteContent));
        assert!(caps.contains(&AuthCapability::DeleteContent));
        assert!(caps.contains(&AuthCapability::ManageMembers));
        assert!(caps.contains(&AuthCapability::ShareContent));
        assert!(caps.contains(&AuthCapability::RevokeAccess));
        assert!(caps.contains(&AuthCapability::ReadMetadata));
    }

    #[test]
    fn test_editor_capabilities() {
        let caps = AuthCapability::editor_capabilities();
        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&AuthCapability::ReadContent));
        assert!(caps.contains(&AuthCapability::WriteContent));
        assert!(caps.contains(&AuthCapability::ReadMetadata));
    }

    #[test]
    fn test_viewer_capabilities() {
        let caps = AuthCapability::viewer_capabilities();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&AuthCapability::ReadContent));
        assert!(caps.contains(&AuthCapability::ReadMetadata));
    }

    #[test]
    fn test_self_implies() {
        assert!(AuthCapability::ReadContent.implies(&AuthCapability::ReadContent));
        assert!(AuthCapability::WriteContent.implies(&AuthCapability::WriteContent));
    }

    #[test]
    fn test_revoke_access_implications() {
        assert!(AuthCapability::RevokeAccess.implies(&AuthCapability::ShareContent));
        assert!(AuthCapability::RevokeAccess.implies(&AuthCapability::ReadContent));
    }
}
