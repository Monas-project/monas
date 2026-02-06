//! Value objects for the state node domain.
//!
//! Value objects ensure domain invariants are maintained at the type level.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Content identifier (CID).
///
/// This value object ensures that content IDs are never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(String);

impl ContentId {
    /// Create a new ContentId.
    ///
    /// Returns an error if the CID is empty.
    pub fn new(cid: String) -> Result<Self, ValueError> {
        if cid.is_empty() {
            return Err(ValueError::EmptyContentId);
        }
        // Additional CID format validation could be added here
        Ok(Self(cid))
    }

    /// Get the CID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwrap the inner string (for cases where ownership is needed).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ContentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Node identifier.
///
/// This value object ensures that node IDs are never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Create a new NodeId.
    ///
    /// Returns an error if the node ID is empty.
    pub fn new(id: String) -> Result<Self, ValueError> {
        if id.is_empty() {
            return Err(ValueError::EmptyNodeId);
        }
        Ok(Self(id))
    }

    /// Get the node ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwrap the inner string (for cases where ownership is needed).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for NodeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Non-empty set of values.
///
/// This value object ensures that a set always contains at least one element,
/// which is important for content networks that must have at least one member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonEmptySet<T: Ord> {
    first: T,
    rest: BTreeSet<T>,
}

impl<T: Ord + Clone> NonEmptySet<T> {
    /// Create a new non-empty set with a single element.
    pub fn new(first: T) -> Self {
        Self {
            first,
            rest: BTreeSet::new(),
        }
    }

    /// Create a non-empty set from an iterator.
    ///
    /// Returns `None` if the iterator is empty.
    pub fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Option<Self> {
        let mut iter = iter.into_iter();
        let first = iter.next()?;
        let rest = iter.collect();
        Some(Self { first, rest })
    }

    /// Insert a value into the set.
    ///
    /// Returns `true` if the value was inserted (not already present),
    /// `false` if it was already present.
    pub fn insert(&mut self, value: T) -> bool {
        if value == self.first {
            false
        } else {
            self.rest.insert(value)
        }
    }

    /// Remove a value from the set.
    ///
    /// Returns `None` if removing the value would make the set empty.
    /// Returns `Some(removed)` with the removed value if successful.
    pub fn remove(&mut self, value: &T) -> Option<T>
    where
        T: PartialEq,
    {
        if value == &self.first {
            // Try to move an element from rest to first
            if let Some(new_first) = self.rest.iter().next().cloned() {
                self.rest.remove(&new_first);
                let old_first = std::mem::replace(&mut self.first, new_first);
                Some(old_first)
            } else {
                // Cannot remove the last element
                None
            }
        } else {
            self.rest.remove(value).then_some(value.clone())
        }
    }

    /// Check if the set contains a value.
    pub fn contains(&self, value: &T) -> bool {
        &self.first == value || self.rest.contains(value)
    }

    /// Get the number of elements in the set.
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Check if the set is empty.
    ///
    /// Always returns `false` since this is a non-empty set by design.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Iterate over all elements in the set.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }

    /// Get the first element (guaranteed to exist).
    pub fn first(&self) -> &T {
        &self.first
    }

    /// Convert to a Vec.
    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    /// Convert to a BTreeSet (loses the non-empty guarantee).
    pub fn to_btreeset(&self) -> BTreeSet<T> {
        let mut set = self.rest.clone();
        set.insert(self.first.clone());
        set
    }
}

impl<T: Ord> PartialEq for NonEmptySet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first && self.rest == other.rest
    }
}

impl<T: Ord> Eq for NonEmptySet<T> {}

/// Value object errors.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("Content ID cannot be empty")]
    EmptyContentId,

    #[error("Node ID cannot be empty")]
    EmptyNodeId,

    #[error("Invalid CID format: {0}")]
    InvalidCidFormat(String),

    #[error("Invalid node ID format: {0}")]
    InvalidNodeIdFormat(String),

    #[error("Member nodes cannot be empty")]
    EmptyMemberNodes,

    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),

    #[error("Node is not a member of the content network")]
    NodeNotMember,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_id_creation() {
        let cid = ContentId::new("QmTest123".to_string()).unwrap();
        assert_eq!(cid.as_str(), "QmTest123");
        assert_eq!(cid.to_string(), "QmTest123");
    }

    #[test]
    fn test_content_id_empty() {
        let result = ContentId::new("".to_string());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValueError::EmptyContentId));
    }

    #[test]
    fn test_node_id_creation() {
        let node_id = NodeId::new("node-1".to_string()).unwrap();
        assert_eq!(node_id.as_str(), "node-1");
        assert_eq!(node_id.to_string(), "node-1");
    }

    #[test]
    fn test_node_id_empty() {
        let result = NodeId::new("".to_string());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValueError::EmptyNodeId));
    }

    #[test]
    fn test_non_empty_set_creation() {
        let set = NonEmptySet::new("a".to_string());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&"a".to_string()));
    }

    #[test]
    fn test_non_empty_set_insert() {
        let mut set = NonEmptySet::new("a".to_string());
        assert!(set.insert("b".to_string()));
        assert!(!set.insert("a".to_string())); // Duplicate
        assert_eq!(set.len(), 2);
        assert!(set.contains(&"a".to_string()));
        assert!(set.contains(&"b".to_string()));
    }

    #[test]
    fn test_non_empty_set_remove() {
        let mut set = NonEmptySet::new("a".to_string());
        set.insert("b".to_string());
        set.insert("c".to_string());

        // Remove from rest
        assert!(set.remove(&"b".to_string()).is_some());
        assert_eq!(set.len(), 2);
        assert!(!set.contains(&"b".to_string()));

        // Remove first
        assert!(set.remove(&"a".to_string()).is_some());
        assert_eq!(set.len(), 1);
        assert!(!set.contains(&"a".to_string()));
        assert!(set.contains(&"c".to_string()));

        // Cannot remove the last element
        assert!(set.remove(&"c".to_string()).is_none());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_non_empty_set_from_iter() {
        let set = NonEmptySet::try_from_iter(vec!["a", "b", "c"]).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&"a"));
        assert!(set.contains(&"b"));
        assert!(set.contains(&"c"));
    }

    #[test]
    fn test_non_empty_set_from_empty_iter() {
        let set = NonEmptySet::<String>::try_from_iter(vec![]);
        assert!(set.is_none());
    }

    #[test]
    fn test_non_empty_set_iter() {
        let mut set = NonEmptySet::new(1);
        set.insert(2);
        set.insert(3);

        let collected: Vec<_> = set.iter().cloned().collect();
        assert_eq!(collected.len(), 3);
        assert!(collected.contains(&1));
        assert!(collected.contains(&2));
        assert!(collected.contains(&3));
    }

    #[test]
    fn test_non_empty_set_to_vec() {
        let mut set = NonEmptySet::new(1);
        set.insert(2);
        set.insert(3);

        let vec = set.to_vec();
        assert_eq!(vec.len(), 3);
        assert!(vec.contains(&1));
        assert!(vec.contains(&2));
        assert!(vec.contains(&3));
    }

    #[test]
    fn test_non_empty_set_to_btreeset() {
        let mut set = NonEmptySet::new(1);
        set.insert(2);
        set.insert(3);

        let btree = set.to_btreeset();
        assert_eq!(btree.len(), 3);
        assert!(btree.contains(&1));
        assert!(btree.contains(&2));
        assert!(btree.contains(&3));
    }

    #[test]
    fn test_content_id_serialization() {
        let cid = ContentId::new("QmTest123".to_string()).unwrap();
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(json, "\"QmTest123\"");

        let deserialized: ContentId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, cid);
    }

    #[test]
    fn test_node_id_serialization() {
        let node_id = NodeId::new("node-1".to_string()).unwrap();
        let json = serde_json::to_string(&node_id).unwrap();
        assert_eq!(json, "\"node-1\"");

        let deserialized: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, node_id);
    }

    #[test]
    fn test_non_empty_set_serialization() {
        let mut set = NonEmptySet::new("a".to_string());
        set.insert("b".to_string());
        set.insert("c".to_string());

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: NonEmptySet<String> = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.len(), set.len());
        assert!(deserialized.contains(&"a".to_string()));
        assert!(deserialized.contains(&"b".to_string()));
        assert!(deserialized.contains(&"c".to_string()));
    }
}
