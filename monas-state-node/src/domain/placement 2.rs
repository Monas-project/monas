//! Content placement strategy for the state node system.
//!
//! This module contains business logic for selecting member nodes for content networks.

use serde::{Deserialize, Serialize};

/// A candidate node for content placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCandidate {
    pub peer_id: String,
    pub available_capacity: u64,
}

/// Placement policy for content networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicy {
    /// Minimum number of member nodes required.
    pub min_members: usize,
    /// Preferred (target) number of member nodes.
    pub preferred_members: usize,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            min_members: 1,
            preferred_members: 3,
        }
    }
}

/// Select member nodes from candidates based on placement policy.
///
/// This function implements the business logic for node selection:
/// - Excludes nodes in the `exclude` list (e.g., the creator)
/// - Sorts candidates by available capacity (highest first)
/// - Selects up to `preferred_members` nodes
/// - Returns an error if fewer than `min_members` are available
///
/// # Arguments
/// * `candidates` - List of candidate nodes with their available capacity
/// * `exclude` - List of node IDs to exclude from selection
/// * `policy` - Placement policy defining member requirements
///
/// # Returns
/// * `Ok(Vec<String>)` - List of selected node IDs
/// * `Err(PlacementError)` - If insufficient nodes are available
pub fn select_member_nodes(
    candidates: &[NodeCandidate],
    exclude: &[String],
    policy: &PlacementPolicy,
) -> Result<Vec<String>, PlacementError> {
    // Filter and score candidates
    let mut scored: Vec<(u64, String)> = candidates
        .iter()
        .filter(|c| !exclude.contains(&c.peer_id))
        .map(|c| (c.available_capacity, c.peer_id.clone()))
        .collect();

    // Sort by capacity (highest first)
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    // Select up to preferred_members
    let selected: Vec<String> = scored
        .into_iter()
        .take(policy.preferred_members)
        .map(|(_, id)| id)
        .collect();

    // Validate minimum requirement
    if selected.len() < policy.min_members {
        return Err(PlacementError::InsufficientNodes {
            required: policy.min_members,
            found: selected.len(),
        });
    }

    Ok(selected)
}

/// Errors that can occur during content placement.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlacementError {
    #[error("Insufficient nodes: required {required}, found {found}")]
    InsufficientNodes { required: usize, found: usize },

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_candidate(peer_id: &str, capacity: u64) -> NodeCandidate {
        NodeCandidate {
            peer_id: peer_id.to_string(),
            available_capacity: capacity,
        }
    }

    #[test]
    fn test_select_member_nodes_success() {
        let candidates = vec![
            create_candidate("node-1", 1000),
            create_candidate("node-2", 500),
            create_candidate("node-3", 1500),
        ];

        let policy = PlacementPolicy {
            min_members: 2,
            preferred_members: 3,
        };

        let result = select_member_nodes(&candidates, &[], &policy).unwrap();

        assert_eq!(result.len(), 3);
        // Should be sorted by capacity: node-3 (1500), node-1 (1000), node-2 (500)
        assert_eq!(result[0], "node-3");
        assert_eq!(result[1], "node-1");
        assert_eq!(result[2], "node-2");
    }

    #[test]
    fn test_select_member_nodes_with_exclusion() {
        let candidates = vec![
            create_candidate("node-1", 1000),
            create_candidate("node-2", 500),
            create_candidate("node-3", 1500),
        ];

        let policy = PlacementPolicy {
            min_members: 1,
            preferred_members: 3,
        };

        let exclude = vec!["node-1".to_string()];
        let result = select_member_nodes(&candidates, &exclude, &policy).unwrap();

        assert_eq!(result.len(), 2);
        assert!(!result.contains(&"node-1".to_string()));
        assert!(result.contains(&"node-2".to_string()));
        assert!(result.contains(&"node-3".to_string()));
    }

    #[test]
    fn test_select_member_nodes_insufficient() {
        let candidates = vec![
            create_candidate("node-1", 1000),
            create_candidate("node-2", 500),
        ];

        let policy = PlacementPolicy {
            min_members: 3,
            preferred_members: 5,
        };

        let result = select_member_nodes(&candidates, &[], &policy);

        assert!(result.is_err());
        match result.unwrap_err() {
            PlacementError::InsufficientNodes { required, found } => {
                assert_eq!(required, 3);
                assert_eq!(found, 2);
            }
            _ => panic!("Expected InsufficientNodes error"),
        }
    }

    #[test]
    fn test_select_member_nodes_all_excluded() {
        let candidates = vec![
            create_candidate("node-1", 1000),
            create_candidate("node-2", 500),
        ];

        let policy = PlacementPolicy {
            min_members: 1,
            preferred_members: 3,
        };

        let exclude = vec!["node-1".to_string(), "node-2".to_string()];
        let result = select_member_nodes(&candidates, &exclude, &policy);

        assert!(result.is_err());
        match result.unwrap_err() {
            PlacementError::InsufficientNodes { required, found } => {
                assert_eq!(required, 1);
                assert_eq!(found, 0);
            }
            _ => panic!("Expected InsufficientNodes error"),
        }
    }

    #[test]
    fn test_select_member_nodes_respects_preferred_limit() {
        let candidates = vec![
            create_candidate("node-1", 1000),
            create_candidate("node-2", 500),
            create_candidate("node-3", 1500),
            create_candidate("node-4", 800),
            create_candidate("node-5", 1200),
        ];

        let policy = PlacementPolicy {
            min_members: 1,
            preferred_members: 3,
        };

        let result = select_member_nodes(&candidates, &[], &policy).unwrap();

        // Should select exactly preferred_members (3) nodes
        assert_eq!(result.len(), 3);
        // Should be the top 3 by capacity
        assert!(result.contains(&"node-3".to_string())); // 1500
        assert!(result.contains(&"node-5".to_string())); // 1200
        assert!(result.contains(&"node-1".to_string())); // 1000
    }

    #[test]
    fn test_placement_policy_default() {
        let policy = PlacementPolicy::default();
        assert_eq!(policy.min_members, 1);
        assert_eq!(policy.preferred_members, 3);
    }

    #[test]
    fn test_node_candidate_equality() {
        let c1 = create_candidate("node-1", 1000);
        let c2 = create_candidate("node-1", 1000);
        let c3 = create_candidate("node-2", 1000);

        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_select_member_nodes_empty_candidates() {
        let candidates: Vec<NodeCandidate> = vec![];

        let policy = PlacementPolicy {
            min_members: 1,
            preferred_members: 3,
        };

        let result = select_member_nodes(&candidates, &[], &policy);

        assert!(result.is_err());
        match result.unwrap_err() {
            PlacementError::InsufficientNodes { required, found } => {
                assert_eq!(required, 1);
                assert_eq!(found, 0);
            }
            _ => panic!("Expected InsufficientNodes error"),
        }
    }

    #[test]
    fn test_select_member_nodes_with_zero_capacity() {
        let candidates = vec![
            create_candidate("node-1", 0),
            create_candidate("node-2", 500),
            create_candidate("node-3", 0),
        ];

        let policy = PlacementPolicy {
            min_members: 1,
            preferred_members: 3,
        };

        let result = select_member_nodes(&candidates, &[], &policy).unwrap();

        // Should still select all nodes, sorted by capacity
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "node-2"); // 500
                                         // node-1 and node-3 have 0 capacity, order between them is stable
    }
}
