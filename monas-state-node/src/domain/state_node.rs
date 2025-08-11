use super::events::{current_timestamp, Event};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub node_id: String,
    pub total_capacity: u64,
    pub available_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentRequest {
    pub requesting_node_id: String,
    pub available_capacity: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentResponse {
    pub assigned_content_network: Option<String>,
    pub assigning_node_id: String,
    pub timestamp: u64,
}

pub fn create_node(node_id: String, total_capacity: u64) -> (NodeSnapshot, Vec<Event>) {
    let snapshot = NodeSnapshot {
        node_id: node_id.clone(),
        total_capacity,
        available_capacity: total_capacity,
    };

    let events = vec![Event::NodeCreated {
        node_id,
        total_capacity,
        available_capacity: total_capacity,
        timestamp: current_timestamp(),
    }];

    (snapshot, events)
}

pub fn build_assignment_request(snapshot: &NodeSnapshot) -> AssignmentRequest {
    AssignmentRequest {
        requesting_node_id: snapshot.node_id.clone(),
        available_capacity: snapshot.available_capacity,
        timestamp: current_timestamp(),
    }
}

pub fn decide_assignment(
    assigning_node_id: &str,
    request: &AssignmentRequest,
    candidate_cids: &[String],
) -> (AssignmentResponse, Vec<Event>) {
    use rand::prelude::IndexedRandom;
    let chosen = {
        let mut rng = rand::rng();
        candidate_cids.choose(&mut rng).cloned()
    };

    let events = match &chosen {
        Some(cid) => vec![Event::AssignmentDecided {
            assigning_node_id: assigning_node_id.to_string(),
            assigned_node_id: request.requesting_node_id.clone(),
            content_id: cid.clone(),
            timestamp: current_timestamp(),
        }],
        None => vec![],
    };

    let response = AssignmentResponse {
        assigned_content_network: chosen.map(|cid| format!("cn::{}", cid)),
        assigning_node_id: assigning_node_id.to_string(),
        timestamp: current_timestamp(),
    };

    (response, events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_node_emits_event() {
        let (snap, events) = create_node("node-A".into(), 500);
        assert_eq!(snap.node_id, "node-A");
        assert_eq!(snap.total_capacity, 500);
        assert_eq!(snap.available_capacity, 500);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::NodeCreated {
                node_id,
                total_capacity,
                available_capacity,
                ..
            } => {
                assert_eq!(node_id, "node-A");
                assert_eq!(*total_capacity, 500);
                assert_eq!(*available_capacity, 500);
            }
            _ => panic!("expected NodeCreated"),
        }
    }

    #[test]
    fn build_assignment_request_uses_snapshot_values() {
        let (snap, _) = create_node("node-A".into(), 700);
        let req = build_assignment_request(&snap);
        assert_eq!(req.requesting_node_id, "node-A");
        assert_eq!(req.available_capacity, 700);
    }

    #[test]
    fn decide_assignment_with_single_candidate() {
        let (snap, _) = create_node("node-A".into(), 700);
        let req = build_assignment_request(&snap);
        let candidates = vec!["cid-1".to_string()];
        let (resp, events) = decide_assignment("node-B", &req, &candidates);
        assert_eq!(resp.assigning_node_id, "node-B");
        assert_eq!(resp.assigned_content_network, Some("cn::cid-1".to_string()));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::AssignmentDecided {
                assigning_node_id,
                assigned_node_id,
                content_id,
                ..
            } => {
                assert_eq!(assigning_node_id, "node-B");
                assert_eq!(assigned_node_id, "node-A");
                assert_eq!(content_id, "cid-1");
            }
            _ => panic!("expected AssignmentDecided"),
        }
    }
}
