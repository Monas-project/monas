use serde::{Deserialize, Serialize};
use super::events::{Event, current_timestamp};

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


