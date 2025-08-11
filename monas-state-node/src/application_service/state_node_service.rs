use std::collections::{BTreeSet, HashMap};
use crate::domain::events::Event;
use crate::domain::state_node::{self, AssignmentRequest, AssignmentResponse, NodeSnapshot};
use crate::domain::content_network::{self, ContentNetwork};

pub trait NodeRegistry {
    fn upsert_node(&mut self, node: &NodeSnapshot);
    fn get_available_capacity(&self, node_id: &str) -> Option<u64>;
}
pub trait ContentNetworkRepository {
    fn find_assignable_cids(&self, capacity: u64) -> Vec<String>;
    fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork>;
    fn save_content_network(&mut self, net: ContentNetwork);
}

pub trait PeerNetwork {
    fn query_node_capacity(&self, node_id: &str) -> Option<u64>;
    fn query_assignable_cids(&self, capacity: u64) -> Vec<String>;
}

// 具体実装は infrastructure 層へ。ここではポートのみ定義します。

#[derive(Default)]
pub struct InMemoryContentDirectory {
    pub cids_by_required_capacity: Vec<(u64, String)>,
    pub networks: HashMap<String, ContentNetwork>,
}
impl ContentNetworkRepository for InMemoryContentDirectory {
    fn find_assignable_cids(&self, capacity: u64) -> Vec<String> {
        self.cids_by_required_capacity.iter().filter(|(need, _)| *need <= capacity).map(|(_, cid)| cid.clone()).collect()
    }
    fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork> { self.networks.get(content_id).cloned() }
    fn save_content_network(&mut self, net: ContentNetwork) { self.networks.insert(net.content_id.clone(), net); }
}

pub fn register_node(directory: &mut dyn NodeRegistry, node_id: String, total_capacity: u64) -> (NodeSnapshot, Vec<Event>) {
    let (snapshot, events) = state_node::create_node(node_id, total_capacity);
    directory.upsert_node(&snapshot);
    (snapshot, events)
}

pub fn handle_assignment_request(
    node_registry: &dyn NodeRegistry,
    content_repo: &dyn ContentNetworkRepository,
    peer_network: Option<&dyn PeerNetwork>,
    assigning_node_id: &str,
    requesting_node: &NodeSnapshot,
) -> (AssignmentRequest, AssignmentResponse, Vec<Event>) {
    let request: AssignmentRequest = state_node::build_assignment_request(requesting_node);
    let a_capacity = node_registry
        .get_available_capacity(&request.requesting_node_id)
        .or_else(|| peer_network.and_then(|n| n.query_node_capacity(&request.requesting_node_id)))
        .unwrap_or(request.available_capacity);

    let mut candidate_cids = content_repo.find_assignable_cids(a_capacity);
    if candidate_cids.is_empty() {
        if let Some(net) = peer_network { candidate_cids = net.query_assignable_cids(a_capacity); }
    }
    let (response, events) = state_node::decide_assignment(assigning_node_id, &request, &candidate_cids);
    (request, response, events)
}

pub fn add_manager(content_repo: &mut dyn ContentNetworkRepository, content_id: &str, added_node_id: &str) -> Vec<Event> {
    let base = content_repo.get_content_network(content_id).unwrap_or_else(|| ContentNetwork { content_id: content_id.to_string(), managing_nodes: BTreeSet::new() });
    let (updated, events) = content_network::add_manager(base, added_node_id.to_string());
    content_repo.save_content_network(updated);
    events
}


