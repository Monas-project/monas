use crate::domain::content_network::{self, ContentNetwork};
use crate::domain::events::Event;
use crate::domain::state_node::{self, AssignmentRequest, AssignmentResponse, NodeSnapshot};
use std::collections::{BTreeSet, HashMap};

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

#[derive(Default)]
pub struct InMemoryContentDirectory {
    pub cids_by_required_capacity: Vec<(u64, String)>,
    pub networks: HashMap<String, ContentNetwork>,
}
impl ContentNetworkRepository for InMemoryContentDirectory {
    fn find_assignable_cids(&self, capacity: u64) -> Vec<String> {
        self.cids_by_required_capacity
            .iter()
            .filter(|(need, _)| *need <= capacity)
            .map(|(_, cid)| cid.clone())
            .collect()
    }
    fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork> {
        self.networks.get(content_id).cloned()
    }
    fn save_content_network(&mut self, net: ContentNetwork) {
        self.networks.insert(net.content_id.clone(), net);
    }
}

pub fn register_node(
    directory: &mut dyn NodeRegistry,
    node_id: String,
    total_capacity: u64,
) -> (NodeSnapshot, Vec<Event>) {
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
    let capacity = node_registry
        .get_available_capacity(&request.requesting_node_id)
        .or_else(|| peer_network.and_then(|n| n.query_node_capacity(&request.requesting_node_id)))
        .unwrap_or(request.available_capacity);

    let mut candidate_cids = content_repo.find_assignable_cids(capacity);
    if candidate_cids.is_empty() {
        if let Some(net) = peer_network {
            candidate_cids = net.query_assignable_cids(capacity);
        }
    }
    let (response, events) =
        state_node::decide_assignment(assigning_node_id, &request, &candidate_cids);
    (request, response, events)
}

pub fn add_member_node(
    content_repo: &mut dyn ContentNetworkRepository,
    content_id: &str,
    added_node_id: &str,
) -> Vec<Event> {
    let base = content_repo
        .get_content_network(content_id)
        .unwrap_or_else(|| ContentNetwork {
            content_id: content_id.to_string(),
            member_nodes: BTreeSet::new(),
        });
    let (updated, events) = content_network::add_member_node(base, added_node_id.to_string());
    content_repo.save_content_network(updated);
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::content_network_repository::ContentNetworkRepositoryImpl;
    use crate::infrastructure::node_repository::NodeRegistryImpl;

    struct StubPeerNetwork {
        capacity: Option<u64>,
        cids: Vec<String>,
    }

    impl PeerNetwork for StubPeerNetwork {
        fn query_node_capacity(&self, _node_id: &str) -> Option<u64> {
            self.capacity
        }
        fn query_assignable_cids(&self, _capacity: u64) -> Vec<String> {
            self.cids.clone()
        }
    }

    #[test]
    fn register_node_returns_snapshot_and_event() {
        let mut nodes = NodeRegistryImpl::default();
        let (snapshot, events) = register_node(&mut nodes, "node-A".into(), 1_000);

        assert_eq!(snapshot.node_id, "node-A");
        assert_eq!(snapshot.total_capacity, 1_000);
        assert_eq!(snapshot.available_capacity, 1_000);
        assert_eq!(events.len(), 1);
        // NodeRegistry should store the node
        assert_eq!(nodes.get_available_capacity("node-A"), Some(1_000));
    }

    #[test]
    fn handle_assignment_request_uses_repo_candidates() {
        let mut nodes = NodeRegistryImpl::default();
        let (a, _) = register_node(&mut nodes, "node-A".into(), 800);

        // prepare contents repo with one candidate that fits
        let mut contents = ContentNetworkRepositoryImpl::default();
        contents
            .cids_by_required_capacity
            .push((500, "cid-1".to_string()));

        let (_req, resp, events) = handle_assignment_request(&nodes, &contents, None, "node-B", &a);

        assert!(resp.assigned_content_network.is_some());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn handle_assignment_request_falls_back_to_peer_network() {
        let mut nodes = NodeRegistryImpl::default();
        let (a, _) = register_node(&mut nodes, "node-A".into(), 400);

        // empty local repo forces fallback
        let contents = ContentNetworkRepositoryImpl::default();
        let peer = StubPeerNetwork {
            capacity: Some(400),
            cids: vec!["cid-x".into()],
        };

        let (_req, resp, events) =
            handle_assignment_request(&nodes, &contents, Some(&peer), "node-B", &a);

        assert!(resp.assigned_content_network.is_some());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn add_member_node_updates_repo_and_emits_event() {
        let mut contents = ContentNetworkRepositoryImpl::default();
        let events = add_member_node(&mut contents, "cid-2", "node-A");

        assert_eq!(events.len(), 1);
        let net = contents
            .get_content_network("cid-2")
            .expect("network saved");
        assert!(net.member_nodes.contains("node-A"));
    }
}
