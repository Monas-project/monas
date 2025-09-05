use crate::application_service::state_node_service::PeerNetwork;

pub struct Libp2pNetwork;

impl Libp2pNetwork {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }
}

impl PeerNetwork for Libp2pNetwork {
    fn query_node_capacity(&self, _node_id: &str) -> Option<u64> {
        None
    }
    fn query_assignable_cids(&self, _capacity: u64) -> Vec<String> {
        Vec::new()
    }
}
