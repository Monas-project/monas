use crate::application_service::state_node_service::ContentNetworkRepository;
use crate::domain::content_network::ContentNetwork;
use std::collections::HashMap;

#[derive(Default)]
pub struct ContentNetworkRepositoryImpl {
    pub cids_by_required_capacity: Vec<(u64, String)>,
    pub networks: HashMap<String, ContentNetwork>,
}

impl ContentNetworkRepository for ContentNetworkRepositoryImpl {
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


