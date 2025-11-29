//! In-memory content network repository implementation.
//!
//! This module provides a simple in-memory implementation for content network
//! management. For production use, see the sled-based implementation in
//! `persistence/sled_content_network_repository.rs`.

use crate::domain::content_network::ContentNetwork;
use std::collections::HashMap;

/// In-memory content network repository for testing and simple use cases.
#[derive(Default)]
pub struct ContentNetworkRepositoryImpl {
    pub cids_by_required_capacity: Vec<(u64, String)>,
    pub networks: HashMap<String, ContentNetwork>,
}

impl ContentNetworkRepositoryImpl {
    /// Find content IDs that can be assigned given the available capacity.
    pub fn find_assignable_cids(&self, capacity: u64) -> Vec<String> {
        self.cids_by_required_capacity
            .iter()
            .filter(|(need, _)| *need <= capacity)
            .map(|(_, cid)| cid.clone())
            .collect()
    }

    /// Get a content network by its content ID.
    pub fn get_content_network(&self, content_id: &str) -> Option<ContentNetwork> {
        self.networks.get(content_id).cloned()
    }

    /// Save a content network.
    pub fn save_content_network(&mut self, net: ContentNetwork) {
        self.networks.insert(net.content_id.clone(), net);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn find_assignable_and_roundtrip_network() {
        let mut repo = ContentNetworkRepositoryImpl::default();
        repo.cids_by_required_capacity.push((300, "cid-1".into()));
        let cids = repo.find_assignable_cids(400);
        assert_eq!(cids, vec!["cid-1".to_string()]);

        let net = ContentNetwork {
            content_id: "cid-1".into(),
            member_nodes: BTreeSet::new(),
        };
        repo.save_content_network(net);
        let got = repo.get_content_network("cid-1");
        assert!(got.is_some());
    }
}
