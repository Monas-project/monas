use super::state_node::{NetworkType, StorageResource};

#[derive(Debug, Clone, PartialEq)]
pub enum StateNodeEvent {
    ResourceVerified {
        node_id: String,
        resources: StorageResource,
        verified: bool,
    },
    RegisteredToUniversal {
        node_id: String,
        resources: StorageResource,
        timestamp: u64,
    },
    JoinedContentNetwork {
        node_id: String,
        content_id: String,
        timestamp: u64,
    },
    Synchronized {
        node_id: String,
        network: NetworkType,
        timestamp: u64,
    },
    LeftNetwork {
        node_id: String,
        network: NetworkType,
        timestamp: u64,
    },
    ResourceUpdated {
        node_id: String,
        old_resources: StorageResource,
        new_resources: StorageResource,
        timestamp: u64,
    },
}

impl StateNodeEvent {
    pub fn node_id(&self) -> &str {
        match self {
            StateNodeEvent::ResourceVerified { node_id, .. } => node_id,
            StateNodeEvent::RegisteredToUniversal { node_id, .. } => node_id,
            StateNodeEvent::JoinedContentNetwork { node_id, .. } => node_id,
            StateNodeEvent::Synchronized { node_id, .. } => node_id,
            StateNodeEvent::LeftNetwork { node_id, .. } => node_id,
            StateNodeEvent::ResourceUpdated { node_id, .. } => node_id,
        }
    }

    pub fn timestamp(&self) -> Option<u64> {
        match self {
            StateNodeEvent::ResourceVerified { .. } => None,
            StateNodeEvent::RegisteredToUniversal { timestamp, .. } => Some(*timestamp),
            StateNodeEvent::JoinedContentNetwork { timestamp, .. } => Some(*timestamp),
            StateNodeEvent::Synchronized { timestamp, .. } => Some(*timestamp),
            StateNodeEvent::LeftNetwork { timestamp, .. } => Some(*timestamp),
            StateNodeEvent::ResourceUpdated { timestamp, .. } => Some(*timestamp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_node_id() {
        let resources = StorageResource::new(1000);
        let event = StateNodeEvent::ResourceVerified {
            node_id: "test_node".to_string(),
            resources,
            verified: true,
        };
        
        assert_eq!(event.node_id(), "test_node");
    }

    #[test]
    fn test_event_timestamp() {
        let event = StateNodeEvent::RegisteredToUniversal {
            node_id: "test_node".to_string(),
            resources: StorageResource::new(1000),
            timestamp: 1234567890,
        };
        
        assert_eq!(event.timestamp(), Some(1234567890));

        let verification_event = StateNodeEvent::ResourceVerified {
            node_id: "test_node".to_string(),
            resources: StorageResource::new(1000),
            verified: true,
        };
        
        assert_eq!(verification_event.timestamp(), None);
    }
}