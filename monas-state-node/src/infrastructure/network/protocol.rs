//! RequestResponse protocol definitions for peer communication.
//!
//! Uses libp2p 0.56's built-in CBOR codec for efficient serialization.
//! The ContentRequest and ContentResponse types implement Serialize/Deserialize
//! for automatic CBOR encoding.

use serde::{Deserialize, Serialize};

/// Protocol name for capacity queries.
pub const CAPACITY_PROTOCOL: &str = "/monas/capacity/1.0.0";

/// Protocol name for content fetching.
pub const CONTENT_PROTOCOL: &str = "/monas/content/1.0.0";

/// Request types for the content protocol.
///
/// Used with libp2p's CBOR codec for efficient binary serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentRequest {
    /// Query the capacity of a node.
    CapacityQuery,
    /// Fetch content by CID.
    FetchContent { content_id: String },
    /// Sync content from a node.
    SyncContent {
        content_id: String,
        from_version: Option<String>,
    },
    /// Fetch CRDT operations for a content.
    FetchOperations {
        genesis_cid: String,
        since_version: Option<String>,
    },
    /// Push CRDT operations to a peer.
    PushOperations {
        genesis_cid: String,
        /// Serialized operations (JSON-encoded)
        operations: Vec<Vec<u8>>,
    },
}

/// Response types for the content protocol.
///
/// Used with libp2p's CBOR codec for efficient binary serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentResponse {
    /// Response to capacity query.
    CapacityResponse {
        total_capacity: u64,
        available_capacity: u64,
    },
    /// Response to content fetch.
    ContentData {
        content_id: String,
        data: Vec<u8>,
        version: String,
    },
    /// Response with CRDT operations.
    OperationsData {
        genesis_cid: String,
        operations: Vec<Vec<u8>>, // Serialized operations
    },
    /// Response to push operations request.
    PushResult {
        genesis_cid: String,
        /// Number of operations accepted
        accepted_count: usize,
    },
    /// Content not found.
    NotFound { content_id: String },
    /// Error response.
    Error { message: String },
}

/// Legacy codec struct for backward compatibility.
/// Note: libp2p 0.56 uses built-in CBOR codec, so this is no longer needed
/// for the main implementation. Kept for reference.
#[derive(Debug, Clone, Default)]
pub struct ContentCodec;

impl ContentCodec {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = ContentRequest::CapacityQuery;
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: ContentRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ContentRequest::CapacityQuery));
    }

    #[test]
    fn test_response_serialization() {
        let resp = ContentResponse::CapacityResponse {
            total_capacity: 1000,
            available_capacity: 800,
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: ContentResponse = serde_json::from_slice(&bytes).unwrap();
        if let ContentResponse::CapacityResponse {
            total_capacity,
            available_capacity,
        } = decoded
        {
            assert_eq!(total_capacity, 1000);
            assert_eq!(available_capacity, 800);
        } else {
            panic!("Expected CapacityResponse");
        }
    }
}
