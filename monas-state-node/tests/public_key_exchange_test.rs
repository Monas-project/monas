//! Integration test for public key exchange protocol.

#[cfg(test)]
mod tests {
    use monas_state_node::domain::value_objects::NodeId;
    use monas_state_node::infrastructure::key_management::NodeKeyPair;
    use monas_state_node::infrastructure::network::public_key_protocol::NodePublicKey;

    #[test]
    fn test_node_public_key_verify() {
        // Generate a test key pair
        let keypair = NodeKeyPair::generate();
        let node_id = keypair.node_id().unwrap();
        let public_key = keypair.public_key_bytes();
        let signing_key = keypair.signing_key();

        // Create a signed NodePublicKey
        let node_pub_key = NodePublicKey::new(
            node_id.as_str().to_string(),
            public_key.clone(),
            signing_key,
        )
        .expect("Failed to create NodePublicKey");

        // Verify it
        assert!(
            node_pub_key.verify().is_ok(),
            "Failed to verify valid signature"
        );

        // Test that NodeId matches public key hash
        let derived_node_id =
            NodeId::from_public_key(&node_pub_key.public_key).expect("Failed to derive NodeId");
        assert_eq!(derived_node_id.as_str(), node_pub_key.node_id);
    }

    #[test]
    fn test_node_public_key_invalid_signature() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        // Generate two different key pairs
        let keypair1 = NodeKeyPair::generate();
        let keypair2_signing = SigningKey::random(&mut OsRng);

        let node_id = keypair1.node_id().unwrap();
        let public_key = keypair1.public_key_bytes();

        // Sign with the wrong key
        let wrong_node_key = NodePublicKey::new(
            node_id.as_str().to_string(),
            public_key.clone(),
            &keypair2_signing,
        )
        .expect("Failed to create NodePublicKey");

        // Verification should fail
        assert!(
            wrong_node_key.verify().is_err(),
            "Should fail to verify invalid signature"
        );
    }

    #[test]
    fn test_node_public_key_wrong_node_id() {
        let keypair = NodeKeyPair::generate();
        let public_key = keypair.public_key_bytes();
        let signing_key = keypair.signing_key();

        // Use wrong NodeId
        let wrong_node_id = "wrong-node-id-12345";

        // Create NodePublicKey with mismatched NodeId
        let node_pub_key =
            NodePublicKey::new(wrong_node_id.to_string(), public_key.clone(), signing_key)
                .expect("Failed to create NodePublicKey");

        // Verification should fail due to NodeId mismatch
        let verify_result = node_pub_key.verify();
        assert!(
            verify_result.is_err(),
            "Should fail when NodeId doesn't match public key"
        );

        if let Err(e) = verify_result {
            assert!(
                e.to_string().contains("NodeId mismatch"),
                "Error should mention NodeId mismatch"
            );
        }
    }

    #[tokio::test]
    async fn test_public_key_exchange_integration() {
        use monas_state_node::infrastructure::crdt_repository::CrslCrdtRepository;
        use monas_state_node::infrastructure::network::{Libp2pNetwork, Libp2pNetworkConfig};
        use monas_state_node::port::content_repository::ContentRepository;
        use std::sync::Arc;
        use tempfile::tempdir;

        // Create two nodes
        let tmp_dir1 = tempdir().unwrap();
        let tmp_dir2 = tempdir().unwrap();

        let crdt_repo1: Arc<dyn ContentRepository> =
            Arc::new(CrslCrdtRepository::open(tmp_dir1.path().join("crdt")).unwrap());
        let crdt_repo2: Arc<dyn ContentRepository> =
            Arc::new(CrslCrdtRepository::open(tmp_dir2.path().join("crdt")).unwrap());

        let config1 = Libp2pNetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false,
            gossipsub_topics: vec!["test".to_string()],
        };

        let config2 = Libp2pNetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_mdns: false,
            gossipsub_topics: vec!["test".to_string()],
        };

        let network1 = Libp2pNetwork::new(config1, crdt_repo1, tmp_dir1.path().to_path_buf())
            .await
            .unwrap();

        let network2 = Libp2pNetwork::new(config2, crdt_repo2, tmp_dir2.path().to_path_buf())
            .await
            .unwrap();

        // Get listen addresses
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let addrs1 = network1.listen_addrs().await;
        assert!(!addrs1.is_empty(), "Network1 should have listen addresses");

        // Connect network2 to network1
        network2.dial(addrs1[0].clone()).await.unwrap();

        // Give them time to connect
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Now test public key querying
        // Note: In real implementation, we'd query by NodeId, but for testing
        // we can use PeerId which the current implementation supports
        use monas_state_node::port::peer_network::PeerNetwork;

        let _peer1_id = network1.local_peer_id();
        let peer2_id = network2.local_peer_id();

        // Network1 queries Network2's public key
        let keys = network1
            .query_node_public_keys_batch(std::slice::from_ref(&peer2_id))
            .await
            .unwrap();

        // Should get at least a placeholder key for now
        assert!(keys.contains_key(&peer2_id), "Should have key for peer2");
        let key = &keys[&peer2_id];
        assert_eq!(key.len(), 65, "P-256 public key should be 65 bytes");
        assert_eq!(key[0], 0x04, "Should be uncompressed P-256 key");
    }
}
