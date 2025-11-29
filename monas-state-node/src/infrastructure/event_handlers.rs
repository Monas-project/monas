//! Event handlers for processing domain events.

use crate::domain::events::Event;
use crate::port::persistence::{PersistentContentRepository, PersistentNodeRegistry};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Event handler context with access to repositories.
pub struct EventHandlerContext<N, C>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
{
    pub node_registry: Arc<RwLock<N>>,
    pub content_repo: Arc<RwLock<C>>,
}

impl<N, C> EventHandlerContext<N, C>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
{
    pub fn new(node_registry: N, content_repo: C) -> Self {
        Self {
            node_registry: Arc::new(RwLock::new(node_registry)),
            content_repo: Arc::new(RwLock::new(content_repo)),
        }
    }
}

/// Handle an incoming event.
pub async fn handle_event<N, C>(ctx: &EventHandlerContext<N, C>, event: &Event) -> Result<()>
where
    N: PersistentNodeRegistry,
    C: PersistentContentRepository,
{
    match event {
        Event::NodeCreated {
            node_id,
            total_capacity,
            available_capacity,
            ..
        } => {
            let node = crate::domain::state_node::NodeSnapshot {
                node_id: node_id.clone(),
                total_capacity: *total_capacity,
                available_capacity: *available_capacity,
            };
            ctx.node_registry.write().await.upsert_node(&node).await?;
            tracing::info!("Handled NodeCreated event for {}", node_id);
        }

        Event::ContentCreated {
            content_id,
            member_nodes,
            ..
        } => {
            let network = crate::domain::content_network::ContentNetwork {
                content_id: content_id.clone(),
                member_nodes: member_nodes.iter().cloned().collect(),
            };
            ctx.content_repo
                .write()
                .await
                .save_content_network(network)
                .await?;
            tracing::info!("Handled ContentCreated event for {}", content_id);
        }

        Event::ContentNetworkManagerAdded {
            content_id,
            member_nodes,
            ..
        } => {
            let network = crate::domain::content_network::ContentNetwork {
                content_id: content_id.clone(),
                member_nodes: member_nodes.iter().cloned().collect(),
            };
            ctx.content_repo
                .write()
                .await
                .save_content_network(network)
                .await?;
            tracing::info!("Handled ContentNetworkManagerAdded event for {}", content_id);
        }

        Event::ContentUpdated { content_id, .. } => {
            // Content updates are handled by the content storage layer
            tracing::info!("Received ContentUpdated event for {}", content_id);
        }

        Event::ContentSyncRequested {
            content_id,
            requesting_node_id,
            source_node_id,
            ..
        } => {
            // Sync requests trigger content fetching from source node
            tracing::info!(
                "Received ContentSyncRequested: {} from {} to {}",
                content_id,
                source_node_id,
                requesting_node_id
            );
        }

        Event::AssignmentDecided {
            content_id,
            assigned_node_id,
            ..
        } => {
            // Assignment decisions update content network membership
            if let Some(mut network) = ctx
                .content_repo
                .read()
                .await
                .get_content_network(content_id)
                .await?
            {
                network.member_nodes.insert(assigned_node_id.clone());
                ctx.content_repo
                    .write()
                    .await
                    .save_content_network(network)
                    .await?;
            }
            tracing::info!(
                "Handled AssignmentDecided: {} assigned to {}",
                content_id,
                assigned_node_id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::persistence::{SledContentNetworkRepository, SledNodeRegistry};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_handle_node_created() {
        let temp_dir = TempDir::new().unwrap();
        let node_registry =
            SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
        let content_repo =
            SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap();

        let ctx = EventHandlerContext::new(node_registry, content_repo);

        let event = Event::NodeCreated {
            node_id: "node-1".to_string(),
            total_capacity: 1000,
            available_capacity: 1000,
            timestamp: 12345,
        };

        handle_event(&ctx, &event).await.unwrap();

        // Verify node was created
        let capacity = ctx
            .node_registry
            .read()
            .await
            .get_available_capacity("node-1")
            .await
            .unwrap();
        assert_eq!(capacity, Some(1000));
    }

    #[tokio::test]
    async fn test_handle_content_created() {
        let temp_dir = TempDir::new().unwrap();
        let node_registry =
            SledNodeRegistry::open(temp_dir.path().join("nodes")).unwrap();
        let content_repo =
            SledContentNetworkRepository::open(temp_dir.path().join("content")).unwrap();

        let ctx = EventHandlerContext::new(node_registry, content_repo);

        let event = Event::ContentCreated {
            content_id: "cid-1".to_string(),
            creator_node_id: "node-1".to_string(),
            content_size: 100,
            member_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timestamp: 12345,
        };

        handle_event(&ctx, &event).await.unwrap();

        // Verify content network was created
        let network = ctx
            .content_repo
            .read()
            .await
            .get_content_network("cid-1")
            .await
            .unwrap();
        assert!(network.is_some());
        let network = network.unwrap();
        assert!(network.member_nodes.contains("node-1"));
        assert!(network.member_nodes.contains("node-2"));
    }
}

