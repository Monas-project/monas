use crate::domain::{events::StateNodeEvent, storage::{Storage, StorageError}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rand::seq::SliceRandom;


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentRequest {
    pub requesting_node_id: String,
    pub node_capacity: u64,
    pub available_capacity: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentResponse {
    pub assigned_content_network: Option<String>,
    pub assigning_node_id: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    Initialized,
    JoinedContentNetwork(String),
    Synchronized,
    Leaving,
    Disconnected,
}

#[derive(Debug, PartialEq)]
pub enum StateNodeError {
    StorageError(StorageError),
    NetworkError(String),
    AlreadyExists(String),
    InsufficientCapacity(u64),
    NoMatchingNetwork,
}

impl From<StorageError> for StateNodeError {
    fn from(error: StorageError) -> Self {
        StateNodeError::StorageError(error)
    }
}

// ドメインサービス: 純粋にドメインロジックのみ
pub struct ContentNetworkAssignmentService;

impl ContentNetworkAssignmentService {
    pub fn determine_network(
        available_networks: &[(String, u64, u64)], // (network_id, min_capacity, max_capacity)
        requested_capacity: u64,
    ) -> Result<String, StateNodeError> {
        let matching_networks: Vec<&(String, u64, u64)> = available_networks
            .iter()
            .filter(|(_, min_cap, max_cap)| {
                requested_capacity >= *min_cap && requested_capacity <= *max_cap
            })
            .collect();

        if matching_networks.is_empty() {
            return Err(StateNodeError::NoMatchingNetwork);
        }

        // random network
        let mut rng = rand::thread_rng();
        let selected_network = matching_networks
            .choose(&mut rng)
            .ok_or_else(|| StateNodeError::NoMatchingNetwork)?;
        
        Ok(selected_network.0.clone())
    }
}

// 集約ルート: StateNode
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateNode {
    node_id: String,
    storages: Storage,
    content_networks: Vec<String>,
    network_capacities: HashMap<String, (u64, u64)>, // (min_capacity, max_capacity)
    status: NodeStatus,
    // 未コミットのドメインイベント
    uncommitted_events: Vec<StateNodeEvent>,
}

impl StateNode {
    /// StateNodeインスタンスを作成
    pub fn new(node_id: String, total_capacity: u64) -> Result<Self, StateNodeError> {
        let storages = Storage::new(total_capacity)?;
        
        let mut node = Self {
            node_id: node_id.clone(),
            storages,
            content_networks: Vec::new(),
            network_capacities: HashMap::new(),
            status: NodeStatus::Initialized,
            uncommitted_events: Vec::new(),
        };

        // ドメインイベントを記録
        node.record_event(StateNodeEvent::NodeCreated {
            node_id: node_id.clone(),
            total_capacity,
            timestamp: current_timestamp(),
        });

        Ok(node)
    }

    /// アサインメントリクエストを作成（純粋関数）
    pub fn create_assignment_request(&self) -> AssignmentRequest {
        AssignmentRequest {
            requesting_node_id: self.node_id.clone(),
            node_capacity: self.storages.total_capacity(),
            available_capacity: self.storages.available_capacity(),
            timestamp: current_timestamp(),
        }
    }

    /// 他のノードからのアサインメント要求を処理（純粋なドメインロジック）
    pub fn process_assignment_request(&mut self, request: AssignmentRequest) -> Result<AssignmentResponse, StateNodeError> {
        // 自分が参加しているネットワークの情報を取得
        let available_networks: Vec<(String, u64, u64)> = self.content_networks
            .iter()
            .filter_map(|network_id| {
                self.network_capacities.get(network_id)
                    .map(|(min, max)| (network_id.clone(), *min, *max))
            })
            .collect();

        // ドメインサービスを使用してネットワークを決定
        let assigned_network = ContentNetworkAssignmentService::determine_network(
            &available_networks,
            request.available_capacity,
        )?;

        // ドメインイベントを記録
        self.record_event(StateNodeEvent::NodeAssigned {
            assigning_node_id: self.node_id.clone(),
            assigned_node_id: request.requesting_node_id.clone(),
            content_network: assigned_network.clone(),
            timestamp: current_timestamp(),
        });

        Ok(AssignmentResponse {
            assigned_content_network: Some(assigned_network),
            assigning_node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        })
    }

    /// アサインメント応答を受信して状態を更新
    pub fn handle_assignment_response(&mut self, response: AssignmentResponse) -> Result<(), StateNodeError> {
        if let Some(content_network) = response.assigned_content_network {
            self.status = NodeStatus::JoinedContentNetwork(content_network.clone());
            
            if !self.content_networks.contains(&content_network) {
                self.content_networks.push(content_network.clone());
            }

            self.record_event(StateNodeEvent::JoinedContentNetwork {
                node_id: self.node_id.clone(),
                content_network,
                timestamp: current_timestamp(),
            });
        }

        Ok(())
    }

    /// ストレージ割り当て（純粋なドメインロジック）
    pub fn allocate_storage(&mut self, amount: u64, content_network: String) -> Result<(), StateNodeError> {
        // ビジネスルール: 要求されたネットワークに参加していない場合はエラー
        if !self.content_networks.contains(&content_network) {
            return Err(StateNodeError::NetworkError(
                format!("Not joined to content network: {}", content_network)
            ));
        }

        // ストレージ割り当て
        self.storages = self.storages.allocate(amount)?;

        // ドメインイベントを記録
        self.record_event(StateNodeEvent::StorageAllocated {
            node_id: self.node_id.clone(),
            amount,
            content_network,
            remaining_capacity: self.storages.available_capacity(),
            timestamp: current_timestamp(),
        });

        Ok(())
    }

    /// コンテンツネットワークを追加
    pub fn add_content_network(&mut self, network_id: String, min_capacity: u64, max_capacity: u64) -> Result<(), StateNodeError> {
        if self.content_networks.contains(&network_id) {
            return Err(StateNodeError::AlreadyExists(format!("Network {} already exists", network_id)));
        }

        self.content_networks.push(network_id.clone());
        self.network_capacities.insert(network_id.clone(), (min_capacity, max_capacity));

        self.record_event(StateNodeEvent::ContentNetworkAdded {
            node_id: self.node_id.clone(),
            network_id,
            min_capacity,
            max_capacity,
            timestamp: current_timestamp(),
        });

        Ok(())
    }

    /// 同期処理
    pub fn synchronize(&mut self) {
        self.status = NodeStatus::Synchronized;
        
        self.record_event(StateNodeEvent::NodeSynchronized {
            node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        });
    }

    /// ネットワークから離脱
    pub fn leave_network(&mut self) {
        self.status = NodeStatus::Leaving;
        
        self.record_event(StateNodeEvent::LeftNetwork {
            node_id: self.node_id.clone(),
            timestamp: current_timestamp(),
        });
    }

    // イベントソーシング用メソッド
    fn record_event(&mut self, event: StateNodeEvent) {
        self.uncommitted_events.push(event);
    }

    pub fn get_uncommitted_events(&self) -> &[StateNodeEvent] {
        &self.uncommitted_events
    }

    pub fn mark_events_as_committed(&mut self) {
        self.uncommitted_events.clear();
    }

    // Getters
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn storages(&self) -> &Storage {
        &self.storages
    }

    pub fn content_networks(&self) -> &[String] {
        &self.content_networks
    }

    pub fn status(&self) -> &NodeStatus {
        &self.status
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, NodeStatus::Synchronized | NodeStatus::JoinedContentNetwork(_))
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}