## Monas State Node

分散コンテンツ管理のためのState Nodeの実装。libp2pベースのP2Pネットワーク上で、ノード登録・コンテンツ割当・CRDT同期を行う。

## ディレクトリ構成

```
monas-state-node/
├── src/
│   ├── lib.rs                          # ライブラリエントリポイント
│   ├── bin/
│   │   └── state_node.rs               # CLIバイナリ
│   ├── domain/
│   │   ├── mod.rs
│   │   ├── state_node.rs               # NodeSnapshot, AssignmentRequest/Response
│   │   ├── content_network.rs          # ContentNetwork エンティティ
│   │   └── events.rs                   # ドメインイベント定義
│   ├── port/
│   │   ├── mod.rs
│   │   ├── persistence.rs              # 永続化トレイト (PersistentNodeRegistry, PersistentContentRepository)
│   │   ├── peer_network.rs             # P2Pネットワークトレイト (PeerNetwork)
│   │   ├── event_publisher.rs          # イベント配信トレイト (EventPublisher)
│   │   └── content_repository.rs       # CRDTコンテンツリポジトリトレイト (ContentRepository)
│   ├── application_service/
│   │   ├── mod.rs
│   │   ├── state_node_service.rs       # ユースケース実装
│   │   └── node.rs                     # StateNode 統合構造体
│   ├── presentation/
│   │   ├── mod.rs
│   │   └── http_api.rs                 # HTTP REST API (axum)
│   └── infrastructure/
│       ├── mod.rs
│       ├── persistence/
│       │   ├── mod.rs
│       │   ├── sled_node_registry.rs       # Sled永続化 (NodeRegistry)
│       │   └── sled_content_network_repository.rs  # Sled永続化 (ContentNetwork)
│       ├── network/
│       │   ├── mod.rs
│       │   ├── libp2p_network.rs           # libp2p実装
│       │   ├── behaviour.rs                # NetworkBehaviour定義
│       │   ├── protocol.rs                 # Request/Responseプロトコル
│       │   └── transport.rs                # トランスポート設定
│       ├── crdt_repository.rs              # crsl-lib CRDT実装
│       ├── gossipsub_publisher.rs          # Gossipsubイベント配信
│       ├── event_bus_publisher.rs          # ローカルEventBus配信
│       ├── event_adapters.rs               # イベントアダプタ
│       ├── disk_capacity.rs                # ディスク容量クエリ
│       └── placement.rs                    # DHTキー計算
├── README.md
└── Cargo.toml
```

## アーキテクチャ

### レイヤリング

| レイヤー | 役割 |
|---------|------|
| **domain** | エンティティ・値オブジェクト・ドメインイベント定義 |
| **port** | 抽象インターフェース (トレイト) 定義 |
| **application_service** | ユースケース実行・オーケストレーション |
| **presentation** | 外部向けAPI (HTTP REST API等) |
| **infrastructure** | portの具象実装 (libp2p, sled等) |

### 主要コンポーネント

#### ドメイン層 (`src/domain/`)

- **state_node.rs**
  - `NodeSnapshot { node_id, total_capacity, available_capacity }`
  - `AssignmentRequest`, `AssignmentResponse`
  - 関数: `create_node`, `build_assignment_request`, `decide_assignment`

- **content_network.rs**
  - `ContentNetwork { content_id, member_nodes: BTreeSet<String> }`
  - 関数: `add_member_node`

- **events.rs**
  - `Event` 列挙型:
    - `NodeCreated` - ノード作成
    - `AssignmentDecided` - コンテンツ割当決定
    - `ContentNetworkManagerAdded` - メンバー追加
    - `ContentCreated` - コンテンツ作成
    - `ContentUpdated` - コンテンツ更新
    - `ContentSyncRequested` - 同期要求

#### ポート層 (`src/port/`)

- **PersistentNodeRegistry** - ノード情報の永続化
- **PersistentContentRepository** - コンテンツネットワーク情報の永続化
- **PeerNetwork** - P2P通信 (Kademlia DHT, RequestResponse, Gossipsub, CRDT同期)
- **EventPublisher** - イベント配信 (ローカル + ネットワーク)
- **ContentRepository** - CRDTベースのバージョン管理コンテンツストレージ

#### アプリケーション層 (`src/application_service/`)

- **StateNodeService** - 主要ユースケース:
  - `register_node` - ノード登録
  - `create_content` - コンテンツ作成 (DHT配置)
  - `update_content` - コンテンツ更新
  - `handle_sync_event` - 同期イベント処理
  - `get_content_network`, `get_node`, `list_nodes`, `list_content_networks`

- **StateNode** - 統合構造体 (全コンポーネントの初期化・実行)

#### プレゼンテーション層 (`src/presentation/`)

- **http_api.rs** - axum REST API

#### インフラ層 (`src/infrastructure/`)

- **persistence/** - Sledベース永続化
- **network/** - libp2p実装
  - Kademlia DHT (ピア探索・コンテンツルーティング)
  - Gossipsub (イベント伝播)
  - RequestResponse (直接通信)
  - mDNS (ローカル探索)
  - TCP/QUIC トランスポート
- **crdt_repository.rs** - crsl-libによるCRDT実装
- **gossipsub_publisher.rs** - Gossipsubイベント配信

## HTTP API

| エンドポイント | メソッド | 説明 |
|---------------|---------|------|
| `/health` | GET | ヘルスチェック |
| `/node/info` | GET | ノード情報取得 |
| `/node/register` | POST | ノード登録 |
| `/nodes` | GET | 全ノード一覧 |
| `/content` | POST | コンテンツ作成 |
| `/content/:id` | GET | コンテンツ情報取得 |
| `/content/:id` | PUT | コンテンツ更新 |
| `/contents` | GET | 全コンテンツ一覧 |

## 依存関係

主な依存:
- **libp2p** (0.56) - P2Pネットワーク (kad, gossipsub, request-response, mdns, identify, tcp, quic)
- **sled** - 組み込みKey-Valueストア
- **crsl-lib** - CRDTベースバージョン管理
- **axum** - HTTP APIフレームワーク
- **tokio** - 非同期ランタイム
- **monas-event-manager** - ローカルイベントバス
- **serde/serde_json** - シリアライゼーション
- **cid/multihash** - コンテンツアドレッシング

## ビルドと実行

```bash
cd monas-state-node

# ビルド
cargo build

# テスト
cargo test

# 実行 (デフォルト設定)
cargo run --bin state-node

# カスタム設定で実行
cargo run --bin state-node -- --data-dir ./my-data -l 127.0.0.1:8081
```

### CLIオプション

| オプション | 短縮 | デフォルト | 説明 |
|-----------|------|-----------|------|
| `--data-dir` | `-d` | `data` | データ永続化ディレクトリ |
| `--listen` | `-l` | `127.0.0.1:8080` | HTTP APIリッスンアドレス |
| `--node-id` | `-n` | (自動生成) | ノードID |
| `--bootstrap` | `-b` | (なし) | ブートストラップノードのmultiaddr |
| `--log-level` | | `info` | ログレベル (trace, debug, info, warn, error) |

## ローカル動作確認 (3ノード構成)

3つのターミナルを開いて、それぞれのノードを起動する。

### 1. ノード1 (ブートストラップノード) の起動

```bash
# ターミナル1
cargo run --bin state-node -- \
  --data-dir ./data/node1 \
  -l 127.0.0.1:8080 \
  --log-level debug
```

起動ログからノード1のPeer IDとリッスンアドレスを確認:
```
Node ID: 12D3KooW...  # これがPeer ID
```

### 2. ノード2 の起動 (ノード1に接続)

```bash
# ターミナル2
# <PEER_ID_1> を ノード1のPeer IDに置き換える
cargo run --bin state-node -- \
  --data-dir ./data/node2 \
  -l 127.0.0.1:8081 \
  -b /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID_1> \
  --log-level debug
```

### 3. ノード3 の起動 (ノード1に接続)

```bash
# ターミナル3
cargo run --bin state-node -- \
  --data-dir ./data/node3 \
  -l 127.0.0.1:8082 \
  -b /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID_1> \
  --log-level debug
```

### 4. 動作確認

```bash
# 各ノードのヘルスチェック
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8082/health

# ノード1を登録
curl -X POST http://127.0.0.1:8080/node/register \
  -H "Content-Type: application/json" \
  -d '{"total_capacity": 1000000}'

# ノード2を登録
curl -X POST http://127.0.0.1:8081/node/register \
  -H "Content-Type: application/json" \
  -d '{"total_capacity": 1000000}'

# ノード3を登録
curl -X POST http://127.0.0.1:8082/node/register \
  -H "Content-Type: application/json" \
  -d '{"total_capacity": 1000000}'

# 登録済みノード一覧を確認 (各ノードで同じ結果になるはず)
curl http://127.0.0.1:8080/nodes
curl http://127.0.0.1:8081/nodes
curl http://127.0.0.1:8082/nodes

# コンテンツを作成 (ノード1から)
# "Hello, World!" をBase64エンコード: SGVsbG8sIFdvcmxkIQ==
curl -X POST http://127.0.0.1:8080/content \
  -H "Content-Type: application/json" \
  -d '{"data": "SGVsbG8sIFdvcmxkIQ=="}'

# コンテンツ一覧を確認 (各ノードで同期されているか)
curl http://127.0.0.1:8080/contents
curl http://127.0.0.1:8081/contents
curl http://127.0.0.1:8082/contents
```

### 5. クリーンアップ

```bash
# 各ノードをCtrl+Cで停止後、データを削除
rm -rf ./data/node1 ./data/node2 ./data/node3
```
