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
| `/content/:id` | DELETE | コンテンツ削除 |
| `/content/:id/members` | POST | コンテンツネットワークのメンバー追加 |
| `/content/:id/access/grant` | POST | コンテンツへのアクセス権限付与 |
| `/contents` | GET | 全コンテンツ一覧 |
| `/content/:id/data` | GET | CRDTの最新データ取得 |
| `/content/:id/history` | GET | CRDT履歴の取得 |
| `/content/:id/version/:version` | GET | CRDTの指定バージョン取得 |

## 認証・認可

State Node は以下のヘッダーを用いて **monas-account の署名検証（認証）** と
**UCAN/AuthToken の署名検証（認可）** を行う。

- `Authorization: Bearer <token>` または `Authorization: <token>`
  - AuthToken/UCAN の JWT 文字列を指定する。
- `X-Request-Signature: <base64>`  
  - リクエスト署名（P-256）を Base64 で指定する。

**必須となる操作:**

- `/content` (POST)
- `/content/:id` (PUT/DELETE)
- `/content/:id/members` (POST)
- `/content/:id/access/grant` (POST)

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

### 自動化スクリプトを使用する方法（推奨）

monas-state-nodeディレクトリ内に自動化スクリプトが用意されています：

```bash
# monas-state-nodeディレクトリから実行
cd monas-state-node

# 3つのノードを起動
./scripts/start-local-nodes.sh

# 基本的な機能テストを実行（認証なし）
./scripts/test-local-nodes.sh

# 認証付き機能テストを実行（自動的にトークンを生成）
./scripts/test-with-auth.sh

# E2Eテスト（コンテンツ作成→更新→同期→権限付与→別アカウント更新）
./scripts/e2e-test.sh

# テスト用の認証データを生成
./scripts/generate-test-auth.sh test-auth

# クリーンアップ（ノードの停止とデータ削除）
./scripts/cleanup-local-nodes.sh
```

#### 認証付きテストについて

`test-with-auth.sh`スクリプトは以下を自動的に実行します：

1. テスト用のP-256鍵ペアを生成
2. AuthToken（JWT形式）を生成
3. リクエスト署名を生成
4. 認証付きでコンテンツの作成・更新・削除をテスト
5. 複数ノード間でのCRDT同期をテスト

個別に認証データを生成する場合：

```bash
# 完全なテスト認証データを生成
./scripts/generate-test-auth.sh test-auth

# 環境変数として認証データをエクスポート
source <(./scripts/generate-test-auth.sh export)

# 特定のコンテンツIDのトークンを生成
./scripts/generate-test-auth.sh generate-token content123

# リクエスト署名を生成
./scripts/generate-test-auth.sh generate-signature '{"data":"test"}'
```

### 手動で起動する方法

#### 1. ノード1 (ブートストラップノード) の起動

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

#### 2. ノード2 の起動 (ノード1に接続)

```bash
# ターミナル2
# <PEER_ID_1> を ノード1のPeer IDに置き換える
cargo run --bin state-node -- \
  --data-dir ./data/node2 \
  -l 127.0.0.1:8081 \
  -b /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID_1> \
  --log-level debug
```

#### 3. ノード3 の起動 (ノード1に接続)

```bash
# ターミナル3
cargo run --bin state-node -- \
  --data-dir ./data/node3 \
  -l 127.0.0.1:8082 \
  -b /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID_1> \
  --log-level debug
```

### 動作確認

#### 基本的な動作確認（認証なし）

```bash
# 各ノードのヘルスチェック
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8082/health

# ノード情報の取得
curl http://127.0.0.1:8080/node/info

# ノード登録
curl -X POST http://127.0.0.1:8080/node/register \
  -H "Content-Type: application/json" \
  -d '{"total_capacity": 1000000}'

# 登録済みノード一覧を確認
curl http://127.0.0.1:8080/nodes

# コンテンツ一覧を確認（認証なしで取得可能）
curl http://127.0.0.1:8080/contents
```

#### 認証・認可が必要な操作

認証・認可が必要な操作には、以下のヘッダーが必要です：
- `Authorization: Bearer <token>` - AuthToken/UCANのJWT
- `X-Request-Signature: <base64>` - リクエスト署名（P-256）

```bash
# コンテンツの作成（認証必須）
# 実際の使用時はトークンと署名を適切に生成する必要があります
TOKEN="your-auth-token"
SIGNATURE="your-request-signature"

curl -X POST http://127.0.0.1:8080/content \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-Signature: $SIGNATURE" \
  -d '{
    "data": "SGVsbG8sIFdvcmxkIQ=="
  }'

# コンテンツの更新（認証必須）
CONTENT_ID="your-content-id"
curl -X PUT http://127.0.0.1:8080/content/$CONTENT_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-Signature: $SIGNATURE" \
  -d '{
    "data": "VXBkYXRlZCBjb250ZW50"
  }'

# コンテンツの削除（認証必須）
curl -X DELETE http://127.0.0.1:8080/content/$CONTENT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-Signature: $SIGNATURE"

# コンテンツネットワークのメンバー追加（認証必須）
curl -X POST http://127.0.0.1:8080/content/$CONTENT_ID/members \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-Signature: $SIGNATURE" \
  -d '{
    "node_id": "12D3KooW..."
  }'

# アクセス権限の付与（認証必須・ownerのみ）
# grantee_id は "type:id" 形式（例: "user:account2"）
# capabilities: ReadContent, WriteContent, DeleteContent,
#               ManageMembers, ShareContent, RevokeAccess, ReadMetadata
curl -X POST http://127.0.0.1:8080/content/$CONTENT_ID/access/grant \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-Signature: $SIGNATURE" \
  -d '{
    "grantee_id": "user:account2",
    "capabilities": ["ReadContent", "WriteContent", "ReadMetadata"]
  }'
```

#### CRDT関連の操作

```bash
# CRDTの最新データ取得
CONTENT_ID="your-content-id"
curl http://127.0.0.1:8080/content/$CONTENT_ID/data

# CRDT履歴の取得
curl http://127.0.0.1:8080/content/$CONTENT_ID/history

# CRDTの指定バージョン取得
VERSION="1"
curl http://127.0.0.1:8080/content/$CONTENT_ID/version/$VERSION
```

#### P2Pネットワークの動作確認

```bash
# ノード間の接続状況を確認
# 各ノードのログで以下のようなメッセージを確認
# - "Peer connected: 12D3KooW..."
# - "Discovered peers via mDNS"
# - "Content synced from peer"

# Gossipsubでのイベント伝播を確認
# 1つのノードでコンテンツを作成すると、他のノードにもイベントが伝播される
```

### クリーンアップ

```bash
# 各ノードをCtrl+Cで停止後、データを削除
rm -rf ./data/node1 ./data/node2 ./data/node3
```

### トラブルシューティング

- **ノードが接続されない場合**
  - ブートストラップノードのPeer IDが正しいか確認
  - ポート9000が他のプロセスで使用されていないか確認
  - ファイアウォールの設定を確認

- **認証エラーが発生する場合**
  - AuthTokenの有効期限を確認
  - 署名の生成方法が正しいか確認
  - monas-accountサービスが正常に動作しているか確認

- **CRDT同期が動作しない場合**
  - ノード間の接続が確立されているか確認
  - Gossipsubトピックへの購読が成功しているか確認
  - ログレベルをdebugにして詳細を確認
