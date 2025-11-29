## Monas State Node - 現状サマリ（実装準拠）

このREADMEは、現在の `src/` の実装に準拠した最小構成のサマリです。詳細な背景・将来設計は `state-node-design-v3.md` および `implementation.md` を参照してください。

## ディレクトリ構成

```
monas-state-node/
├── src/
│   ├── lib.rs
│   ├── application_service/
│   │   ├── mod.rs
│   │   └── state_node_service.rs
│   ├── domain/
│   │   ├── mod.rs
│   │   ├── state_node.rs
│   │   ├── content_network.rs
│   │   └── events.rs
│   └── infrastructure/
│       ├── mod.rs
│       ├── node_repository.rs
│       ├── content_network_repository.rs
│       └── network.rs
├── README.md (このファイル)
├── implementation.md
└── state-node-design-v3.md
```

## 命名・レイヤリング方針

- ドメイン（`src/domain`）: エンティティ・値オブジェクトとドメインルール、イベント定義。
- アプリケーション（`src/application_service`）: ユースケース実行・オーケストレーション、ポート（trait）定義。
- インフラ（`src/infrastructure`）: ポートの具象実装（インメモリ/ネットワークスタブ）。

命名規則は Rust の一般的規約に準拠し、ファイル名はスネークケース、公開型はパスカルケース。イベントは `Event` 列挙型で表現。

## 現状の登録・割当関連機能

### ドメイン
- `state_node.rs`
  - `NodeSnapshot { node_id, total_capacity, available_capacity }`
  - `AssignmentRequest { requesting_node_id, available_capacity, timestamp }`
  - `AssignmentResponse { assigned_content_network: Option<String>, assigning_node_id, timestamp }`
  - 関数: `create_node`, `build_assignment_request`, `decide_assignment`
- `content_network.rs`
  - `ContentNetwork { content_id, member_nodes: BTreeSet<String> }`
  - 関数: `add_member_node`
- `events.rs`
  - `Event::{ NodeCreated, AssignmentDecided, ContentNetworkManagerAdded }`

### アプリケーション
- `state_node_service.rs`
  - ポート: `NodeRegistry`, `ContentNetworkRepository`, `PeerNetwork`
  - ユースケース: `register_node`, `handle_assignment_request`, `add_member_node`
  - 方針: ドメインで事実(Event)を生成し、呼び出し側が配信処理を担う想定

### インフラ
- `node_repository.rs`: `NodeRegistryImpl(HashMap<node_id, NodeSnapshot>)`
- `content_network_repository.rs`: `ContentNetworkRepositoryImpl`（インメモリ）
- `network.rs`: `Libp2pNetwork` スタブ（問い合わせは未実装で None/空を返却）

## アップロード/同期に関する現状評価

- 受信（アップロード）面のI/Oは未実装。現在は「登録」「割当決定」「コンテンツネットワークへの追加」を、インメモリの擬似リポジトリとイベントで表現。
- 同期はイベント駆動を想定するが、配信/購読は未実装（アウトボックスやGossipsub等の導入が前提）。
- `PeerNetwork` スタブが存在し、将来的に `libp2p` 実装へ差し替え可能。

## 依存とビルド

- 主な依存: `serde`, `thiserror`, `rand (0.9)`, `anyhow`, `async-trait`
- テストは `cargo test` で実行可能

```bash
cd monas-state-node
cargo test
```

## 次のステップ（提案）

- I/O 実装: アップロード受信APIと、`PeerNetwork` の Request/Response 実装（libp2p）
- 同期: Outbox/Inbox を用いたイベント配信と適用（冪等設計）
- 永続化: `NodeRegistry`/`ContentNetworkRepository` のRocksDB/SQLite実装