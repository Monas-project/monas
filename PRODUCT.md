# Monas Product Document

## 1. Monasとは何か

Monas は、**暗号化されたコンテンツそのもの**と、**そのコンテンツを誰がどこでどう扱えるかという状態管理**を分離して扱うためのプロダクトです。

このリポジトリが目指しているのは、単なる「分散ストレージ」でも「クラウドストレージ代替」でもありません。Monas がやりたいことは次の 3 点です。

1. コンテンツは利用者側で暗号化し、保存先を固定しない
2. アクセス権限はファイルサーバー依存ではなく、暗号鍵と capability token で持つ
3. メタデータ、版管理、レプリケーション、アクセス失効は P2P な state network で扱う

つまり Monas は、

- データプレーン: 実ファイルの暗号化・保存・共有
- コントロールプレーン: 所有者、メンバー、版履歴、同期、失効
- アイデンティティプレーン: 鍵、署名、トークン

を分離しながら一貫した体験にまとめようとしているプロダクトです。

現時点のコードベースでは、この構想を構成するサブシステムは既に複数実装されています。ただし、**すべてが一体の完成品として接続されているわけではなく、一部は独立した実装段階**にあります。本書では、その理想像と現実装を分けて整理します。

## 2. 解こうとしている課題

Monas が対象にしている課題は、既存のクラウドストレージや SaaS 型ファイル共有で起きやすい以下の問題です。

- 実データの所在と権限管理が一体化しており、保存先を変えると権限モデルも変わる
- クラウド事業者の ACL に依存するため、暗号学的な所有権や委譲モデルが弱い
- ファイル共有はできても、あとから確実に失効させるのが難しい
- 複数ノードに分散配置したい場合、配置戦略、冗長化、同期、復旧の実装が重い
- ローカル、IPFS、Google Drive、OneDrive のような異なる保存先を同じモデルで扱いにくい
- コンテンツ本体とメタデータの履歴管理が分断されやすい

Monas はこれに対して、

- 保存先の抽象化
- content-addressed な識別子
- クライアント側暗号化
- 共有鍵の recipient ごとのラッピング
- capability token による委譲
- state node による履歴・同期・配置管理

で解こうとしています。

## 3. プロダクト思想

### 3.1 Encryption First

Monas の中心思想は「保存より前に暗号化する」です。保存先が Google Drive でも IPFS でもローカルでも、保存されるのは暗号化済みデータであるべき、という前提です。

### 3.2 Storage Agnostic

Monas は保存先をプロダクトの本質にしません。保存先は差し替え可能な provider として扱い、プロダクトの本質は次に置きます。

- コンテンツ識別
- 鍵管理
- アクセス委譲
- バージョン履歴
- レプリケーション

### 3.3 Capability-Based Access

「このファイルを読める人」をサーバーの ACL だけで表現するのではなく、**所有者が署名した capability token** と **受信者向けにラップした CEK** で扱うのが思想です。

### 3.4 Metadata Is a Network Problem

コンテンツ本体のバイト列は任意の provider に置けても、誰が owner なのか、どのノードが責任を持つのか、どの版が最新か、古い token を失効したか、という情報はネットワークで整合的に持つ必要があります。これを担うのが `monas-state-node` です。

### 3.5 Identity Must Be Cryptographically Bound

ユーザー ID やノード ID は、できるだけ公開鍵と結びついているべきです。Monas はこの方向に寄せた設計になっており、少なくとも state-node 側では自己完結した公開鍵ベースの識別子と署名検証を強く意識しています。

## 4. Monas を構成する主要プロダクト要素

| 要素 | 役割 | 主な実装 |
| --- | --- | --- |
| Account | 鍵生成、署名、アカウント表現 | `monas-account` |
| Content | コンテンツ暗号化、保存、共有、再暗号化 | `monas-content` |
| Filesync | 保存先 provider 抽象化 | `monas-filesync` |
| State Node | P2P 状態管理、版管理、配置、認可、同期 | `monas-state-node` |
| Event Bus | 非同期イベント伝播の共通部品 | `monas-event-manager` |
| SDK/Proto | 将来のクライアント組み込み足場 | `sdk/monas-kotlin`, `wasm-module-proto` |

## 5. プロダクト全体像

### 5.1 目指している最終像

```text
Client / App
  |
  | 1. 鍵生成・署名
  v
monas-account
  |
  | 2. CEK生成、暗号化、provider保存、共有用 envelope 生成
  v
monas-content
  |
  | 3. content metadata / ownership / placement / version を通知
  v
monas-state-node (P2P)
  |
  | 4. content network / access policy / CRDT sync / token invalidation
  v
State Network

Storage Providers
  - local
  - IPFS
  - Google Drive
  - OneDrive
```

### 5.2 現在のコード上の実態

現実には、今のリポジトリには **2 つの並行した content 管理路線** があります。

1. `monas-content`
   コンテンツを暗号化し、外部 provider に保存し、HPKE で共有する路線
2. `monas-state-node`
   コンテンツバイト列自体を CRDT に入れて分散履歴管理する路線

この 2 つは将来的に統合される前提の設計ですが、**現在は完全には接続されていません**。特に重要なのは次です。

- `monas-content` から `monas-state-node` への通知は `NoopStateNodeClient` で未接続
- `monas-content` の `content_id` は SHA-256 hex ベース
- `monas-state-node` の `content_id` は CRDT の genesis CID ベース
- つまり、現時点では ID モデルもフローもまだ 1 つに収束していない

この点は、プロダクト戦略上かなり重要です。今の Monas は「思想が通った複数の核」を持っており、**統合フェーズの前段**にあります。

## 6. 各コンポーネントの詳細

## 6.1 `monas-account`

### 役割

`monas-account` は、Monas のアイデンティティ層の最小実装です。ドメイン上は「アカウント = 鍵ペア」という非常にシンプルなモデルを採用しています。

### できること

- K-256 または P-256 鍵ペアの生成
- 永続化した鍵のロード
- 任意メッセージへの署名
- 鍵の削除

### API

デフォルトでは `127.0.0.1:4002` で起動します。

| Endpoint | Method | 内容 |
| --- | --- | --- |
| `/accounts` | `POST` | 鍵ペア作成 |
| `/accounts` | `DELETE` | 保存済み鍵の削除 |
| `/accounts/sign` | `POST` | Base64 メッセージへの署名 |

### 入出力の意味

- 作成時には `key_type` として `K256` または `P256` を指定
- レスポンスには `public_key_base64` と `secret_key_base64` が返る
- 署名 API は `message_base64` を受け取り、`signature_base64` を返す

### 設計思想

このサービスは wallet や key agent に近い位置づけで、複雑な user profile や DID directory をまだ持ちません。Monas の初期段階では「署名できる主体を作ること」を最小責務にしています。

### 現状の制約

- 鍵種は K-256 / P-256 のみ
- state-node の署名検証は実質 P-256 前提なので、**アカウント層で K-256 を作れても state-node 認証とは完全整合していない**
- 鍵作成 API が秘密鍵をレスポンスで返すため、プロダクション設計としては wallet/KMS 化が必要

## 6.2 `monas-content`

### 役割

`monas-content` は Monas のデータプレーンです。コンテンツの生成、暗号化、保存、取得、共有、再暗号化を担います。

### コアモデル

`Content` は以下を持ちます。

- `raw_id`: 平文コンテンツから導出した ID
- `series_id`: 論理的に同一系列のコンテンツ ID
- `encrypted_id`: `plainCid || ciphertext` から導出した暗号文側識別子
- `metadata`: `name`, `path`, `provider`, timestamps
- `encrypted_content`
- `is_deleted`

### ID の意味

- `raw_id`
  平文バイト列の SHA-256 hex
- `encrypted_id`
  `sha256(plainCid || 0x00 || ciphertext)` の hex
- `series_id`
  更新後も論理系列を追うための ID

この設計により、「同じ平文か」「暗号文が変わったか」「論理的には同じファイル系列か」を分離して扱えます。

### 暗号化の思想

コンテンツごとに CEK を 1 つ発行し、その CEK でコンテンツ本体を暗号化します。受信者への共有は、平文や CEK を直接渡さず、CEK を受信者公開鍵向けにラップして配布します。

### 現在の暗号実装

- コンテンツ暗号化: AES-256-CTR ベース
- CEK 生成: OS RNG
- 共有時の鍵ラッピング: HPKE v1
  - KEM: P-256
  - KDF: HKDF-SHA256
  - AEAD: AES-256-GCM

### 共有モデル

`Share` は「1 コンテンツに対する ACL」として設計されています。

- `Permission::Read`
- `Permission::Write`
- `Permission::Owner`

各 recipient は `KeyId` で識別されます。`KeyId` は公開鍵から導出され、recipient ごとに `KeyEnvelope` を発行します。

### できること

- コンテンツ作成
- コンテンツ更新
- 論理削除
- 復号取得
- CEK 指定による復号
- 再暗号化
- provider 接続 / 切断
- 共有付与 / 共有取消
- KeyEnvelope からの CEK unwrap

### API

デフォルトでは `127.0.0.1:4001` で起動します。

| Endpoint | Method | 内容 |
| --- | --- | --- |
| `/contents` | `POST` | コンテンツ作成 |
| `/contents/{id}` | `PATCH` | 名前または内容の更新 |
| `/contents/{id}` | `DELETE` | 論理削除 |
| `/contents/{id}/fetch` | `GET` | 復号済みコンテンツ取得 |
| `/contents/{id}/decrypt` | `POST` | CEK を渡して復号 |
| `/contents/{id}/reencrypt` | `POST` | 新 CEK で再暗号化 |
| `/providers` | `GET` | 接続済み provider 一覧 |
| `/providers/{provider}/connect` | `POST` | provider 接続 |
| `/providers/{provider}/disconnect` | `DELETE` | provider 切断 |
| `/shares` | `POST` | 共有付与 |
| `/shares/unwrap` | `POST` | KeyEnvelope から CEK 取得 |
| `/shares/{content_id}/{recipient_key_id}` | `DELETE` | 共有取消 |
| `/shares/{content_id}` | `GET` | ACL 取得 |

### provider abstraction

`monas-content` は `monas-filesync` を通じて複数 provider に保存できます。

- `local`
- `local-mobile`
- `ipfs`
- `google-drive`
- `onedrive`

### provider 接続の意味

provider 接続は OAuth 自体をここで完結させるのではなく、**既に取得した access token を登録する**モデルです。つまり Monas は provider の認証 UX を抽象化しているというより、保存先へのアクセス資格を内部に保持して利用する構成です。

### 現状の制約

- API ルーターでは `InMemoryContentEncryptionKeyStore` と `InMemoryShareRepository` を使用しており、**現行起動パスはプロセス内メモリ依存**
- Sled 実装は存在するが、presentation 層にまだ配線されていない
- `StateNodeClient` が `Noop` なので、**state-node 連携は未接続**
- つまり `monas-content` は今のままでも単体で使えるが、「Monas network の content control plane」とはまだ一体化していない

## 6.3 `monas-filesync`

### 役割

`monas-filesync` は、保存先 provider を同じ API で扱うためのストレージ抽象化レイヤーです。

### 設計意図

Monas は保存先を product lock-in の中心に置かないため、provider ごとの差分を `StorageProvider` trait に閉じ込めています。

### 実装済み provider

- IPFS
- Google Drive
- OneDrive
- Local Desktop
- Local Mobile

### URI モデル

provider ごとに URI でリソースを表します。

- `ipfs://<cid>`
- `google-drive://content/file.json` または `google-drive://<file_id>`
- `onedrive://<item_id>`
- `local://path/to/file`

### 設定

`filesync.toml` と `MONAS_*` 環境変数で設定できます。

主な環境変数:

- `MONAS_IPFS_GATEWAY`
- `MONAS_GOOGLE_DRIVE_API_ENDPOINT`
- `MONAS_GOOGLE_DRIVE_CLIENT_ID`
- `MONAS_GOOGLE_DRIVE_CLIENT_SECRET`
- `MONAS_GOOGLE_DRIVE_ROOT_FOLDER_ID`
- `MONAS_ONEDRIVE_API_ENDPOINT`
- `MONAS_ONEDRIVE_CLIENT_ID`
- `MONAS_ONEDRIVE_CLIENT_SECRET`
- `MONAS_LOCAL_BASE_PATH`

### 実装上のポイント

- `MultiStorageRepository` は provider ごとの access token を保持
- ローカル provider はデフォルトで接続済み扱い
- credentials を JSON に永続化する実装がある
- IPFS は raw block と pin を使う設計になっている

### 現状の制約

- クラウド接続は `cloud-connectivity` feature 前提
- OAuth フローそのものは未提供
- provider ごとの差分吸収はあるが、コンフリクト解決や sync 戦略は filesync 単体の責務ではない

## 6.4 `monas-state-node`

### 役割

`monas-state-node` は Monas のコントロールプレーンであり、以下を担います。

- P2P ネットワーク参加
- ノード登録
- コンテンツ配置
- content network のメンバー管理
- CRDT による版管理
- owner / capability token に基づく認可
- token 失効
- relay と failover
- 冗長化維持

### State Node が持つ世界観

State Node は「ファイルストア」ではなく、**ある content をどのノード群が担当するか**を管理するノードです。ここでの中心エンティティは `ContentNetwork` です。

`ContentNetwork` は以下を持ちます。

- `content_id`
- `member_nodes`

つまり State Node が直接表現したいのは、「この content はどのノード群が責任を持つか」です。

### Node モデル

ノードは `NodeSnapshot` として扱われます。

- `node_id`
- `total_capacity`
- `available_capacity`

### 配置思想

content 作成時、state-node は content ID から DHT key を計算し、Kademlia に近い closest peer 探索を行い、さらに容量を見て配置候補を選びます。

これは単純なランダム配置ではなく、

- DHT proximity
- 容量
- 冗長度

を合わせて placement を決める設計です。

### 版管理

版管理は `CrslCrdtRepository` が担います。

- create / update を operation として保持
- DAG で履歴を保持
- latest version / version history を取得可能
- operation を他ノードに push / fetch 可能

### アクセス制御

state-node の access control は 2 層あります。

1. `AccessPolicy`
   owner と `min_valid_issued_at` を持つ
2. `ContentAccessControl`
   token invalidation を補助する永続化状態

owner であれば即座に権限が通り、owner 以外は AuthToken による delegated capability を必要とします。

### 認証モデル

state-node は `monas-account` 系の自己完結型 key ID と署名を前提にしています。

- self-contained key ID 例: `user:<130 hex chars of uncompressed P-256 public key>`
- request signature を `X-Request-Signature` に載せる
- timestamp を `X-Request-Timestamp` に載せる

### 認可モデル

state-node 側の `AuthToken` は JWT 風の capability token です。payload は以下のような要素を持ちます。

- `iss`: issuer key ID
- `aud`: audience key ID
- `exp`
- `iat`
- `jti`
- `att`: capability 一覧

capability には以下があります。

- Read
- Write
- Delete
- Share
- Revoke
- Reencrypt

### API

デフォルトでは `127.0.0.1:8080` で起動します。

| Endpoint | Method | 内容 |
| --- | --- | --- |
| `/health` | `GET` | ヘルスチェック |
| `/health/live` | `GET` | liveness |
| `/health/ready` | `GET` | readiness |
| `/node/info` | `GET` | ノード情報取得 |
| `/node/register` | `POST` | ノード登録 |
| `/nodes` | `GET` | ノード一覧 |
| `/contents` | `GET` | content network 一覧 |
| `/content` | `POST` | content 作成 |
| `/content/:id` | `PUT` | content 更新 |
| `/content/:id` | `DELETE` | content 削除 |
| `/content/:id/members` | `POST` | メンバー追加 |
| `/content/:id/data` | `GET` | 最新または指定 version のデータ取得 |
| `/content/:id/history` | `GET` | version history 取得 |
| `/content/:id/version/:version` | `GET` | 特定 version 取得 |
| `/content/:id/access/invalidate` | `POST` | 既存 token の失効 |

### public endpoint と private endpoint の分離思想

以下は public です。

- health 系
- node info
- node register
- nodes
- contents

公開されるのは node ID、capacity、listen address、content ID などで、コンテンツ本体は含みません。

read/write 系は認証を必要とします。

### relay の思想

local node が対象 content の member でなければ、

- update
- delete
- invalidate_tokens

を member node に relay します。これにより「どの edge から入ってきても、担当ノードが処理する」構造を作っています。

### redundancy maintenance

state-node には update 後に冗長度を維持する仕組みがあります。

- member ノードの空き容量を確認
- 閾値未満ノードを低容量と判定
- 健全ノード数が replication factor を下回れば新規 member を追加
- 必要に応じて低容量ノードを除外

デフォルト値:

- `min_replication_factor = 3`
- `capacity_threshold_bytes = 1GB`

### 運用特性

- libp2p ベース
- Kademlia DHT
- Gossipsub
- request/response
- mDNS
- TCP / QUIC
- body limit 16 MiB
- global/per-IP rate limit あり

### 現状の制約

- content 作成 API は `data` をそのまま CRDT に保存するため、**state-node 単体フローでは plaintext を保持する**
- 一方で Monas 全体思想は encryption-first なので、ここは `monas-content` 統合で最終形に寄せる必要がある
- node ID は概念的には公開鍵由来だが、実際の配置処理では libp2p `PeerId` 文字列をそのまま扱う箇所が多い
- infra ドキュメントの一部は `peer_id` という旧表現が残っており、API 実装とは微妙にズレがある

## 6.5 `monas-event-manager`

### 役割

`monas-event-manager` は Monas 専用の業務ドメインではなく、非同期・型安全なイベント配信基盤です。

### 提供価値

- subscriber 単位の retry
- dead letter 的な回復
- persistence
- health monitoring

Monas 全体では、「state update をどのように内部伝播するか」の共通部品として使える位置づけです。

## 6.6 SDK / WASM Proto

`sdk/monas-kotlin` と `wasm-module-proto` は、将来の client embedding の方向性を探るための足場です。

現状は `add(a, b)` を呼ぶ最小実装で、まだ Monas の本体機能をラップしていません。ここは完全に proto 段階です。

## 7. 主要ドメインモデル

## 7.1 Content 側

| モデル | 意味 |
| --- | --- |
| `Content` | コンテンツ本体、暗号文、状態 |
| `Metadata` | 名前、パス、timestamps、provider |
| `ContentEncryptionKey` | コンテンツ単位の CEK |
| `Share` | content に対する ACL |
| `KeyEnvelope` | recipient ごとの CEK 配布パケット |
| `StorageProvider` | 保存先抽象 |

## 7.2 State 側

| モデル | 意味 |
| --- | --- |
| `NodeSnapshot` | ノード容量スナップショット |
| `ContentNetwork` | content を担当するノード集合 |
| `AccessPolicy` | owner と token invalidation 水準 |
| `ContentAccessControl` | invalidation の補助永続状態 |
| `SerializedOperation` | CRDT 同期用 operation |

## 7.3 Identity / Auth 側

| モデル | 意味 |
| --- | --- |
| `Identity` | user / node / service の識別 |
| `AuthCapability` | state-node ドメイン上の権限 |
| `AuthToken` | delegated capability token |
| `KeyId` | 公開鍵由来の識別子 |

## 8. 典型フロー

## 8.1 ターゲットフロー: コンテンツ作成

1. クライアントが `monas-account` で鍵を持つ
2. `monas-content` が CEK を生成する
3. 平文を暗号化し `raw_id` と `encrypted_id` を得る
4. 暗号文を provider に保存する
5. `monas-content` が `monas-state-node` に content created operation を送る
6. `monas-state-node` が owner を記録し、member node を選定し、content network を作る
7. state network が版管理・権限・同期を担う

## 8.2 現在の実装フロー: `monas-content`

1. API が Base64 コンテンツを受ける
2. CEK を生成し暗号化
3. `MultiStorageRepository` で provider に保存
4. CEK をストアに保存
5. `NoopStateNodeClient` に通知しようとするが、実際には何も送られない

つまり、暗号化と保存はできるが、state network との接続はまだない、という状態です。

## 8.3 現在の実装フロー: `monas-state-node`

1. API が Base64 コンテンツを受ける
2. caller を認証する
3. CRDT repository に content を create する
4. DHT + capacity で member node を選ぶ
5. access policy を owner 付きで付与する
6. operation を member に push する
7. `ContentCreated` event を publish する

これは単体では完結していますが、保存先 provider abstraction や ciphertext 管理はまだ統合されていません。

## 8.4 共有フロー

1. owner が recipient 公開鍵を指定
2. `monas-content` が recipient の `KeyId` を算出
3. CEK を HPKE でラップ
4. `KeyEnvelope` を返す
5. recipient は秘密鍵で CEK を unwrap
6. `decrypt_with_cek` で content を復号できる

## 8.5 失効フロー

1. owner が state-node に対して invalidate を要求
2. state-node が owner かを確認
3. `min_valid_issued_at` を更新
4. 以後、古い `iat` を持つ token を拒否
5. operation を member node に push

このモデルは「すでに配った token をまとめて古くする」という意味で非常に重要です。

## 8.6 再暗号化フロー

1. `monas-content` が旧 CEK で復号
2. 新 CEK を発行
3. 同じ plaintext を再暗号化
4. `raw_id` は維持
5. `encrypted_id` は更新
6. 共有先を再編成できる

これは owner が一部 recipient を外したい場合の基本機能です。

## 9. セキュリティモデル

## 9.1 強い点

- コンテンツ暗号化が provider 非依存
- content-addressed な整合性確認がある
- recipient ごとに CEK をラップするため、共有が recipient-specific
- owner と delegated token を分けている
- state-node では request signature と timestamp を検証する
- token invalidation がある
- node 間同期は operation ベース

## 9.2 現状の注意点

- `monas-account` の create API は秘密鍵を返す
- `monas-content` の標準起動経路では CEK / share が in-memory
- `monas-content` と `monas-state-node` の統合は未完
- state-node 単独フローでは plaintext が CRDT に入る
- state-node の認証・署名検証は P-256 前提
- full UCAN delegation chain verification は未実装
- `UcanAdapter` は capability token による認可を提供するが、名前の通りの完全 UCAN 実装ではない
- policy が存在しない content は read が通る設計になっており、最終的には product policy の再確認が必要

## 10. API と実装の成熟度評価

### すでに成立しているもの

- 鍵生成と署名
- provider abstraction
- コンテンツ暗号化と復号
- recipient ごとの CEK sharing
- content の論理削除と再暗号化
- P2P node registration
- CRDT 版管理
- content network membership
- token invalidation
- relay / failover / redundancy maintenance
- Docker / Terraform による state-node 配備足場

### まだ統合が必要なもの

- `monas-content` と `monas-state-node` の本接続
- content ID モデルの統一
- owner / share / capability の end-to-end 接続
- provider OAuth UX
- 永続ストアの presentation 配線
- plaintext を持たない最終的 state-node モデル
- SDK の実用化

## 11. 運用イメージ

## 11.1 ローカル

- `monas-account`: `MONAS_ACCOUNT_PORT` デフォルト `4002`
- `monas-content`: `MONAS_CONTENT_PORT` デフォルト `4001`
- `monas-state-node`: `--listen` デフォルト `127.0.0.1:8080`

`monas-state-node` には 3 ノード起動スクリプトと Docker Compose、Terraform が用意されています。

## 11.2 クラウド

state-node は AWS ECS Fargate を前提にした Terraform があり、

- bootstrap node
- member node
- EFS
- ALB
- Cloud Map

を使って構成できる前提です。

つまり Monas はローカル PoC だけを想定しているのではなく、**分散 state network を実際に配備する前提の実装**を持っています。

## 12. 事業・プロダクトとしての意味

Monas を事業的に見ると、このプロダクトは「新しいストレージを作る」よりも、**保存・権限・同期・共有を分離したソフトウェア基盤を作る**ことに本質があります。

この基盤が成立すると、次のような製品形態に展開できます。

- 暗号化ドキュメント共有基盤
- sovereign team storage
- 複数クラウド横断の secure content fabric
- ローカルファーストな knowledge / asset 管理
- API / SDK 提供型の組み込み基盤

ただし、現時点で最も重要なのは派生ユースケースの広がりではなく、**コアとなる 2 本の実装路線を統合して 1 つの一貫した product flow に収束させること**です。

## 13. このリポジトリを読んだ上での結論

Monas は現在、

- 暗号化コンテンツ管理
- provider abstraction
- P2P state management
- capability-based authorization
- CRDT versioning

という、プロダクトの核になる要素を既に個別には持っています。

一方で、まだ未解消の重要論点があります。

- content plane と state plane の統合
- ID モデルの統一
- plaintext/ciphertext の責務分離の最終決定
- owner / share / delegated token の end-to-end 実装

したがって Monas の現在地を一言で表すなら、

**「思想はかなり明確で、コア部品も揃っているが、完成品というより統合直前のアーキテクチャ段階にある分散暗号化コンテンツ基盤」**

です。

CEO 観点では、このプロダクトは単なる機能追加ではなく、

- 何を network に持たせるのか
- 何を client に持たせるのか
- 何を provider に委ねるのか

を切り分け直す設計思想そのものに価値があります。
