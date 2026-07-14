# read 経路の完全性: 署名付き応答の E2E 検証

- ステータス: **設計中(draft)**
- 関連: PR #54、issue #55
- 前提ブランチ: `feature/read-response-signing`(#54 の上に積む)

## 1. 目的

read の relay 応答に対して、**返ってきたデータ・版が正当な member によるものか**をクライアント側で暗号学的に検証できるようにする。#54 で対処済みの範囲(下記)では塞がらない、以下の攻撃を防ぐ。

- 偽データ注入(暗号文本文以外)
- 偽履歴の注入(存在しない版 ID の混入)
- ロールバック攻撃(過去の本物の版を「最新」として返す)
- 未検証ピア(DHT フォールバックで拾った非 member)への relay

### #54 で対処済み(本ドキュメントの対象外)

| 対処 | 手段 |
|---|---|
| credential 漏洩の悪用 | 読み取り署名を `read:{content_id}:{timestamp}` に content_id バインド |
| 偽データ注入(暗号文**本文**) | SDK 暗号化を AES-256-GCM (AEAD) に移行。改ざん・偽造本文は復号で失敗 |

## 2. 問題の構造 — 2レイヤー

read 経路には独立した2つの信頼問題があり、両方を埋めないと防御にならない。

### レイヤー1: 誰に聞くか(メンバーシップ)

`resolve_members`(`state_node_service.rs:449`)は、ローカルに `ContentNetwork` レコードがない場合、Kademlia DHT の近接ピア(`find_closest_peers`)をそのまま relay 先「member」として扱う。暗号学的検証はない。攻撃者は自分の PeerID を対象コンテンツの DHT キー近傍に置くだけで relay 先候補に入れる(正規 member である必要はない)。

さらに、ローカルの `ContentNetwork` レコード自体も gossip イベント(`ContentNetworkManagerAdded` / `Removed`、`events.rs:20-62`)のペイロードを無検証で保存・上書きしている。イベントに署名フィールドはない。

**既存の弱点(調査で判明)**: incoming request の member 判定は **libp2p PeerID 文字列**(ed25519 由来)を member set と照合している(`libp2p_network.rs:1546, 1616` の `has_member_str(&peer.to_string())`)。一方 `member_nodes` は **P-256 由来 NodeId**(`content_network.rs:14`)。型が食い違っており、現状の member 判定は署名検証ではなく文字列比較。本設計で整合を取る。

### レイヤー2: 返ってきた答えが正しいか(応答の完全性)

relay 先が返す `(data, version)`・履歴(版 CID リスト)には署名も系列検証もない。GCM が守るのは暗号文本文のみで、以下は素通りする。

- **偽履歴**: `get_history` / `get_latest_version`(SDK `controller/state.rs`)は relay 先が返す版 CID 文字列リストをそのまま信頼。
- **ロールバック**: 過去の本物の暗号文(正規 CEK で暗号化済み)を「最新」として返すと GCM は通り、クライアントは正常復号して「最新」と信じる。

**正常な stale read との区別**: 正規 member が sync 遅延で一時的に古い版を返すのは結果整合性として正常な仕様であり、守るべき挙動。攻撃との違いは「時間が経てば sync で自己修復するラグ」か「攻撃者が特定の相手に古い版/偽履歴を意図的に固定・注入し収束しない」か。検出軸は member/非 member でも新旧でもなく、**自己修復するラグか、収束しない改ざんか**。

## 3. libp2p が保証する範囲と、しない範囲

libp2p(Noise、`transport.rs:21`)が保証するのは**各ホップの相手 PeerID が本物であること**(トランスポート認証)だけ。

- **多段 relay では隣接ホップのみ認証** — A→B→C で A が検証できるのは「B と話した」ことだけ。C が誰か・member か・B が C の応答を正直に転送したかは libp2p レイヤーに現れない。中間ノードは中身を差し替え放題。
- **PeerID は「member であること」を語らない** — member は Monas アプリ層の概念(ContentNetwork)。

したがって「どこから read したかの証明」は libp2p から降ってこず、**アプリ層で作るしかない**。

## 4. 既存資産(調査結果)

設計は既存の鍵・検証部品・データ構造の上に構築できる。

### 4.1 署名鍵: node_key(P-256)が第一候補

state node は2種類の鍵を持つ:

| 鍵 | ファイル | 型 | 用途 |
|---|---|---|---|
| ed25519 peer key | `data_dir/peer_key.ed25519` | `libp2p::identity::Keypair` | トランスポート/PeerID のみ |
| **P-256 node_key** | `data_dir/node_key.pem`(生 32byte) | `NodeKeyPair`(`key_management.rs:9`) | **node 認証・NodeId・公開鍵証明の署名** |

read 応答署名には **node_key(P-256)** が自然。理由:
- 既に `NodePublicKey`(`public_key_protocol.rs:26`)で「node_id ↔ P-256 公開鍵」の所有証明に使用済み。
- `member_nodes` の NodeId が P-256 公開鍵ハッシュ由来(`content_network.rs:24`)なので、署名者鍵と member 判定が暗号学的に一致する。

### 4.2 再利用できる検証部品

- `crypto::verify_p256_signature`(`crypto.rs:34`、SHA-256 digest 方式、monas-account の署名と互換)
- `NodePublicKey`(`public_key_protocol.rs`、node_id+timestamp を P-256 署名する雛形)— read 応答署名の最も近い雛形
- `PublicKeyRegistry`(`port/public_key_registry.rs:12`、node_id → pubkey 取得。in-memory + sled 実装)

**注意**: 検証系が2系統ある — `signature_verifier.rs` は raw-message verify、`crypto.rs` は SHA-256 digest verify。応答署名では digest 方式(account 互換)に統一する。

### 4.3 系列検証は既存データ構造で原理的に可能

crsl-lib の `Node`(`dasl/node.rs:26`)は:

```rust
pub struct Node<P, M> {
    pub payload: P,          // ContentPayload { data, access_policy }
    pub parents: Vec<Cid>,   // 親版参照(複数可 = DAG)
    pub genesis: Option<Cid>,// 所属 genesis(genesis 自身は None)
    pub timestamp: u64,
    pub metadata: M,
}
```

- version CID = Node 全体(payload/parents/genesis/timestamp/metadata)の **CBOR → SHA-256**(`node.rs:76`)。**親が変われば CID も変わる**ため、CID を再計算すれば parents/genesis 参照の改ざんをクライアント側でも検知できる。
- 「同一系列所属」は `get_genesis(X) == G` で O(1) 判定可能(`dag.rs:425`、既に `crdt_repository.rs:226` で利用)。ただしこれは genesis フィールドの**自己申告一致**であり、genesis から parents を辿る**到達可能性の検証ではない**。
- 到達可能性(真の親子チェーン)を辿れる公開 API は `branching_history`(parent→children 隣接、`repo.rs:112`)のみ。`linear_history`/`get_history`/`latest` は CID の列/単体のみでエッジ情報を返さない。
- **crsl-lib の Node/Operation には署名も検証される author も無い**(author は Operation の自由文字列 `operation.rs:9`)。真正性は CRDT レイヤーでは担保されないので、**署名は state-node アプリ層で付与する**。

### 4.4 応答経路と署名フィールドの後方互換追加

read 応答は2区間で異なるシリアライズを経る:

- relay ワイヤ(node↔node): libp2p **CBOR** codec(`behaviour.rs:38`、`ContentResponse` を serde/CBOR)
- HTTP(caller node↔SDK): **JSON**

署名フィールドは **`Option` で後方互換に追加可能**(CBOR は末尾フィールド追加を無視/欠損=None、JSON は `#[serde(default)]`)。ただし E2E で運ぶには経路上の全型を通す必要がある:

| 層 | 型 | 場所 |
|---|---|---|
| member 戻り値 | `(Vec<u8>, String)` | `read_content_via_relay`(`state_node_service.rs:565`) |
| 内部 IPC | `RelayOutcome::Data { data, version }` | `libp2p_network.rs:55` |
| ワイヤ ★中心 | `ContentResponse::ContentData { content_id, data, version }` | `protocol.rs:106` |
| caller 分解 | `Ok((data, version))` | `libp2p_network.rs:1828`(現状 `..` で余剰フィールド破棄) |
| HTTP | `ContentDataResponse` | `http_api.rs:225` |
| SDK | `StateNodeContentDataResponse` | `models/state_node.rs:51` |

履歴も運ぶなら `ContentResponse::HistoryData`(`protocol.rs:129`)/ `ContentHistoryResponse`(`http_api.rs:232`)も同様。**caller の `libp2p_network.rs:1828` の分解パターン修正が必須**(現状署名を捨てている)。

## 5. 設計方針(たたき台 / 要レビュー)

### 5.1 何に署名するか

member は応答ごとに、以下を含むメッセージへ node_key(P-256)で署名する:

```
sign( content_id || version_cid || sha256(data) || timestamp )
```

- `sha256(data)` を含めることで本文の真正性を担保(GCM とは独立に、暗号文そのものの出所を保証)。
- `version_cid` を含めることで「どの版か」を署名対象に固定。
- `timestamp` で応答のリプレイ窓を制限。

署名は `ContentResponse::ContentData` に `signature: Option<Vec<u8>>` + `signer_node_id: Option<String>` として載せ、E2E で SDK まで運ぶ。

### 5.2 クライアント側の検証(3段)

1. **署名検証**: `signer_node_id` の公開鍵で署名を検証(公開鍵の入手経路は §6 の論点)。→ 応答が「その node の本物の発言」であることを保証。
2. **member 検証**: `signer_node_id` が対象コンテンツの正規 member か。→ ContentNetwork レコードの署名検証(レイヤー1)と連動。
3. **系列・単調性検証**:
   - **系列チェーン**: 版が genesis から parents で到達可能か。各版の `parents`/`genesis` をクライアントが取得できる口(現状 monas ラッパーに Node の parents を返す API が無い → `repo.dag.get_node()` 直呼びが必要。新設が要る)。
   - **単調性(ロールバック検出)**: クライアントが「前回見た版」をローカル記録し、返ってきた版がその祖先に巻き戻っていないか(monotonic / TOFU)。member/非 member 問わず効く。

### 5.3 メンバーシップ証明(レイヤー1)

`ContentNetwork` レコード(member リスト)に owner / genesis authority の署名を付け、gossip 受信時・DHT フォールバック時の両方で検証。§4.1 の弱点(PeerID 文字列 vs P-256 NodeId)もここで整合を取る。

## 6. 未解決の論点(設計で詰める)

1. **member 公開鍵の配布**: クライアントは `signer_node_id` の P-256 公開鍵をどう入手するか。`NodePublicKey` 交換(`libp2p_network.rs:1907`)は node 間のもの。クライアント(SDK)への配布経路が要る。ContentNetwork レコードに member の公開鍵を含める案が有力。
2. **メンバーシップ署名の権威**: 誰が member リストに署名する権利を持つか。owner か、genesis authority か。member 追加/削除のたびに再署名が必要。
3. **系列検証のコスト**: クライアントが毎回 genesis まで parents を辿るのは高コスト。どこまで検証するか(直近のみ / チェックポイント / 全チェーン)。
4. **単調性の状態管理**: 「前回見た版」をクライアントのどこに、どう永続化するか。複数デバイス間で不整合が出ないか。
5. **鍵ローテーション**: node_key / member 鍵のローテーション時に過去の署名をどう扱うか。
6. **段階導入**: 署名を `Option` にする以上、「署名を検証しないと拒否する」モードへの移行タイミング(新旧ノード混在期間の扱い)。

## 7. スコープと優先度

- すべて「攻撃者が read relay の経路に入れること」が前提。**クローズドな 4 ノード構成の現状では成立しない**。オープン参加型ネットワークにする前までに対応(Kademlia への Sybil/eclipse 攻撃が現実的になるため)。
- 実装は段階分割の想定: (a) 応答署名 + クライアント検証(レイヤー2 の中核)→ (b) 系列・単調性検証 → (c) メンバーシップ署名(レイヤー1)。
