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

E2E で運ぶ必要があるのは、(A) の Node 全体バイト列(`data` を「生 payload」から「`Node::to_bytes()` の CBOR」に変える or 別フィールド追加)と、(B) の **owner 発行 member 証明トークン**(node 生署名ではない、§5.0.0)。いずれも **`Option` で後方互換に追加可能**(CBOR は末尾フィールド追加を無視/欠損=None、JSON は `#[serde(default)]`)。経路上の全型を通す必要がある:

| 層 | 型 | 場所 |
|---|---|---|
| member 戻り値 | `(Vec<u8>, String)` | `read_content_via_relay`(`state_node_service.rs:565`) |
| 内部 IPC | `RelayOutcome::Data { data, version }` | `libp2p_network.rs:55` |
| ワイヤ ★中心 | `ContentResponse::ContentData { content_id, data, version }` | `protocol.rs:106` |
| caller 分解 | `Ok((data, version))` | `libp2p_network.rs:1828`(現状 `..` で余剰フィールド破棄) |
| HTTP | `ContentDataResponse` | `http_api.rs:225` |
| SDK | `StateNodeContentDataResponse` | `models/state_node.rs:51` |

追加フィールドの想定: `node_bytes: Option<Vec<u8>>`(A 用、Node 全体)と `member_proof: Option<String>`(B 用、owner 発行 JWT)。**member リスト・node 生署名は載せない**(§5.0.0)。**caller の `libp2p_network.rs:1828` の分解パターン修正が必須**(現状 `..` で余剰フィールドを捨てている)。

## 5. 設計方針(たたき台 / 要レビュー)

### 5.0.0 機密性の制約(メタデータプライバシー) ★設計の大前提

**完全性を足すために、メタデータ機密性(誰がどの content を管理しているか)を悪化させてはならない。**

背景: 当初案(member 集合を晒す / member node 鍵で応答に署名)は、完全性は満たすが機密性を壊す。「member リスト全体が見える」ことは「単体の member が見える」現状より質的に一段危険:

| 観点 | 単体が見える(現状 relay) | リスト全体が見える(避けるべき) |
|---|---|---|
| 可用性攻撃 | 冗長化(replication)が守る | **全 member 特定で冗長化が無効化** — 一番効く |
| 名寄せ・相関 | 点が繋がりにくい | ノード共起グラフが組め、名寄せ可能 |
| 非否認性 | 揮発的(観測のみ) | 署名を載せると**永続的な証拠**が残る |

したがって設計制約:

1. **member 集合(リスト)を relay ノード・クライアントに晒さない。** 現状 relay が漏らす範囲(応答した単体ノード)を超えて広げない。
2. **応答した個別ノードが「自分は正規 member だ」を単体で証明する**形にする。集合を見せずに単体の正当性だけ検証する。
3. member node 鍵の**生署名を relay に残さない**(非否認性の劣化を避ける)。証拠が残るなら、node 身元と結びつかない形にする。

### 5.0 鍵レイヤーの整理(調査で確定)

設計に関わる鍵は**別レイヤーの2種類**で、混同しないこと。

| 鍵 | 実体 | 管理 | 用途 |
|---|---|---|---|
| **ユーザー鍵**(owner) | `AccessPolicy.owner` = `Identity{id: hex(P-256 pubkey), type: User}`(`identity.rs:15`, `access_policy.rs:21`) | monas-account | 誰がコンテンツの所有者か。read 認証もこの鍵の署名 |
| **node 鍵**(member) | `member_nodes` の NodeId = P-256 node_key 由来(`content_network.rs:24`) | 各 state node(`node_key.pem`) | 誰がコンテンツを複製保持する node か |

→ **メンバーシップ(誰が member か)の権威はユーザー鍵(owner)、応答の発言者は node 鍵(member)**。§5.3 のメンバーシップ署名は owner のユーザー鍵で、§5.1 の応答署名は member の node 鍵で行う。

### 5.0.1 重要な発見: Node 全体を返せば、データ真正性と系列は署名なしで検証できる

crsl-lib の `Node` は `to_bytes()`(CBOR)/`from_bytes()` が公開されており(`node.rs:90/104`)、`content_id()` はその CBOR バイト列の SHA-256(`node.rs:76`)。したがって:

- member が生 `data` ではなく **シリアライズした `Node` 全体**(payload + parents + genesis + timestamp + metadata)を返せば、クライアントは:
  1. **`from_bytes` → `content_id()` を再計算 → 要求した version CID と一致するか**でデータ本文と親参照の改ざんを検知できる(**署名不要**。CID = 内容ハッシュなので、CID が正しければ中身は正しい)
  2. Node に含まれる `parents` / `genesis` で系列を辿れる

- つまり **署名が本質的に必要なのは「これが最新である」という否定的事実**(=より新しい版が存在しないこと)だけに絞り込める。データの真正性・系列は content-addressing で足りる。

**機密性との両立**: Node の中身は暗号文(payload.data は SDK が暗号化済み)なので、Node 全体を返してもコンテンツ内容は漏れない。ただし §5.0.0 の制約から、Node を返すこと自体が「応答した単体ノードがこの content を持つ」ことを示す点は現状 relay と同じ(単体レベル)であり、それを超えない。**member リストや node 生署名は載せない。**

この発見により設計を2つに分離できる:

- **(A) 版指定 read**(`version` を指定):**署名不要**。member は Node を返し、クライアントは CID 再計算で検証。改ざん・偽データは弾ける。機密性の追加漏洩もゼロ(content-addressing のみ)。
- **(B) 最新 read / 履歴**(`version: None`):member の「これが最新」という主張は content-addressing では検証できない(否定的事実のため)。ここに完全性の裏付けが要るが、**§5.0.0 の制約下でどう作るかが本設計の核心**(§5.1)。

### 5.1 「最新である」の完全性を、機密性を壊さずに足す

「これが最新」の否定的事実には裏付けが要るが、member node 鍵の生署名(§5.0.0 が禁じる)は使えない。代わりに2つのアプローチを組み合わせる。

#### 5.1.a 単調性チェック(node 証明不要・機密性ゼロ影響)★まず必須

クライアントが「その content について自分が最後に見た version CID」をローカルに記録し、**新しい応答がその版の祖先(=巻き戻り)なら拒否/警告**する(TOFU 的 monotonicity)。

- ロールバック攻撃(過去の本物の版を最新と偽る)を検出できる。
- 版指定 read(A)で Node を取得できるので、返ってきた版から parents を辿り「前回見た版が祖先に含まれるか」を確認できる。含まれなければ巻き戻り。
- **node の身元も member リストも一切要らない。** relay に何の証拠も残さない。機密性への影響ゼロ。
- 限界: 「自分が初めて読む content」には基準がない(TOFU の初回問題)。また「最新を隠して古いが正当な版を出す」stale は検出できるが、「まだ誰も見ていない最新」の欠落は原理的に検出不能(否定的事実)。

#### 5.1.b owner 発行の member 証明(単体・リスト非公開)— レイヤー1 兼用

応答ノードが正規 member であることを、**リストを晒さず単体で**証明する。既存の owner 署名委任トークン(`service.rs:98-133`、`{iss: owner, aud: recipient, att: [{with: "monas://content/{cid}", can}]}` を owner P-256 鍵で ES256 署名)を **member 証明**に転用する:

- owner が各 member node に対し「この content の member である」証明トークン(`aud = member の node 公開鍵 key_id`、`att = {with: content, can: "host"}` 等)を発行。
- 応答時、member は**自分宛の証明トークン**を応答に添える。クライアントは owner 公開鍵(= `AccessPolicy.owner`、read 認証で既に既知)で検証し、「owner がこのノードを member と認めている」ことを確認。
- **リスト全体は出ない** — 応答した1ノードの証明だけ。他の member が誰かは分からない。§5.0.0 の制約を満たす。
- 非否認性: トークンは owner→当該 node の委任なので、「node が自分の身元で署名した証拠」ではなく「owner がこの node を認可した証拠」。member 集合の共起グラフには使えず、劣化は限定的。ただし「owner がこの content をこの node に置いた」事実は残るため、**この証明を応答ごとに常時添付するか、要求時のみか**は §6 の論点。

#### 5.1.c 版の真正性(A で解決済み・再掲)

「最新」と主張された版そのものの中身の真正性は §5.0.1(A)の CID 再計算で担保。5.1.a/5.1.b は「その版が本当に最新の系列に属し、正規ノードが出したか」を補う。

### 5.2 クライアント側の検証フロー

最新 read の場合:

1. **版の真正性**: 応答の Node を `from_bytes` → `content_id()` 再計算し、応答が主張する version CID と一致するか(§5.0.1)。不一致なら偽データ → 拒否。
2. **単調性**: ローカル記録の「最後に見た版」が、今回の版の祖先か(parents を辿る)。巻き戻りなら拒否/警告(§5.1.a)。
3. **member 証明**(有効化時): 応答に添えられた owner 発行の member 証明トークンを owner 公開鍵で検証(§5.1.b)。無効 or 欠落は段階導入モードに従い warn/拒否。
4. 検証通過後、ローカルの「最後に見た版」を更新。

member リストの取得・検証は**フローに現れない**(晒さないため)。

### 5.3 メンバーシップ証明 — 単体・リスト非公開(改訂)

当初案(`ContentNetwork` リストに owner 署名を付けて配布)は**リスト全体を晒すため §5.0.0 に反する**ので採らない。代わりに §5.1.b の **owner 発行の単体 member 証明トークン**で「応答ノードが member か」を検証する。

- owner が各 member node に個別に発行する証明トークンなので、**リストとして流通しない**。クライアントが目にするのは「応答した1ノードの証明」だけ。
- gossip の `ContentNetworkManagerAdded` イベント無検証問題(§2 レイヤー1)は、node 側が「自分が member になった証拠」= owner 発行トークンを保持し、relay 応答時に提示する形で解消。node 間で member 集合を交換・保存する必要が減る。
- §4.1 の弱点(member 判定が libp2p PeerID 文字列 vs P-256 NodeId)は、証明トークンの `aud` を P-256 node 公開鍵に統一することで整合を取る。

## 6. 論点への推奨(機密性制約 §5.0.0 反映後)

1. **member 公開鍵の配布** → **配布しない(リスト非公開)**。当初の「ContentNetwork レコードに member 公開鍵一覧を同梱」案は撤回。クライアントが検証するのは owner 公開鍵(既知)で署名された**単体の member 証明トークン**(§5.1.b)のみ。各 member の node 公開鍵はトークンの `aud` として1件ずつ現れるだけで、集合は出ない。

2. **member 証明の権威** → **owner のユーザー鍵**。`AccessPolicy.owner`(P-256 pubkey、read 認証で既知)が member 証明トークンを ES256 署名(既存 `service.rs:98-133` / `jwt_signer.rs` を転用)。member 追加時に owner がそのノード宛トークンを発行、削除は TTL 失効 + `min_valid_issued_at` 相当の一括失効(既存の token 失効機構、design.md §10)を流用。**残論点**: owner オフライン時の member 追加 → 既存の write 委任と同じく、管理権限の委任トークンで移譲する形を検討(初版は owner online 必須で割り切り可)。

3. **系列検証のコスト** → **通常は単調性チェックのみ(前回版が今回版の祖先かを parents で辿る短いパス)、全チェーン検証はオンデマンド**。版指定 read は CID 再計算だけで足りる(§5.0.1)ため毎回 genesis まで辿らない。監査時のみ全チェーン。

4. **単調性の状態管理** → **SDK のローカル sled に「content_id → 最後に見た version CID + timestamp」を記録**。SDK は既に `SledContentEncryptionKeyStore`(`controller/mod.rs:246`)を持つので同 DB に足す。**追記のみ DAG を実コードで確認済み**(更新は `new_child` で新 CID を作り parents で前版を指す、既存 Node は不変 — `node.rs:53`, `crdt_repository.rs:563`)なので、正規の巻き戻しは発生せず誤検知しない。複数デバイスは各自の観測履歴を持てばよく状態共有不要(v3→v5 の前進は正常、v5→v3 の後退のみ警告)。

5. **鍵ローテーション** → member 証明トークンの `exp` / `iat` で世代管理。node 鍵ローテーション時は owner が新しい `aud`(新公開鍵)のトークンを再発行、旧トークンは TTL 失効。初版はローテーション非対応でも可。

6. **段階導入** → **3 モードで移行**: (i) member 証明を応答に付けるが**検証しない**(観測のみ) → (ii) あれば検証、無ければ warn で通す → (iii) 必須(無い/無効は拒否)。単調性チェック(§5.1.a、機密性影響ゼロ)は依存物が無いので**先行して (iii) 相当まで入れてよい**。member 証明(§5.1.b)はオープン化前に (iii) へ。

### 6.1 ユーザーに確認したい設計判断

- **member 証明の添付頻度**(非否認性 vs 検証可能性): owner→node の証明を**応答ごとに常時添付**するか、**クライアントが要求したときだけ**か。常時添付は検証が確実だが「owner がこの content をこの node に置いた」事実が応答経路に露出しやすい。要求時のみは露出を絞れるが未検証応答が増える。
- **owner オフライン時の member 管理**(論点2): 管理権限の委任を入れるか、初版は owner online 必須で割り切るか。
- **単調性の強制タイミング**: §5.1.a を先行して拒否モードまで入れてよいか(機密性影響ゼロ・依存なしのため技術的には即可)。
- **実装の分割単位**: §7 の段階を別 PR にするか。

## 7. スコープと優先度

- すべて「攻撃者が read relay の経路に入れること」が前提。**クローズドな 4 ノード構成の現状では成立しない**。オープン参加型ネットワークにする前までに対応(Kademlia への Sybil/eclipse 攻撃が現実的になるため)。
- **機密性制約 §5.0.0 は全段階で不変の前提**。完全性を足す各段が member 集合を晒していないか、各 PR でチェックする。
- 実装の段階分割(依存順):
  1. **版の真正性(A)** — member が Node 全体を返す + クライアント CID 再計算。署名不要・機密性影響ゼロ。最優先で独立に入る。
  2. **単調性チェック(§5.1.a)** — SDK ローカル記録 + 祖先判定。機密性影響ゼロ・依存なし。1 と並行可。
  3. **owner 発行 member 証明(§5.1.b / §5.3)** — owner 署名トークン発行 + 応答添付 + クライアント検証。段階導入 (i)→(iii)。オープン化前に必須化。
