# read 経路の完全性: 署名付き応答の E2E 検証

- ステータス: **方式確定(2026-07-18)、実装計画待ち**
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

#### 5.1.b owner 発行の member 証明(単体・リスト非公開)— レイヤー1 兼用 ★採用決定(2026-07-18)

応答ノードが正規 member であることを、**リストを晒さず単体で**証明する。既存の owner 署名委任トークン(`service.rs:98-133`、`{iss: owner, aud: recipient, att: [{with: "monas://content/{cid}", can}]}` を owner P-256 鍵で ES256 署名)を **member 証明**に転用する:

- owner が各 member node に対し「この content の member である」証明トークン(`aud = member の node 公開鍵 key_id`、`att = {with: content, can: "host"}` 等)を発行。
- 応答時、member は**自分宛の証明トークン**を応答に添える。クライアントは owner 公開鍵(= `AccessPolicy.owner`、read 認証で既に既知)で検証し、「owner がこのノードを member と認めている」ことを確認。
- **リスト全体は出ない** — 応答した1ノードの証明だけ。他の member が誰かは分からない。§5.0.0 の制約を満たす。
- 非否認性: トークンは owner→当該 node の委任なので、「node が自分の身元で署名した証拠」ではなく「owner がこの node を認可した証拠」。member 集合の共起グラフには使えず、劣化は限定的。

**なぜ owner が信頼の根になるか(設計議論の記録)**: member の証明は「読み手が既に信頼している何か」に根を張る必要がある(宙に浮いた証明は攻撃者も同じ形で主張できる)。読み手が確実に持つ信頼の起点は **owner の公開鍵だけ** — 読み手の read 権限自体が owner 署名の委任で付与されるため。member 自身の鍵(攻撃者も名乗れる)、NodeID↔鍵のハッシュ関係(「この content の member か」を語らない)、CEK(読み手も持つので member を区別できない)はいずれも根にならない。「誰が member かを決める権威 = owner」の必然的帰結として、証明の署名者も owner になる。**owner は発行時に一度署名するだけで、read 処理のたびに介在するわけではない。**

**owner 公開鍵の可視性について**: 検証の成立自体は owner 公開鍵の秘匿を必要としない(署名検証は公開鍵で行う。重要なのは読み手が「正しい owner 鍵」を権限付与経路で得ていること)。ただしメタデータ機密性の観点では、証明トークンの `iss`(owner key id)が relay 中継ノードに見えると「owner ↔ content ↔ node」のリンクが漏れる。緩和策: 証明トークンを**読み手宛に暗号化して運ぶ**(中継には不透明)、または要求時のみ添付。owner 公開鍵が関係者(権限保持者)以外に知られていない運用なら、`iss` が見えても外部者は owner を同定できないため、露出はさらに限定される。実装フェーズで添付方式と合わせて確定する。

**この方式が防ぐもの / 防がないもの(明確化)**:
- ✅ 防ぐ: **非 member のなりすまし**(DHT フォールバックで拾われた無関係ノードが偽応答・偽履歴を返す)— 証明を出せないので弾ける。指摘 #54 レビューの主シナリオはこれ。
- ❌ 防がない: **正規 member 自身が古い版を「最新」と返す**こと(悪意 or 単なる sync 遅延)。証明は出せてしまう。これは分散システムの原理的限界(否定的事実「より新しい版が無い」はネットワーク越しに証明不能)であり、§5.1.a の単調性チェックによるベストエフォート検出 + 「既知の限界」として脅威モデルに明記する。

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

### 6.1 設計判断の状況(2026-07-18 更新)

**決定済み**:
- **方式**: §5.1.b(owner 発行の単体 member 証明 + member 応答)+ §5.1.a(単調性)+ (A) CID 再計算、の組み合わせで確定。owner は発行時のみ介在し read 経路には入らない。
- **鮮度の限界の受容**: 正規 member 自身によるロールバック/stale は原理的に防げないことを「既知の限界」として脅威モデルに明記する(§5.1.b)。

**実装前提の確定(2026-07-18)**: production 利用ゼロ(テストのみ)のため、**後方互換は一切考慮しない。破壊的変更 OK。1 PR で全実装**。これに伴い:
- **段階導入(3 モード)は廃止** — 最初から検証必須(検証失敗 = 拒否)で実装する。`Option` フィールドでの共存も不要、ワイヤ型は直接置き換える。
- **member 証明の添付方式**: **常時添付**で開始(シンプル優先)。`iss` の読み手宛暗号化は初版では入れず、§5.1.b の緩和策として TODO 記録に留める(クローズド環境のうちは露出リスクが実質ない)。
- **owner オフライン時の member 追加**: 初版は **owner online 必須**で割り切る(委任は将来)。
- **単調性**: 最初から拒否モード。

### 6.2 検討して却下した案(再検討防止の記録)

1. **署名付き member リストの配布** — リスト全体が晒され、冗長化の無効化・名寄せ・非否認性の劣化を招く(§5.0.0)。却下。
2. **member node 鍵の生署名を応答に載せる** — 「この node がこの content を持つ」永続的証拠が残る。owner→node 委任トークンで代替(§5.1.b)。
3. **envelope への最新版 CID 埋め込み** — 調査の結果、envelope(HPKE wrapped CEK)は**共有付与時に1回だけ**配布され、通常の update では再配布されない(`update_content` は share/envelope に一切触れない)。静的に埋めた CID は初版で固定され最新を追えない。却下。なお envelope の HPKE aad には content_id が既にバインドされており「この envelope はこの版のもの」の認証は既存機構で効いている。
4. **認証付き可変「最新ポインタ」**(JWT の未使用 `fct` フィールド等に最新 CID を載せる案を含む) — ポインタ自体が「最新性を保証すべき可変状態」になり、同じ問題が再帰する(そのポインタは最新か?)。同期・更新コストも生む。却下。
5. **CEK による member 証明** — CEK は読み手・書き手・(設計次第で)member 全員が持つため「member だけ」を区別できない。却下。

## 7. スコープと前提

- すべて「攻撃者が read relay の経路に入れること」が前提。**クローズドな 4 ノード構成の現状では成立しない**が、オープン参加型移行前に必要なので今のうちに入れる(Kademlia への Sybil/eclipse 攻撃が現実的になるため)。
- **機密性制約 §5.0.0 は不変の前提**。完全性を足す実装が member 集合を晒していないかを実装中チェックする。
- **後方互換なし・破壊的変更 OK・1 PR**(§6.1)。

## 8. 実装計画(1 PR)

3 コンポーネントを 1 PR で実装する。依存順に記載するが同一 PR。すべて既存コードの file:line は §4 の調査に基づく。

### 8.0 検証ロジックの置き場所 = `monas-content`(2026-07-18 修正)

**検証は `monas-sdk` ではなく `monas-content` に置く。** 理由:
- `monas-sdk` は `monas-content` に依存する薄い API 層(`monas-sdk/Cargo.toml:10`)。コンテンツの暗号処理(復号 `domain/content/encryption.rs`、CID 計算 `infrastructure/content_id.rs`、CEK 管理、share/envelope)は**すべて既に `monas-content` に集約**されている。read の完全性検証もコンテンツドメインの責務なのでここに属する。
- SDK は「検証する `monas-content` の口を呼ぶだけ」に留め、JWT 検証・CID 再計算などの暗号ロジックを SDK に持ち込まない。

**CID 再計算の重要な差異**: `monas-content` 既存の `Sha256ContentIdGenerator`(`content_id.rs:9`)は `SHA-256(raw_content)` を hex 化するだけで、**crsl-lib の Node CID(`SHA-256(CBOR(Node全体))` → CIDv1 RAW/SHA2-256、`node.rs:76`)とはアルゴリズムもエンコードも別物**。version CID の再計算には crsl-lib 準拠の実装が要る。`content_id.rs:6` に `todo: crslのcid生成を使用する` とある通り元々 crsl 準拠にしたい意図があるので、**`monas-content` に crsl-lib 準拠の Node CID 計算を新設**(既存 generator とは別関数)してこの TODO を回収する。crsl-lib を `monas-content` 依存に足すか、CBOR+SHA-256+CID の軽量実装を `monas-content` 内に持つかは 8.6 で判断。

### 8.1 コンポーネント A: 版真正性(Node 全体を返して CID 再計算)

**目的**: member の read 応答が「生 payload」ではなく `Node` 全体(CBOR)を返すようにし、クライアントが CID を再計算して改ざん検知する。

**state-node 側**:
1. `crdt_repository.rs` の `get_version` / `get_latest_with_version`(`:184, :207, :232`)が現状 `node.payload().data.clone()` を返すのを、**`node.to_bytes()`(CBOR 全体)を返す**ように変更。戻り値型を「payload バイト列」から「Node CBOR バイト列」へ。※ port trait `content_repository.rs` のシグネチャも変更。
2. `read_content_via_relay`(`state_node_service.rs:565`)の戻り値 `(Vec<u8>, String)` の `Vec<u8>` を Node CBOR に。
3. ワイヤ: `ContentResponse::ContentData { content_id, data, version }`(`protocol.rs:106`)の `data` を Node CBOR に(意味を変えるだけで型は `Vec<u8>` のまま。フィールド名を `node_bytes` にリネームして意図を明示)。内部 `RelayOutcome::Data`(`libp2p_network.rs:55`)も同様。
4. HTTP `ContentDataResponse`(`http_api.rs:225`)/ SDK `StateNodeContentDataResponse`(`models/state_node.rs:51`)の `data` も Node CBOR(base64)に。

**クライアント検証(`monas-content` に実装、SDK はそれを呼ぶ)**:
5. `monas-content` に crsl-lib 準拠の Node CID 再計算 + 検証関数を新設(§8.0)。Node CBOR を受け取ったら CID 再計算 → 要求 version と一致を検証。不一致は**拒否**。
6. 検証後、Node の `payload.data`(暗号文)を取り出して既存の復号(`domain/content/encryption.rs`、AES-GCM)に渡す。復号・CID 検証とも `monas-content` 内で完結し、SDK は結果を受け取るだけ。

### 8.2 コンポーネント B: 単調性チェック(ロールバック検出)

**目的**: SDK が「content ごとに最後に見た version CID」を記録し、後退した応答を拒否。

1. SDK ローカルストア: 既存 `SledContentEncryptionKeyStore`(`controller/mod.rs:246`)と同じ sled DB に **`content_id → last_seen_version_cid` ストア**を新設(新しい tree/prefix)。in-memory 実装も対で用意(`controller/mod.rs:230` に倣う)。
2. 祖先判定: 応答の Node から `parents`(`node.rs:144`)を辿り、「記録済みの last_seen が今回版の祖先に含まれるか」を確認。含まれない(= 後退 or 分岐)なら**拒否/警告**。
   - 辿るために親版の取得が要る場合がある → 版指定 read(A)で親を順次取得。深さは実装で bound(全チェーンは監査時のみ、§6 論点3)。
3. 検証通過後、last_seen を今回版に更新。初回(記録なし)は TOFU で受理 + 記録。

### 8.3 コンポーネント C: owner 発行 member 証明

**目的**: 応答ノードが正規 member であることを、リストを晒さず単体で証明。

**owner(monas-account)側 — 証明発行**:
1. 既存の委任トークン発行(`service.rs:98-133`、`DelegationClaims { iss, aud, exp, iat, jti, att }` を ES256 署名)を転用し、**member 証明トークン**を発行する口を追加。`aud = member の node 公開鍵 key_id`、`att = [{ with: "monas://content/{cid}", can: "host" }]`(`can` に `host` を追加、`DelegatedCapability` / `CapabilityAction` に enum 追加)。
2. member 追加フロー(`add_member_to_content` 系、`state_node_service.rs:1564` 周辺)で、owner がこのトークンを発行し、対象 member node に配布する経路を追加。member node はトークンを永続化。

**member node 側 — 応答に添付**:
3. `read_content_via_relay`(`state_node_service.rs:565`)/ `read_history_via_relay`(`:598`)の応答に、自ノードの member 証明トークンを載せる。ワイヤ `ContentResponse::ContentData` / `HistoryData` に `member_proof: String`(必須)を追加。内部 `RelayOutcome`・HTTP・SDK 型も同様に追加(§4.4 の経路表の全型)。
4. caller の分解 `libp2p_network.rs:1828`(現状 `..` で余剰を捨てている)を修正し、`member_proof` を通す。

**クライアント検証(`monas-content` に実装)**:
5. 応答の `member_proof` を **owner 公開鍵**で ES256 検証(`monas-content` に検証関数を新設。既存の署名検証/鍵管理と同居)。`att.with` が要求 content と一致、`exp` 未失効を確認。無効/欠落は**拒否**。
6. owner 公開鍵の入手(§8.6 参照): SDK/content が持つ委任トークンの `iss` から導出できるか確認。導出できれば追加 API 不要。

### 8.4 検証フロー統合(SDK, §5.2)

最新 read で以下を順に。1つでも失敗したら拒否:
1. A: Node CBOR → CID 再計算 = 主張 version か
2. C: member_proof を owner 鍵で検証(member か)
3. B: last_seen が今回版の祖先か(後退でないか)
4. 全通過 → 復号して返す + last_seen 更新

### 8.5 テスト計画

- A: 改ざん Node(payload 書き換え)→ CID 不一致 → 拒否を検証。
- B: v5 を見た後に v3 を返す → 後退拒否。初回 v3 は受理。
- C: 非 member(証明なし/他 content の証明)→ 拒否。正規 member の証明 → 受理。owner 鍵違い → 拒否。
- 統合: 既存の relay read e2e(`e2e-test.sh`)を Node 返却 + 証明必須に更新。
- **§5.0.0 チェック**: 応答・ログに member 集合が現れないことをテスト/レビューで確認。

### 8.6 実装前に確定した事項(調査済み 2026-07-18)

**(1) CID 再計算は `monas-content` に crsl-lib 準拠で新設**(§8.0)。`monas-content` は現状 crsl-lib 非依存。選択肢:
- (a) crsl-lib を `monas-content` 依存に追加し `Node::from_bytes`/`content_id()` を直接使う。確実だが DAG ライブラリ全体(leveldb 等)を持ち込む。
- (b) **【推奨】`monas-content` に軽量 Node CID 計算を自前実装**: Node の CBOR を最小限デコード(`payload`/`parents`/`genesis`)+ 受信 CBOR 全体を SHA-256 → CIDv1(RAW/SHA2-256、`node.rs:76-81` と同一手順)。`serde_cbor` + `sha2` + `cid` で足りる。`content_id.rs:6` の TODO 回収も兼ねる。
- → **(b) を採用**。CBOR スキーマ一致テスト(state-node が出す Node CBOR を `monas-content` が再計算して一致)を必須にする。crsl-lib のバージョンは rev pin(`Cargo.toml:51`)なのでスキーマ固定でよい。

**(2) owner 公開鍵の入手経路**: `AccessPolicy` は state-node ドメインで content/SDK には無い。member 証明を owner 鍵で検証するには入手経路が要る:
- read 認可のために content/SDK は既に「自分の権限(委任トークン)」を持つ。そのトークンの `iss` が owner なので、**owner 公開鍵は委任トークンの `iss` から得られる**可能性が高い(要確認: `iss` が pubkey そのものか key_id か。`service.rs` の `owner_key_id = key_id_from_public_key(...)` を見る限り key_id。key_id から pubkey を復元できる形式か確認)。
- **確認済み(2026-07-18)**: owner key_id は `user:{hex(public_key)}`(`service.rs:160-161` `key_id_from_public_key`)で**公開鍵そのものを内包する自己完結型**。委任トークンの `iss` から hex デコードするだけで owner 公開鍵が復元でき、**追加の取得 API・通信は不要**。member 証明の検証に必要な鍵は読み手が既に持つ委任トークンから取れる。

### 8.7 実装中に判定する TODO

- 単調性の祖先探索の深さ bound の既定値。8.2-2。
- member 証明の配布経路(owner→member node)の具体。8.3-2。
- member 証明トークンの永続化先(member node 側)。8.3-2。
- `member_proof` の `iss` 露出緩和(読み手宛暗号化)は初版スコープ外・TODO 記録のみ(§6.1)。
