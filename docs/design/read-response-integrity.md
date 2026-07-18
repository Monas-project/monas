# read 経路の完全性: 応答データの E2E 検証

- 関連: PR #54(read relay)、issue #55(セキュリティ指摘)、PR #56(実装)
- ステータス: 実装済み

relay 経由の read で返ってくるデータ・版・履歴には、もともと署名も系列検証もなかった。
本設計は、read 応答をクライアント側で暗号学的に検証し、さらに state node から
読んで復号する実 read 経路までを定義する。

## 1. 脅威モデル

### 1.1 前提: libp2p が保証しない範囲

libp2p(Noise トランスポート)が保証するのは**各ホップの相手 PeerID が本物であること**だけ。

- 多段 relay(A→B→C)で A が検証できるのは「B と話した」ことまで。C が誰か、
  B が C の応答を正直に転送したかはトランスポート層に現れない。中間ノードは中身を差し替えられる。
- PeerID は「member であること」を語らない(member は Monas アプリ層の概念)。

したがって read 応答の検証はアプリ層で行うしかない。

### 1.2 防ぐ攻撃

| 攻撃 | 防御 |
|---|---|
| 非 member / 中間ノードによる偽データ・偽版・偽履歴の注入 | **A: 版真正性**(§2) |
| ロールバック(過去の本物の版を「最新」と偽って返す) | **B: 単調性**(§3) |

なお #54 時点で対処済みのもの: 読み取り署名の content_id バインド
(`read:{content_id}:{timestamp}`)による credential 再利用の防止、
AES-256-GCM(AEAD)による暗号文本文の改ざん検知。

### 1.3 防がない(既知の限界)

**正規 member 自身による stale 提示のうち、クライアントが一度も見ていない範囲**は検出できない。
「より新しい版が存在しない」という否定的事実はネットワーク越しに証明不能なため。
sync 遅延による一時的な stale read は結果整合性として正常な仕様であり、守るべき挙動。
攻撃と区別できるのは「クライアントが既に受理した版より後退したとき」だけで、それは B が検出する。

## 2. コンポーネント A: 版真正性(CID 再計算)

state node は read 応答として、暗号文の生バイトではなく **crsl-lib `Node` 全体(CBOR)** を返す。
クライアントは受け取った CBOR バイト列から CID を再計算し
(`CIDv1(RAW, SHA2-256)`、crsl-lib の `Node::content_id()` と同一)、
要求した版 CID と一致することを検証する。

- CID はバイト列そのもののハッシュなので、一致すれば payload(暗号文)・parents・
  genesis・timestamp・metadata すべてが真正。**正しい CID を持つ偽 Node は作れない**ため、
  応答を返した相手が誰であっても改ざんは弾ける。署名は不要。
- local 分岐・relay 分岐とも同じ Node CBOR 形式で返す(クライアントは分岐を意識せず同一検証)。

実装:
- state node: `port/content_repository.rs` の `get_latest_node_bytes_with_version` /
  `get_version_node_bytes`、`presentation/http_api.rs`(`/content/:id/data`, `/content/:id/version/:version`)
- クライアント: `monas-content/src/infrastructure/node_verification.rs`
  (`recompute_node_cid` / `verify_and_extract`)。CID 再計算が crsl-lib の
  `Node::content_id()` とバイト一致することはパリティテストで担保
  (`cid` / `multihash` / `serde_cbor` のバージョンを crsl-lib に pin)。

### member 証明を採用しない理由

「owner が member 追加時に証明トークンを発行し、node が read 応答に添付する」案は
検討の上**不採用**とした。Monas では member は DHT 複製配置
(`add_member_to_content`)によって **owner の関与なく自律的に増減・入れ替わる**ため、
「owner が member 追加時に発行する」という経路がそもそも成立しない。
そして A により、データが暗号学的に正しければ返した相手の身元確認は不要になる。

## 3. コンポーネント B: 単調性(ロールバック検出)

クライアントは content ごとに「最後に受理した版 CID」(last_seen)をローカルに記録し、
最新読みの結果が last_seen の**子孫**(または同一)であることを確認する。

- 祖先判定は、今回受理した Node の parents から **CID 検証済みの親リンクだけ**を辿る
  (祖先 Node も版指定 read で取得し、A と同じ CID 検証を通す)。偽の親リンクで
  last_seen を祖先に見せかけることはできない。
- 初回(記録なし)は TOFU で受理して記録。検証通過後に last_seen を更新。
- 探索は fetch 上限 256 で打ち切り、**fail-closed**(拒否)。攻撃者が偽の深い DAG で
  クライアントに際限なく fetch させる DoS を防ぐ。
- 後退検出時は Conflict エラー(「ロールバック攻撃または stale relay の可能性」)。
- **版を明示指定した read は対象外**(過去の版を意図的に読む正当な操作。A のみ適用され、
  last_seen も更新しない)。
- 履歴 API(版 CID リスト)自体は無検証のままだが、履歴は「どの版を読むか選ぶ」ためだけに
  使われ、選んだ版の中身は A、新しさは B が守る。

実装: `monas-content/src/infrastructure/last_seen_version_store.rs`
(sled: 既存 DB に `last_seen:` prefix で同居 / in-memory)、
`monas-sdk/src/controller/state.rs`(`walk_ancestors_for`, `enforce_read_monotonicity`)。

## 4. 実 read 経路

検証機構だけでは使えないため、state node から読んで復号する経路を SDK / gateway に用意する。

### 4.1 フロー(`read_content_from_state_node` / gateway `POST /state/read`)

1. `read:{content_id}:{timestamp}` 署名の認証コンテキストを解決(gateway は auth ヘッダを転送)
2. 版を決定(明示指定、または履歴の最新)
3. Node CBOR を取得し CID 検証(**A**)
4. 最新読みなら単調性チェック(**B**)
5. ローカル cek_store から CEK を引き、AES-GCM 復号 + plain CID 照合
   (復号結果から plain content id を再計算して一致確認)

入力は `content_id`(state node 側の id)と `local_content_id`(CEK 引き当てと
plain CID 照合に使う)の両方。local↔remote の対応表は存在しないため呼び出し側が渡す。

エラーは呼び出し側が対処を判断できる形に写像する:

| 状況 | エラー |
|---|---|
| CID 不一致(改ざん) | Internal(検証失敗を明示) |
| 後退検出 / 探索上限 | Conflict |
| CEK がローカルに無い | NotFound(share envelope の処理を案内) |
| CEK で復号失敗 | Forbidden(CEK ローテーション後の鍵世代ずれ、または revoke の可能性を案内) |
| plain CID 不一致 | Conflict(content 更新後の古い local id の可能性を案内) |

### 4.2 share 受信者の read と CEK のライフサイクル

CEK はコンテンツ暗号鍵で、作成者は cek_store に保持している。share 受信者は
KeyEnvelope(受信者公開鍵で wrap された CEK)を受け取り、ローカルで unwrap して復号する。

- **CEK 永続化**: `decrypt_shared_content` の復号成功時
  (= CEK の正しさが証明された時点)に、unwrap 済み CEK を**受信者デバイスの
  ローカル cek_store** に保存する。以後、受信者も state node 経由の検証付き read で
  復号できる。CEK も平文もネットワーク・state node には一切出ない
  (state node は終始 ciphertext-only。E2E 暗号化の思想は不変)。
- **ローテーション追従**: revoke は「reencrypt(CEK ローテーション)→ ACL 更新 →
  残存受信者向け KeyEnvelope 再発行」の順で行い、再発行 envelope を
  `RevokeShareOutput.reissued_envelopes` として owner に返す。owner がこれを配布し、
  受信者が `decrypt_shared_content` で再処理すると保存済み CEK が上書き更新される。
  旧 CEK のまま新 ciphertext を読むと Forbidden で再処理へ誘導される。
- revoke の安全性は受信者の鍵破棄(強制不能)ではなく **CEK ローテーション**に依存する。
  取り消された受信者は過去に見た版を今後も復号できるが、それは平文を既に見ている以上
  避けられず、脅威モデル上も許容される。ローテーション後の新しい版は復号できない。

## 5. 検証

- SDK 統合テスト(`monas-sdk/tests/state_read_integration_test.rs`):
  作成者 read 往復 / share 受信者 read(CEK 永続化)/ 改ざん Node 拒否 /
  単調性(TOFU・前進・後退・明示版指定)/ CEK ローテーション追従
- 祖先探索の単体テスト(diamond DAG の重複排除、上限打ち切りの fail-closed 含む)
- crsl-lib との CID パリティテスト(`monas-content` 側)
