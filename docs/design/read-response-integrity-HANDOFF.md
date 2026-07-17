# read-response-integrity 実装ハンドオフ(別セッション再開用)

最終更新: 2026-07-18。このファイルだけ読めば、別セッションで作業を再開できるように書いた。

---

## 0. 一言サマリ

PR #54(read relay)に対するセキュリティ指摘(issue #55)への対応。read 応答の完全性を、**メタデータ機密性(誰がどの content を持つか)を晒さずに**足す。

**最重要の設計訂正(2026-07-18)**: 当初計画にあった「owner 発行の member 証明」(コンポーネント C)は**廃止**。理由 → §2。現在の正しい設計は **A(版真正性)+ B(単調性)のみ**。

- 作業ブランチ: `feature/read-response-signing`(base = `fix/state-node-read-relay` = PR #54)
- PR 向き先: **`fix/state-node-read-relay`(#54)**。まだ PR は作っていない。
- 前提: production 利用ゼロ(テストのみ)。**後方互換不要・破壊的変更 OK・1 PR**。
- モデル: Fable 5 を使い続ける(ユーザー指示、メモリ `use-fable-5-model` 参照)。
- 設計本体: `docs/design/read-response-integrity.md`(冒頭に訂正あり)。

---

## 1. 何を防ぐか(訂正後)

#54 で対処済み: credential の content_id バインド、AES-GCM(暗号文本文の改ざん検知)。

本作業で足すのは以下(A + B のみ):

| 攻撃 | 防御 | 状態 |
|---|---|---|
| 非 member が偽データ/偽版を返す | **A: Node CBOR + CID 再計算**。攻撃者は正しい CID を持つ偽 Node を作れない | ✅ コア実装済み |
| ロールバック(過去の本物の版を最新と偽る) | **B: 単調性チェック**(前回見た版より祖先へ後退したら拒否) | ❌ 未実装 |

**防がない(既知の限界、脅威モデルに明記)**: 正規 member 自身による stale/ロールバック(否定的事実「より新しい版が無い」はネットワーク越しに証明不能)。

---

## 2. ⚠️ なぜ member 証明(C)を廃止したか

当初 §5.1.b で「owner が member 追加時に証明トークン(ES256 JWT, aud=node, can=host)を発行し、node が read 応答に添付、client が owner 鍵で検証」を採用した。**これは誤り**:

- **owner は誰が member かを知らないし、知り得ない**。member は DHT 複製配置・`add_member_to_content` で **owner の関与なく自律的に増減・入れ替わる**。「owner が member 追加時に発行」という経路が Monas に存在しない。
- 「署名の根が owner(read 認可)」と「member を認定するのが owner」は別問題。混同していた。

**結論**: member であることの確認は不要。データが CID で検証できれば、返した相手が誰でもよい(A で完結)。→ C は全面廃止。

---

## 3. コミット状況(このブランチ、`main..HEAD`)

設計ドキュメント(9 コミット、`3f80337`〜`ffe1db3`)は省略。実装コミットは以下:

1. `ec26c00` **A(サーバ + クライアント検証コア)** — 保持
2. `7970b35` **read 形式統一 + E2E verify-decrypt コア + verify_integrity 修正** — 保持
3. `3a64a5a` **C(member 証明)** — **⚠️ revert する**(§2)

`main..HEAD` の base コミット(`361bcc6` 以前)は #54 の中身。

---

## 4. 実装済みの中身(保持するもの)

### 4.1 コンポーネント A — 版真正性(完了・パリティ実証済み)

**state-node 側**(`ec26c00`, `7970b35`):
- `monas-state-node/src/port/content_repository.rs`: trait に `get_latest_node_bytes_with_version` / `get_version_node_bytes` 追加(Node CBOR を返す)。
- `monas-state-node/src/infrastructure/crdt_repository.rs`: 実装(`node.to_bytes()` = CBOR を返す)。
- `monas-state-node/src/test_utils.rs` / `infrastructure/auth/ucan_adapter.rs`: モック実装追加。
- `monas-state-node/src/application_service/state_node_service.rs`: `read_content_via_relay` が新メソッドを使い Node CBOR を返す。
- `monas-state-node/src/presentation/http_api.rs`: `/content/:id/data` と `/content/:id/version/:version` の **local 分岐も relay 分岐も Node CBOR を返すよう統一**(client がどちらでも同じ形式を検証)。`version` フィールドを必ず埋める。

**client 側**(`monas-content`):
- `monas-content/src/infrastructure/node_verification.rs`(新規): `recompute_node_cid`(CBOR → SHA-256 → CIDv1 RAW/SHA2-256)+ `verify_and_extract(node_bytes, expected_version_cid) -> VerifiedNode{ciphertext, parents}`。CID 不一致で拒否。
  - **crsl-lib パリティテスト済み**: 本物の crsl-lib `Node`(genesis + child)を作り `Node::content_id()` と一致確認。これが最大リスクで、クリア済み。
- `monas-content/src/application_service/content_service/service.rs`: `verify_and_decrypt_relay_read(node_bytes, expected_version_cid, local_content_id) -> VerifiedRead{plaintext, parents}` = 検証 → CEK ロード(`cek_store.load`)→ `decrypt_with_cek`(AES-GCM + content_id 照合)。**これが E2E 復号の再利用コア**。
- `monas-content/Cargo.toml`: `serde_cbor`, `cid`(serde feature), `multihash` 追加。dev-dep に `crsl-lib`(パリティ用)。

**verify_integrity 修正**(`monas-sdk/src/controller/state.rs`): state node が Node CBOR を返すようになったので、旧「生暗号文とバイト比較」が壊れる。`verify_and_extract` で CID 検証 + 暗号文抽出してから比較するよう修正済み。

### 4.2 廃止するもの(C, `3a64a5a`)— revert 対象

- `monas-account/src/application_service/command.rs`: `IssueMemberProofRequest`
- `monas-account/src/application_service/service.rs`: `issue_member_proof`
- `monas-account/src/application_service/mod.rs`: export 追加
- `monas-content/src/infrastructure/member_proof.rs`(新規ファイル)
- `monas-content/src/infrastructure/mod.rs`: `pub mod member_proof;`
- `monas-content/Cargo.toml`: dev-dep `monas-account`(member_proof パリティ用)
→ `git revert 3a64a5a` で概ね戻る(コンフリクトしたら mod.rs / Cargo.toml を手で調整)。member_proof.rs 削除を確認。

---

## 5. 残作業(A + B のみ、C は無し)

### 5.1 B — 単調性チェック(未実装)

目的: client が「content ごとに最後に見た version CID」を記録し、後退(祖先へのロールバック)を拒否。

- SDK ローカル sled(既存 `SledContentEncryptionKeyStore`、`monas-sdk/src/controller/mod.rs:246`)と同じ DB に `content_id -> last_seen_version_cid` の tree を新設。in-memory 版も(`mod.rs:230` に倣う)。
- 祖先判定: `verify_and_extract` が返す `VerifiedNode.parents`(親版 CID)を辿り、「last_seen が今回版の祖先か」を確認。祖先でなければ後退 → 拒否。親を辿るのに版指定 read で親 Node を順次取得(深さは bound、既定は実装で決める)。
- 追記のみ DAG(`new_child` で新 CID、既存 Node 不変)は確認済みなので誤検知しない。初回(記録なし)は TOFU 受理 + 記録。検証通過後に last_seen 更新。

### 5.2 実 read エンドポイント(未実装)— これが無いと「実際に使えない」

現状 SDK には「state node から暗号文を読んで復号してユーザーに返す」経路が**無い**(`get_content` はローカルストレージから復号)。新設が必要:

- SDK に新メソッド(例 `read_content_from_state_node`): auth 受け取り → `resolve_state_read_auth` → `get_state_node_history` で最新 version 決定 → `get_state_node_version_data`(Node CBOR base64)→ decode → `content_service.verify_and_decrypt_relay_read` → 単調性チェック(B)→ 平文返却。
- **入力は remote_content_id(state node 読み取り)と local_content_id(CEK 引き)の両方**が必要(local↔remote の対応表は無く、呼び出し側が両方渡す設計。`VerifyIntegrityInput` と同じ)。
- gateway(`monas-gateway/src/main.rs`)の read ハンドラに `HeaderMap` を足し `build_state_node_auth_context` を通す(現状 read は auth 非対応)。
- **CEK の欠落に注意**: share で受け取った content は unwrap した CEK が保存されない(`decrypt_shared_content` は即復号のみ)。自分が作成者なら `cek_store.load(local_id)` で取れる。share 経由も読めるようにするなら unwrap 済み CEK を `cek_store.save` する経路が別途要る(スコープ判断)。

### 5.3 テスト + PR

- 単体: A の改ざん拒否、B の後退拒否/初回受理。統合: relay read e2e(`monas-state-node/scripts/e2e-test.sh`)を Node 返却形式に更新。
- `cargo build/test/clippy/fmt` を content/sdk/state-node/account で green に。**Rust 1.97 の clippy で確認**(`rustup run 1.97.0 cargo clippy --workspace --all-targets --profile test --no-deps -- --deny warnings`。CI が最新 stable を入れるため。#54 で `for_kv_map`/`useless_borrows_in_formatting` に刺さった前例あり)。
- PR 作成: **base = `fix/state-node-read-relay`**。本文に「A+B のみ、member 証明は設計上不要として不採用」を明記。

---

## 6. 再開時の最初の一手

1. このファイルと `docs/design/read-response-integrity.md` 冒頭の訂正を読む。
2. `git revert 3a64a5a`(C を戻す)。ビルド green 確認。
3. 実 read エンドポイント(§5.2)→ 単調性(§5.1)の順で実装。
4. テスト → PR(§5.3)。

## 6.1 タスクリスト全体(チェックリスト)

前セッションの TaskCreate は引き継がれないので、ここに残す。

- [x] **A サーバ**: state-node が Node CBOR を返す(`ec26c00`)
- [x] **A クライアント**: monas-content で CID 再計算・検証 + crsl-lib パリティ(`ec26c00`)
- [x] **read 形式統一 + E2E verify-decrypt コア + verify_integrity 修正**(`7970b35`)
- [x] **設計訂正 + ハンドオフ doc**(`b41f454`)
- [ ] **C を revert**: `git revert 3a64a5a`(member 証明は設計上不要)
- [ ] **B 単調性チェック**: SDK sled に last_seen 記録 + parents 祖先判定(§5.1)
- [ ] **実 read エンドポイント**: SDK 新メソッド + gateway auth 転送 + CEK 入手(§5.2)。**これが無いと「実際に使えない」**
- [ ] **テスト**: A 改ざん拒否 / B 後退拒否・初回受理 / e2e-test.sh 更新(§5.3)
- [ ] **build/test/clippy/fmt green**(Rust 1.97 の clippy で確認、§5.3)
- [ ] **PR 作成**: base = `fix/state-node-read-relay`(#54)。本文に「A+B のみ、member 証明は不採用」明記

## 6.2 ユーザーからの確定事項(セッション履歴より)

- **1 PR のみ**で実装する。
- **後方互換は一切考慮しない。破壊的変更 OK**(production 利用ゼロ、テストのみ)。
- **PR 向き先は `fix/state-node-read-relay`(#54)**。
- **「実際に使えないと意味がない」** → 検証機構だけでなく、state node から読んで復号する**実 read 経路まで**作ること(§5.2 は必須、切り出し不可)。
- **member 証明は不要**(§2。owner は membership を知り得ない)。
- Fable 5 モデルを使い続ける。

## 6.3 実 read 経路で残っている設計判断(§5.2 の CEK 問題)

share で受け取った content は、unwrap した CEK が現状どこにも保存されない(`decrypt_shared_content` は即復号のみ)。実 read 経路で share 済み content も読めるようにするなら、unwrap 済み CEK を `cek_store.save` する経路が別途要る。**自分が作成者の content なら `cek_store.load(local_id)` で足りる**ので、初版は「作成者による自 content の read」に絞り、share 経由 read は別途、という切り分けも可(実装時にユーザー判断を仰ぐ)。

---

## 7. 主要な file:line リファレンス(調査済み)

- crsl-lib Node: `~/.cargo/git/checkouts/crsl-lib-*/e13b86c/src/dasl/node.rs`(`content_id`:76, `to_bytes`:90, `from_bytes`:104, `parents`:144)。rev pin = `e13b86ce...`。
- CEK ストア: `monas-content/src/infrastructure/key_store.rs`(sled key = `cek:{content_id}`)。
- 復号: `monas-content/src/infrastructure/encryption.rs`(AES-256-GCM, `[nonce12||ct||tag16]`)。
- decrypt_with_cek: `monas-content/src/application_service/content_service/service.rs:268`。
- SDK read: `monas-sdk/src/controller/state.rs`(`get_state_node_history`:83, `get_state_node_version_data`:104, `verify_integrity`:225)。
- SDK local read: `monas-sdk/src/controller/content.rs:842`(`get_content`, ローカル復号)。
- gateway: `monas-gateway/src/main.rs`(read ハンドラ:114, `build_state_node_auth_context`:284)。
- owner key_id 形式: `monas-account/src/application_service/service.rs:160`(`user:{hex(pubkey)}`, 自己完結型)。
