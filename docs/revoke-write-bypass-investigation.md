# Revoke後の書き込みバイパス調査 — 旧delegated tokenの書き込みがstate nodeに受理される

- 日付: 2026-09-10
- 発見経緯: example-ui のデモ録画（revoke/削除/権限変更ジャーニー）の自動実行中に検出。2回連続で再現（cutoff伝播待ち10秒を入れても再現）
- 対象: `monas-ui-wt` worktree（branch `feat/example-ui-monas-drive`）+ demoノード node1〜node4.monas-demo.net
- 深刻度: High — revoke の完全性保証（revoke後は書き込めない）がクラスタ全体で成立していない。機密性は CEK ローテーションで維持されている（後述）

## 症状

再現ジャーニー（`.demo-permissions.mjs` Phase D）:

1. Alice (owner, gateway :3000 → node1) がファイルを作成し、Bob (gateway :3001 → node2) に read+write で共有
2. Alice が Bob を revoke
   - UI/SDK 上は成功: 「Invalidate prior tokens: Token cutoff advanced on the state-node first — before rotation, so the revoked recipient cannot write in between」「token cutoff 1789033235」
3. Bob の旧tokenでの「Edit contents」の **読み込みは拒否される**（Could not load contents）
4. しかし **10秒以上待った後の保存（update）は受理される**:
   `PUT bafkrei… accepted: token gP61Fq… grants write`
5. Alice の verified read でネットワーク head が Bob の書き込み（"this must not land"）に置き換わったことを確認
   - 証跡スクリーンショット: `/tmp/monas-demo2-videos/bug-head-after-revoked-write.png` ほか（bug-write-accepted-{alice,bob}.png）

## 根本原因

**revoke の失効境界（`min_valid_issued_at`）はメンバーノード間でベストエフォート伝播であり、かつ write の relay は認可拒否(403)を受けても次のメンバーへフェイルオーバーし続けるため、「まだ revoke を知らないメンバー」が1台でもあれば旧tokenの書き込みがそこで受理される。**

### 経路の詳細

関連コードはすべて `monas-state-node/src/`。

1. **revoke時の失効伝播に保証がない** — `application_service/state_node_service.rs` `invalidate_tokens_inner()`
   - genesis を持つノードが CRDT の access_policy に新 `min_valid_issued_at` をコミット
   - 他メンバーへは `push_operations` で送るが、失敗しても `tracing::warn!(… will rely on sync)` のみ。呼び出しは成功として返る
   - 追いつきは periodic sync（30s間隔、`application_service/node.rs`。前回runの遅延でさらに遅れうる）任せ

2. **writeのrelayは403でも止まらない** — 同ファイル `relay_with_failover()`（757行付近）
   - `auth_verdict_is_authoritative()` は **常に false**（190〜197行）
   - コメントにある設計判断: owner-signed membership (issue #63) が入るまで、メンバーであることを証明できない候補の403は「偽403で書き込みを封じる攻撃」でありうるため、拒否を受けても次の候補へ続行し、全滅した場合のみ最後に拒否を返す（availability優先）
   - 結果として、revoke済みを知っているメンバーが拒否しても、**cutoff未達のメンバーを探し当てた時点で書き込み成功**になる

3. **受理側の認可はローカルビュー依存** — `infrastructure/auth/ucan_adapter.rs` `authorize()` / `verify_auth_token()`
   - 検証は `content_repo.get_access_policy()`（= 自ノードのCRDT headのaccess_policy）の `min_valid_issued_at` に対する `iat > cutoff`（排他）チェック
   - ロジック自体は正しい。**ローカル判定は正しいがビューが古い**、分散整合性の問題

4. **受理された書き込みは正当なheadとして伝播する** — `infrastructure/crdt_repository.rs` `update_content()`
   - access_policy: None は既存policyを保存し、CRDT headが進む。以後のsyncで全ノードに伝播し、owner の verified read にも「recipient with write access が編集した新しい版」として見える

### 前提が崩れるポイント

`relay_with_failover` の「本物のメンバーなら全員同じ判定を返すはず」という前提は、revoke直後のポリシー不一致ウィンドウでは成立しない。このウィンドウ中、フェイルオーバーは「一番古いビューを持つメンバーを探し当てる」動作になる。relay固有の問題でもなく、revoked recipient が悪意クライアントとして各メンバーへ直接試行しても同じ。

### 補足: readが拒否されたのはなぜか

Phase D で Bob の read（Edit contents の読み込み）が拒否されたのは認可ではなく **CEKローテーション** のため（revokeで新CEKに再暗号化済み、旧CEKでは復号不能）。read の認可も同じ弱点を持つはずで、cutoff未達メンバーからは旧tokenで旧版ciphertextを読める可能性がある。つまり:

- 機密性（新しい版を読めない）: CEKローテーションで守られている
- 完全性（revoke後に書けない）: **破れている** ← 本バグ

UI/SDKの表示「Token cutoff advanced on the state-node first — before rotation, so the revoked recipient cannot write in between」は単一ノード内でのみ真で、クラスタ全体では成り立っていない。

## 対策案

1. **短期** — `invalidate_tokens` の完了条件強化
   - cutoff適用を全メンバー（少なくとも過半数）への同期適用成功で完了とする
   - `push_operations` 失敗を warn で飲まず、部分成功を SDK に返し、UI の「cannot write in between」の断定表示をやめる
2. **中期** — write受理時の再検証
   - メンバーがcommit前に quorum read で最新cutoffを確認する、または「revoke操作が自ノードheadに含まれているか」を検証してから受理
3. **設計** — issue #63（owner-signed membership）の実装
   - メンバーであることを owner 署名で証明できれば `auth_verdict_is_authoritative` を復活でき、attestedメンバーの403で即打ち切りできる（偽403攻撃と両立）

## 再現手順

前提: node1〜node4 が `/node/register` 済み（空なら全createが "No available member nodes found (HTTP 500)" で落ちる。登録は
`curl -X POST https://nodeN.monas-demo.net/node/register -H 'Content-Type: application/json' -d '{"total_capacity":1000000}'`）。
ローカルスタック: vite :5173/:5174、gateway :3000(node1)/:3001(node2)、account :4002/:4003。

```
cd /Users/soma/monas/monas-ui-wt/example-ui
node .demo-permissions.mjs   # Phase D で "BUG: revoked recipient's write was accepted" で停止
```

スクリプト: `example-ui/.demo-permissions.mjs`（untracked、録画付きジャーニー）。
Phase A〜C（write共有での編集、AlreadyShared確認、revoke→再shareによる権限ダウングレード/アップグレード）は通過し、Phase D の「revoke後の書き込み拒否」検証で停止する。

## 関連する既知の設計・issue

- issue #63: owner-signed membership（`auth_verdict_is_authoritative` 復活の前提）
- issue #61: request署名のリプレイ防御をtimestamp鮮度チェックに一本化（jti単回消費の廃止）
- bug #93: 非メンバーノードのrelay（1-hop制限）— 本バグのwrite relay経路そのもの
- `docs/` の該当設計メモがあれば追記のこと

## 未確定事項

- 受理したメンバーへの `push_operations` が実際に失敗していたのか、それとも periodic sync の遅延だけで説明できるのか（demoノードのログ未確認）
- read側のバイパス（cutoff未達メンバーからの旧版read）の実地再現は未実施

## 決定(2026-09-10)

検討した3案:

- A. 入場審査を quorum に — revoke は過半数メンバーへの適用成功で完了、delegated write の受理は他メンバーの最新ビューを過半数確認できたときのみ。q+q>k で「成功した revoke 後の旧トークン write は必ずどこかで 403」が成立する。LWW マージ自体は変えない(認可は commit 前の入口チェック)。代償はメンバー過半数に届かないときの delegated write / revoke の可用性。
- B. 自己証明 op + policy-aware head — update op に token(iat・capability の証明)を埋め、head 導出を「op 集合内の最大 cutoff に対して認可が成立する op だけを LWW で畳む」に変える。cutoff は単調なので収束性は保たれる。crsl-lib の head 計算・node_verification・SDK の verified read まで波及する別 PR 規模。
- C. warn のみ — 保証は与えず、状態を正直に報告する。

**C を採用**(PR #47 内で完結させるため)。B は別 issue として起票する。

### 追記: マージ規則の欠陥(C の後に判明)

C の実装後、A/B/C のどれとも別に、**CRDT のマージ規則そのものが revoke を消す**ことが分かった。access_policy は版ノードの payload に本体と同居しており、crsl-lib の Merge は payload を timestamp で丸ごと選ぶ(純 LWW)。よって revoke と並行する write が timestamp で勝つと、Merge ノードの policy は write 側の古い `min_valid_issued_at` になり、失効境界が巻き戻る — 「窓の中で1回書ける」ではなく「窓の中で1回書ければ以後も書ける」だった。逆(revoke が timestamp で勝つ)では、本体を変えていない revoke ノードが並行する正当な write を消す。

これは A/B の代替ではなく前提で、分断や sync 遅延など「並行 head が生じる状況」すべてで起きる。修正は「policy を別 DAG に出す」のではなく、同じ payload のままフィールド別に畳む(本体は本体を変えた head の中で LWW、`min_valid_issued_at` は max)。crsl-lib に利用側からマージポリシーを注入する口(`Repo::with_merge_policy`)と、head を読む前に並行 head を畳む口(`Repo::merge_heads`)を足し、state-node で `MonasMergePolicy` を注入する。詳細は design.md §11。

- crsl-lib: PR (feat/injectable-merge-policy)
- monas: PR (feat/policy-aware-merge → feat/example-ui-monas-drive)

残るのは「窓の中の write が1回本体として残る」だけで、それは B で閉じる。

### C で入れたもの

- `monas-state-node` `invalidate_tokens_inner`: 各メンバーへの `push_operations` を1回リトライし、届いた/届かなかったメンバーを `InvalidateTokensOutcome { new_min_valid_issued_at, notified_members, unreached_members, relayed }` で返す。挙動(revoke は待たない・失敗しない)は変えない。relay 経路では伝播情報は「不明」(`relayed: true`)。
- HTTP `POST /content/:id/access/invalidate` レスポンスに `notified_members` / `unreached_members` / `relayed` を**常に**含める(旧ノードとの判別のため `skip_serializing_if` を使わない)。
- `monas-sdk` `RevokeShareOutput.token_invalidation_reach`(旧ノード応答では `None` = 不明。空リストを「全員到達」と誤読しない)。
- example-ui: revoke の Protocol activity に「Cutoff propagation」ステップを追加し、全員到達 / N 台未到達(+~30 s の窓の説明) / relay で不明 / 旧ノードで不明 を出し分け。未到達・不明のときはトーストでも警告。「cannot write in between」という断定文言は削除。
- テスト: state-node 単体(未到達メンバーの報告・リトライ回数・全員到達)、SDK 単体(旧/新レスポンスの判別)。

### 残課題

- B の起票(`docs/` にこのメモをリンク)。
- demo ノード(node1〜4)は旧バイナリのため、UI 上は「reach unknown」表示になる。新バイナリのデプロイ後に `.demo-permissions.mjs` Phase D を再実行し、node3 等を落とした状態で `unreached_members` が出ることを確認する。
