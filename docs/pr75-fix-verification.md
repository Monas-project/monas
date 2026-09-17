# PR75 修正・検証記録

対象: PR75 のレビュー対応を追加する `fix/pr75-review-followup`。検証時の基点 `8c07300` と、PR75 マージ後の `5e0fb9b` のファイル内容は同一であることを確認。hosted-node deploy は未実施。

## 修正と回帰防止

- 本文: 同じ DAG payload に `body_updated_at` を保持し、本文だけを `(body_updated_at, data)` の max で選択。policy-only 更新・Merge は順序を引き継ぐ。新規 write は観測済み順序を超える。head の収束・読み取り・commit を同じ lock 内で実行し、明示 policy 指定の両更新経路でも `min_valid_issued_at` を下げない。
- 同期: operation を線形履歴の位置で対応付けず、実ノードの構造と timestamp に対応付ける。分岐後・複数回の Merge も export でき、`since_version` は兄弟枝を落とさない。曖昧な対応はエラー。
- Preview: 記録済みの最新 write ではなく、実際に表示している本文の version と head を比較。
- revoke: 旧 node の伝播報告欠落を「伝播不要」ではなく「不明」と表示。flow と toast の両経路を修正。
- identity: 旧 UI で作成順に保存された複数 signing account から、最後に作成したものだけを signing として保持。以前の秘密鍵は復号用として保持し、降格を永続化。最新 account の削除で古い signing key を復活させない。

## 実行結果

- `cargo test --workspace`: 870 passed / 0 failed / 4 ignored。
- `cargo clippy --workspace --all-targets --profile test --no-deps -- --deny warnings`: 成功。
- `cargo fmt --check`, `git diff --check`: 成功。rustfmt の既存 nightly-only 設定に関する警告は残る。
- `cd example-ui && npm run build`: 成功。
- `npm run test:regression`: 12 passed。HTTP 境界のみ fixture 化し、実際の App・store・flow・API adapter を通す。外部 origin と未知 API は拒否。担当エージェントの3回反復でも 36 passed、親エージェントが最終状態で12件を再実行。
- ローカル4-node libp2p mesh: create HTTP 201、即時取得、非 member 経由 relay read の smoke 3 passed / 0 failed。mDNS 無効。既存 :8080 を占有するサービスを触らず、CI の runner の一時コピーで HTTP :18080–18083、P2P :19091–19094、一時ストアを使用。テスト終了後に起動した node を停止。最初の一時コピーではツールの出力マスキングで Authorization の変数が置換され401となったため、元スクリプトから文字列を保持してコピーし直し、成功を確認した。本体コードの認証回避は行っていない。

## テストが旧不具合を検出することの確認

- `tests/fieldwise_convergence.rs`: 新しい本文の後の policy-only 更新、両枝 policy-only、複数回 Merge・再起動・遅着 write を実 repository の export/import で検証。旧本文選択ロジックを一時的に復元すると3件とも本文不一致で失敗。
- `tests/operation_export.rs`: 分岐の export、Merge の再同期、部分履歴、実 CID / node bytes の一致、曖昧な対応の拒否を検証。
- `tests/body_order.rs`: 未来の順序を持つ imported node → 再起動 → 新 write、古い明示 policy の両経路、初期 policy と本文の順序一致、旧 JSON / CBOR 形式の拒否。観測順序を超える処理・各 policy clamp を別々に無効化すると、それぞれ対応テストが失敗。
- Merge の単体テスト: 結合則・可換則・冪等性、timestamp 同値時の決定性。content verifier は新しい本文順序フィールドも CID に結び付いており、改ざんで検証に失敗することを確認。
- UI: preview、revoke flow、revoke toast、identity の旧挙動を個別に戻す4回の mutation run がそれぞれ期待どおり失敗。修正を戻した状態で最終 build / tests 成功。

## 制約・未実施

- `body_updated_at` は必須の保存・wire 形式変更。既存データの自動移行は未実装。顧客利用前の demo は全 state-node を同時更新し、新ストアでコンテンツを再作成する前提。既存データを保持する必要があれば、デプロイ前に移行設計が必要。データ削除は行っていない。
- 伝播が遅れた member に対する revoke 直後の write を禁止する変更ではない。既存の eventual-consistency モデルを維持し、マージで本文や失効境界を巻き戻さない修正。
- account API に現在の signing key を読み取る endpoint はない。バックエンドを UI 外でリセット・置換した場合まで自動回復できるわけではない。
- export の保持データは対象 content に絞るが、crsl-lib の `get_nodes_by_genesis` 自体は store 全体を走査する。content ごとの完全な計算量分離は未実装。
- UI 回帰 suite は実画面を通るが backend response は fixture。ブラウザから gateway・実 node を通した共有/revoke 全旅程は今回未実施。mesh smoke と repository の複数 replica 試験を区別する。

実行ログ: `/tmp/pr75-fixed-workspace.log`, `/tmp/pr75-mesh.log`, `/tmp/pr75-mutation-*.log`, `/tmp/pr75-regression-final.log`。一時ログは永続的な CI artifact ではない。
