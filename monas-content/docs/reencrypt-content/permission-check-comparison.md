# 権限チェック実装方式の比較: ShareRepository追加 vs PermissionService

## 概要

コンテンツ再暗号化機能の実装において、Owner権限チェックを実装するための2つの設計案を比較します。

- 案A: `ContentService`に`ShareRepository`を追加
- 案B: `PermissionService`を新規作成

## 比較表

| 項目 | 案A: ShareRepository追加 | 案B: PermissionService |
|------|-------------------------|----------------------|
| 設計ドキュメントとの一致 | ✅ 一致 | ❌ 不一致（PermissionServiceの記載なし） |
| 実装の複雑さ | ✅ シンプル（直接ShareRepository使用） | ⚠️ 中（新サービス＋エラー変換） |
| 既存コードへの影響 | ⚠️ 中（型パラメータ追加、インスタンス化修正） | ⚠️ 大（新サービス作成＋型パラメータ追加） |
| 責務の分離 | ⚠️ ContentServiceの責務拡大 | ✅ 良い（権限チェック専用サービス） |
| 再利用性 | ❌ ContentService内のみ | ✅ 高い（他の操作でも使用可能） |
| テスト容易性 | ✅ 良い（ContentServiceのテスト内で権限チェックもテスト） | ✅ 良い（PermissionServiceを独立してテスト可能） |
| 型パラメータの増加 | ⚠️ 6→7（1つ増加） | ⚠️ 6→7（1つ増加、PermissionServiceの型パラメータも考慮） |
| 将来の拡張性 | ⚠️ 中（権限チェックロジックの変更がContentServiceに影響） | ✅ 高い（PermissionServiceのみ修正） |
| DDD原則への適合 | ✅ 良い（アプリケーションサービス層内の依存） | ✅ 良い（責務の分離） |
| コードの重複 | ⚠️ 権限チェックロジックがContentService内に閉じる | ✅ 権限チェックロジックを共有可能 |

---

## 案A: ContentServiceにShareRepositoryを追加

### 概要

`ContentService`の構造体に`ShareRepository`を追加し、権限チェックを`ContentService`内で直接実装する方式。

### メリット

1. 設計ドキュメントと一致: 設計ドキュメントで`ShareRepository`を使用することが明記されている
2. 実装がシンプル: `ShareRepository`を直接使用するため、追加の抽象化層が不要
3. 権限チェックロジックが集約: 権限チェックロジックが`ContentService`内に集約される
4. 既存パターンとの対称性: `ShareService`が`ContentRepository`を使用しているパターンと対称
5. 追加のサービス層が不要: 新しいサービス層を作成する必要がない

### デメリット

1. 型パラメータの増加: `ContentService`の型パラメータが6つから7つに増える
2. 責務の拡大: `ContentService`の責務が拡大（コンテンツ管理＋権限チェック）
3. 既存コードへの影響: `ContentService`のインスタンス化箇所の修正が必要
4. 権限チェックロジックの再利用が難しい: 権限チェックロジックが`ContentService`内に閉じるため、他の操作で再利用する際に重複実装が必要になる可能性がある

---

## 案B: PermissionServiceを作成

### 概要

権限チェック専用の`PermissionService`を新規作成し、`ContentService`から`PermissionService`を使用する方式。

### メリット

1. 責務の分離: 権限チェック専用のサービスとして分離される
2. 再利用性: 他の操作（`update`, `delete`など）でも使用可能
3. テスト容易性: 権限チェックロジックを独立してテスト可能
4. 将来の拡張性: 権限チェックロジックの変更が容易（`PermissionService`のみ修正）
5. 単一責任の原則に適合: 各サービスが明確な責務を持つ

### デメリット

1. 新しいサービス層の追加: 設計の複雑化（新しいモジュールとファイルが必要）
2. 型パラメータの増加: `ContentService`の型パラメータが6つから7つに増える（`PermissionService`の型パラメータも考慮）
3. 既存コードへの影響: 新サービス作成＋`ContentService`修正が必要
4. エラーの変換が必要: `PermissionError`を`ReencryptError`に変換する必要がある
5. 設計ドキュメントとの不一致: 設計ドキュメントに`PermissionService`の記載がない

---

## 追加の考慮事項

### 権限チェックの再利用性

案Aの場合:
- 他の操作（例：`update`, `delete`）でもOwner権限チェックが必要な場合、`ContentService`内に重複実装が必要
- 権限チェックロジックの変更時に複数箇所を修正する必要がある

案Bの場合:
- `PermissionService::check_owner_permission()`を他の操作でも再利用可能
- 権限チェックロジックの変更は`PermissionService`のみで対応可能

### エラーハンドリング

案Aの場合:
- `ShareRepository`のエラーを直接`ReencryptError`に変換できるため、エラー変換がシンプル

案Bの場合:
- `PermissionError`を`ReencryptError`に変換する必要があるため、エラー変換のロジックが複雑になる可能性がある

---

## 推奨

### 短期的には案Aを推奨

理由:

1. 設計ドキュメントと一致: 設計ドキュメントで`ShareRepository`を使用することが明記されている
2. 実装がシンプル: `ShareRepository`を直接使用するため、追加の抽象化層が不要
3. 既存コードへの影響が小さい: 型パラメータの追加とインスタンス化の修正のみ
4. 既存パターンとの対称性: `ShareService`が`ContentRepository`を使用しているパターンと対称

### 長期的には案Bを検討

理由:

1. 責務の分離が明確: 権限チェック専用のサービスとして分離される
2. 再利用性が高い: 他の操作でも使用可能
3. 将来の拡張性が高い: 権限チェックロジックの変更が容易
4. テストが容易: 権限チェックロジックを独立してテスト可能

### 推奨される実装戦略

1. まず案Aで実装: 設計ドキュメントに合わせて案Aで実装する
2. リファクタリングのタイミング: 他の操作（`update`, `delete`など）でもOwner権限チェックが必要になったら案Bにリファクタリングする

---

## 結論

- 現時点での推奨: 案A（ShareRepository追加）
- 将来の検討事項: 権限チェックの再利用が必要になったら案B（PermissionService）にリファクタリング
