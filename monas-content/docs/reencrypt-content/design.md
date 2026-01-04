# コンテンツ再暗号化機能の設計書

## 概要

Write権限を持つユーザが、特定のkey idを持つRead権限ユーザのアクセスを拒否するために、コンテンツを再暗号化する機能を実装します。

#### **権限設計の方針**:
- **Owner権限のモック実装を追加**: Owner権限を持つユーザのみが再暗号化を実行できる
- **Owner権限を前提とする**: Owner権限が設定されていない場合、エラーを返す（Write権限での代替は行わない）
- **将来の削除を考慮**: Owner権限は将来的にmonas-state-nodeが権限管理するため、モック実装として追加し、削除可能な設計とする

**重要な要件**: 再暗号化処理完了後、`ShareService::grant_share()`を実行することで、再暗号化されたコンテンツに対する新しい`KeyEnvelope`を生成できる必要があります。

## Owner権限のモック実装について

### 設計方針

1. **モック実装**: Owner権限は将来的にmonas-state-nodeが管理するため、一時的なモック実装として追加
2. **削除可能な設計**: モック実装は将来的に削除することを前提とし、明確に分離された実装とする
3. **権限の階層**: Owner > Write > Read の階層を定義
4. **権限管理**: Owner権限を持つユーザのみが権限の付与・削除を行える

### 実装範囲

- **ドメイン層**: `Permission::Owner`を追加、`Share`に`owner_key_id`フィールドを追加
- **アプリケーション層**: Owner権限チェックを追加（モック実装）
- **再暗号化機能**: Owner権限チェックを優先的に使用

## 処理フロー

### 概要

再暗号化処理は以下の8つのステップで構成されます：

1. **APIリクエスト受信**: Owner権限保持者が`requester_key_id`と`revoked_key_id`を指定して再暗号化APIを呼び出す
2. **事前確認**: コンテンツの存在確認、削除状態確認、Share取得、Owner権限確認、削除確認、更新確認を実行
3. **復号**: 既存のCEKを使用してコンテンツを復号し、プレーンテキストを取得
4. **CEK生成**: 新しいCEKを生成
5. **再暗号化**: プレーンテキストを新しいCEKで再暗号化し、新しいContentオブジェクトを作成
6. **CEK保存**: 新しいCEKを`ContentEncryptionKeyStore`に保存
7. **Content保存**: 再暗号化されたContentを`ContentRepository`に保存（失敗時はCEKを削除してロールバック）
8. **結果返却**: 新しいCEKを含む`ReencryptContentResult`を返す

### 詳細実装

#### 1. APIリクエスト受信（プレゼンテーション層）

**入力**:

- `ReencryptContentRequest`構造体:
  ```rust
      pub struct ReencryptContentRequest {
          pub requester_key_id_base64: String,  // Owner権限を持つユーザのKeyId（base64エンコード）
          pub revoked_key_id_base64: String,    // 削除されたKeyId（base64エンコード）
      }
  ```




- `content_id`: URLパスから取得（`ContentId`型）

**処理**:

- `requester_key_id_base64`と`revoked_key_id_base64`をbase64デコードして`KeyId`に変換
- `ReencryptContentCommand`を構築:
  ```rust
      pub struct ReencryptContentCommand {
          pub content_id: ContentId,
          pub requester_key_id: KeyId,
          pub revoked_key_id: KeyId,
      }
  ```




#### 2. 事前確認（アプリケーションサービス層・ドメイン層）

##### 2.1 コンテンツの取得（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::find_by_id(&content_id)` を呼び出し
- **戻り値**: `Result<Option<Content>, ContentRepositoryError>`
- **期待される値**:
- 成功時: `Ok(Some(Content))`
    - `Content`構造体:
      ```rust
                  pub struct Content {
                      id: ContentId,                    // コンテンツID（再暗号化後は変更される可能性）
                      series_id: ContentId,            // 論理的な系列ID（維持される）
                      metadata: Metadata,              // メタデータ（名前、パス、作成日時、更新日時）
                      raw_content: Option<Vec<u8>>,    // プレーンテキスト（通常はNone）
                      encrypted_content: Option<Vec<u8>>, // 暗号化されたコンテンツ
                      is_deleted: bool,                // 削除フラグ
                      content_status: ContentStatus,   // Active/Deleting/Deleted
                  }
      ```




- コンテンツが存在しない場合: `Ok(None)`
- **エラー処理**: `Ok(None)`の場合、`ReencryptError::ContentNotFound`エラーを返す

### 2.2 削除状態の確認（ドメイン層）

- **ドメイン層**: `Content::is_deleted()` を呼び出し
- 戻り値: `bool`
- エラー処理: `ContentDeleted` エラーを返す（`true`の場合）

##### 2.3 Shareの取得（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ShareRepository::load(&content_id)` を呼び出し
- **戻り値**: `Result<Option<Share>, ShareRepositoryError>`
- **期待される値**:
- 成功時: `Ok(Some(Share))`
    - `Share`構造体:
      ```rust
                  pub struct Share {
                      content_id: ContentId,                              // コンテンツID
                      recipients: HashMap<KeyId, ShareRecipient>,         // 受信者一覧
                      owner_key_id: Option<KeyId>,                       // Owner権限を持つKeyId（モック実装）
                  }
      ```




    - `ShareRecipient`構造体:
      ```rust
                  pub struct ShareRecipient {
                      key_id: KeyId,                    // 受信者のKeyId
                      permissions: Vec<Permission>,     // Read/Write/Owner権限のリスト
                  }
      ```




- Shareが存在しない場合: `Ok(None)`
- **エラー処理**: `Ok(None)`の場合、`ReencryptError::ShareNotFound`エラーを返す

### 2.4 権限の確認（ドメイン層）

- **ドメイン層**: `Share::owner_key_id()` を呼び出し（Owner権限の確認）
- 戻り値: `Option<&KeyId>`
- Owner権限が設定されている場合（`Option::Some(owner_key_id)`）:
    - `owner_key_id == requester_key_id` を確認
    - 不一致の場合: `OwnerPermissionDenied` エラーを返す
- Owner権限が未設定の場合（`Option::None`）:
    - `OwnerPermissionDenied` エラーを返す（Owner権限を前提とするため、Write権限での代替は行わない）

##### 2.5 削除確認（ドメイン層）

- **ドメイン層**: `Share::recipients()` を呼び出し
- **戻り値**: `&HashMap<KeyId, ShareRecipient>`
- **期待される値**:
- `recipients`は`HashMap<KeyId, ShareRecipient>`型
- `revoked_key_id`が`recipients`に含まれていないこと（`contains_key(&revoked_key_id) == false`）
- **エラー処理**: `recipients.contains_key(&revoked_key_id) == true`の場合、`ReencryptError::RevokedKeyIdStillExists`エラーを返す

##### 2.6 更新確認（ドメイン層）

- **ドメイン層**: `Content::metadata()` を呼び出し
- **戻り値**: `&Metadata`
- **期待される値**:
- `Metadata`構造体:
    ```rust
            pub struct Metadata {
                name: String,                      // コンテンツ名
                path: String,                      // パス
                created_at: DateTime<Utc>,         // 作成日時
                updated_at: DateTime<Utc>,         // 更新日時
                id: ContentId,                     // ContentId
            }
    ```




- **ドメイン層**: `Metadata::updated_at()` を呼び出し
- **戻り値**: `DateTime<Utc>`
- **更新確認のロジック**: 暫定的な実装方針に従う（現時点では詳細未定）

#### 3. 既存のCEKでコンテンツを復号（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::load(&content_id)` を呼び出し
- **戻り値**: `Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError>`
- **期待される値**:
- 成功時: `Ok(Some(ContentEncryptionKey))`
    - `ContentEncryptionKey`構造体: `ContentEncryptionKey(Vec<u8>)` - 32バイトのCEK
- CEKが存在しない場合: `Ok(None)`
- **エラー処理**: `Ok(None)`の場合、`ReencryptError::MissingContentEncryptionKey`エラーを返す
- **ドメイン層**: `Content::decrypt(&old_cek, &encryptor)` を呼び出し
- **戻り値**: `Result<Vec<u8>, ContentError>`
- **期待される値**:
- 成功時: `Ok(Vec<u8>)` - プレーンテキスト（復号されたコンテンツ）
- 失敗時: `Err(ContentError::DecryptionError(String))`
- **エラー処理**: `Err`の場合、`ReencryptError::Domain(ContentError)`エラーを返す

### 4. 新しいCEKを生成（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyGenerator::generate()` を呼び出し
- 戻り値: `ContentEncryptionKey`

#### 5. 再暗号化されたContentを作成（ドメイン層）

- **ドメイン層**: `Content::update_content(raw_content, &id_generator, &new_cek, &encryptor)` を呼び出し
- **引数**:
- `raw_content`: `Vec<u8>` - 復号したプレーンテキスト（**重要**: プレーンテキストを渡す（事前に暗号化しない））
- `id_generator`: `ContentIdGenerator`トレイト実装
- `new_cek`: `ContentEncryptionKey` - 新しいCEK
- `encryptor`: `ContentEncryption`トレイト実装
- **戻り値**: `Result<(Content, ContentEvent), ContentError>`
- **期待される値**:
- 成功時: `Ok((Content, ContentEvent::Updated))`
    - `Content`構造体:
    - `id`: 新しい`ContentId`（`ContentIdGenerator::generate(&raw_content)`で生成）
    - `series_id`: 元の`series_id`を維持
    - `metadata`: `Metadata::with_new_id(new_id)`で新しいIDに更新し、`updated_at`も更新
    - `encrypted_content`: `Some(Vec<u8>)` - 新しいCEKで暗号化されたコンテンツ（IV + 暗号文）
    - `raw_content`: `None`
    - `is_deleted`: `false`
    - `content_status`: `ContentStatus::Active`
    - `ContentEvent`: `ContentEvent::Updated`
- 失敗時: `Err(ContentError::EncryptionError(String))`
- **重要**: `Content::update_content()`は内部で`encryption.encrypt(&new_cek, &raw_content)`を呼び出して暗号化するため、事前に`ContentEncryption::encrypt()`を呼び出す必要はない（二重暗号化を避けるため）
- **エラー処理**: `Err`の場合、`ReencryptError::Domain(ContentError)`エラーを返す

#### 6-9. コミットフェーズ（永続化・アトミック性保証）

**重要**: メモリ上での準備（Step 3-5）が完了してから、以下の永続化操作を実行します。

##### 6. 新しいContentIdでCEKを保存（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::save(new_content_id, &new_cek)` を呼び出し
- **引数**:
- `new_content_id`: `&ContentId` - 再暗号化後の新しいContentId
- `&new_cek`: `&ContentEncryptionKey` - 新しいCEK
- **戻り値**: `Result<(), ContentEncryptionKeyStoreError>`
- **期待される値**:
- 成功時: `Ok(())`
- 失敗時: `Err(ContentEncryptionKeyStoreError::Storage(String))`
- **エラー処理**: `Err`の場合、エラーを返す（まだ何も保存されていないため、ロールバック不要）

##### 7. 新しいContentIdでContentを保存（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::save(new_content_id, &reencrypted_content)` を呼び出し
- **引数**:
- `new_content_id`: `&ContentId` - 再暗号化後の新しいContentId
- `&reencrypted_content`: `&Content` - 再暗号化されたContentオブジェクト
- **戻り値**: `Result<(), ContentRepositoryError>`
- **期待される値**:
- 成功時: `Ok(())`
- 失敗時: `Err(ContentRepositoryError)` - ストレージエラーなど
- **エラー処理とロールバック**: Content保存が失敗した場合、新しいContentIdのCEKを削除してロールバック
  ```rust
    if let Err(e) = self.content_repository.save(&new_content_id, &reencrypted_content) {
        // ロールバック: 新しいContentIdのCEKを削除
        let _ = self.cek_store.delete(&new_content_id);
        return Err(ReencryptError::ContentRepository(e));
    }
  ```




##### 8. 古いContentIdのCEKを削除（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::delete(old_content_id)` を呼び出し
- **引数**:
- `old_content_id`: `&ContentId` - 元のContentId
- **戻り値**: `Result<(), ContentEncryptionKeyStoreError>`
- **期待される値**:
- 成功時: `Ok(())`
- 失敗時: `Err(ContentEncryptionKeyStoreError::Storage(String))`
- **エラー処理とロールバック**: CEK削除が失敗した場合、新しいContentIdのCEKとContentを削除してロールバック
  ```rust
    if let Err(e) = self.cek_store.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        return Err(ReencryptError::KeyStore(e));
    }
  ```




##### 9. 古いContentIdのContentを削除（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::delete(old_content_id)` を呼び出し
- **引数**:
- `old_content_id`: `&ContentId` - 元のContentId
- **戻り値**: `Result<(), ContentRepositoryError>`
- **期待される値**:
- 成功時: `Ok(())`
- 失敗時: `Err(ContentRepositoryError)` - ストレージエラーなど
- **エラー処理とロールバック**: Content削除が失敗した場合、新しいContentIdのCEKとContentを削除してロールバック
  ```rust
    if let Err(e) = self.content_repository.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        // 古いContentIdのCEKは既に削除済みなので、復元はしない
        return Err(ReencryptError::ContentRepository(e));
    }
  ```




- **アトミック性保証**: この実装により、すべての操作が成功した場合のみ、新しいContentIdのデータが残り、古いContentIdのデータが削除される。いずれかの操作が失敗した場合、新しいContentIdのデータが削除され、古いデータがそのまま残る。これにより、「途中まで実行している」状態や「CEKの生成はできたけど暗号化はうまくできなかった」などの整合性を満たせない状態が発生しない

#### 8. 新しいCEKを返す（アプリケーションサービス層）

- **アプリケーションサービス層**: `ReencryptContentResult` を構築して返す
- **戻り値**: `Result<ReencryptContentResult, ReencryptError>`
- **期待される値**:
- 成功時: `Ok(ReencryptContentResult)`
    - `ReencryptContentResult`構造体:
      ```rust
                  pub struct ReencryptContentResult {
                      pub content_id: ContentId,         // 再暗号化後の新しいContentId
                      pub series_id: ContentId,        // 論理的な系列ID（維持される）
                      pub metadata: Metadata,          // 更新されたメタデータ
                      pub new_cek: ContentEncryptionKey, // 新しいCEK
                  }
      ```




## 実装内容

### 1. ドメイン層（Owner権限のモック実装）

#### 1.1 Permission enumの拡張

`monas-content/src/domain/share/share.rs`に以下を追加：

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Read,
    Write,
    Owner,  // モック実装: 将来的にmonas-state-nodeが管理するため削除予定
}

impl Permission {
    pub fn can_read(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(
            p, 
            Permission::Read | Permission::Write | Permission::Owner
        ))
    }

    pub fn can_write(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(
            p, 
            Permission::Write | Permission::Owner
        ))
    }

    // モック実装: 将来的に削除予定
    pub fn can_manage_permissions(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(p, Permission::Owner))
    }
}
```



#### 1.2 Share構造体の拡張

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Share {
    content_id: ContentId,
    recipients: HashMap<KeyId, ShareRecipient>,
    // モック実装: 将来的にmonas-state-nodeが管理するため削除予定
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_key_id: Option<KeyId>,
}

impl Share {
    // モック実装: 将来的に削除予定
    pub fn grant_owner(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        if self.owner_key_id.is_some() {
            return Err(ShareError::InvalidOperation(
                "Owner already exists".to_string()
            ));
        }
        
        if let Some(recipient) = self.recipients.get_mut(&key_id) {
            recipient.permissions.push(Permission::Owner);
        } else {
            let recipient = ShareRecipient::new(
                key_id.clone(),
                vec![Permission::Owner],
            );
            self.recipients.insert(key_id.clone(), recipient);
        }
        
        self.owner_key_id = Some(key_id.clone());
        
        Ok(ShareEvent::RecipientGranted {
            content_id: self.content_id.clone(),
            key_id,
            permissions: vec![Permission::Owner],
        })
    }

    // モック実装: 将来的に削除予定
    pub fn owner_key_id(&self) -> Option<&KeyId> {
        self.owner_key_id.as_ref()
    }

    // モック実装: 将来的に削除予定
    fn can_manage_permissions(&self, key_id: &KeyId) -> bool {
        self.owner_key_id.as_ref() == Some(key_id)
            || self.recipients
                .get(key_id)
                .map(|r| Permission::can_manage_permissions(r.permissions()))
                .unwrap_or(false)
    }
}
```

**注意**: モック実装のため、`grant_read()`、`grant_write()`、`revoke()`メソッドへの権限チェック追加は**行わない**。将来的にmonas-state-nodeが権限管理するため。

### 2. アプリケーションサービス層

#### 2.1 再暗号化機能の権限チェック

`monas-content/src/application_service/content_service/service.rs`に`reencrypt`メソッドを追加：

```rust
// モック実装: Owner権限チェック（将来的にmonas-state-nodeが管理するため削除予定）
fn check_reencrypt_permission(share: &Share, requester_key_id: &KeyId) -> bool {
    // Owner権限の確認（Owner権限を前提とする）
    if let Some(owner_key_id) = share.owner_key_id() {
        return owner_key_id == requester_key_id;
    }
    // Owner権限が未設定の場合はエラー（Write権限での代替は行わない）
    false
}
```



#### 2.2 再暗号化処理の実装（整合性保証含む）

`monas-content/src/application_service/content_service/service.rs`に`reencrypt`メソッドを実装：

```rust
pub fn reencrypt(&self, cmd: ReencryptContentCommand) -> Result<ReencryptContentResult, ReencryptError> {
    // ... 権限チェック、削除確認、更新確認などの処理 ...
    
    // === 準備フェーズ（メモリ上で実行） ===
    
    // 既存のContentIdを保存
    let old_content_id = content.id().clone();
    
    // 既存のCEKで復号
    let plaintext = content.decrypt(&old_cek, &self.encryptor)
        .map_err(ReencryptError::Domain)?;
    
    // 新しいCEKを生成
    let new_cek = self.key_generator.generate();
    
    // 再暗号化されたContentを作成（新しいContentIdが生成される）
    let (reencrypted_content, _event) = content.update_content(
        plaintext,
        &self.content_id_generator,
        &new_cek,
        &self.encryptor,
    )
    .map_err(ReencryptError::Domain)?;
    
    let new_content_id = reencrypted_content.id().clone();
    
    // === コミットフェーズ（永続化） ===
    
    // Step 4: 新しいContentIdでCEKを保存
    self.cek_store
        .save(&new_content_id, &new_cek)
        .map_err(ReencryptError::KeyStore)?;
    
    // Step 5: 新しいContentIdでContentを保存
    if let Err(e) = self.content_repository.save(&new_content_id, &reencrypted_content) {
        // ロールバック: 新しいContentIdのCEKを削除
        let _ = self.cek_store.delete(&new_content_id);
        return Err(ReencryptError::ContentRepository(e));
    }
    
    // Step 6: 古いContentIdのCEKを削除
    if let Err(e) = self.cek_store.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        return Err(ReencryptError::KeyStore(e));
    }
    
    // Step 7: 古いContentIdのContentを削除
    if let Err(e) = self.content_repository.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        // 古いContentIdのCEKは既に削除済みなので、復元はしない
        return Err(ReencryptError::ContentRepository(e));
    }
    
    // すべて成功: 新しいContentIdのデータのみが残る
    Ok(ReencryptContentResult {
        content_id: new_content_id,
        series_id: reencrypted_content.series_id().clone(),
        metadata: reencrypted_content.metadata().clone(),
        new_cek,
    })
}
```

**注意**: `ContentRepository`トレイトに`delete`メソッドを追加する必要があります。既存の実装を確認し、必要に応じて追加します。**アトミック性保証の実装**:

- メモリ上で全ての準備（復号、CEK生成、再暗号化）を完了してから永続化を開始
- 新しいContentIdでCEKとContentを保存し、すべて成功したら古いContentIdのデータを削除
- いずれかの操作が失敗した場合、新しいContentIdのデータを削除してロールバック
- これにより、「途中まで実行している」状態や「CEKの生成はできたけど暗号化はうまくできなかった」などの整合性を満たせない状態が発生しない

#### 2.3 ShareServiceの変更（オプション）

**注意**: `ShareService::grant_share()`と`revoke_share()`へのOwner権限チェック追加は**行わない**。将来的にmonas-state-nodeが権限管理するため、モック実装は最小限とする。

### 3. エラーハンドリング

`ReencryptError`に以下を追加：

```rust
#[error("owner permission denied: requester_key_id={requester_key_id}, content_id={content_id}")]
OwnerPermissionDenied { 
    requester_key_id: KeyId, 
    content_id: ContentId 
},
```



### 4. アトミック性を保証する設計

#### 4.1 設計方針

**設計方針**: **2フェーズコミットパターン**を採用し、すべての操作をアトミックに完了させる**採用理由**:

1. **要件の明確性**

- 「途中まで実行している」状態を許容しない要件に合う
- 整合性を満たさない状態を排除できる

2. **データ整合性の重要性**

- 暗号化システムでは整合性が重要
- CEKとContentの不整合は致命的

3. **実装コストは許容範囲**

- `delete`メソッドの追加は既存パターンに沿う
- `ContentEncryptionKeyStore`には既に`delete`がある

4. **ContentId変更への対応**

- `Content::update_content()`が既に新しいContentIdを生成
- 設計上、ContentId変更は想定内

#### 4.2 詳細設計

**基本原則**:

- メモリ上で全ての準備を完了してから、最後に一括で保存する
- 新しいContentIdでCEKとContentを保存し、すべて成功したら古いContentIdのデータを削除
- いずれかの操作が失敗した場合、新しいContentIdのデータを削除してロールバック
- 常に整合性が保たれた状態のみが永続化される

**実装フロー**:**準備フェーズ（メモリ上で実行）**:

1. 既存のCEKでコンテンツを復号（Step 3）
2. 新しいCEKを生成（Step 4）
3. 再暗号化されたContentを作成（Step 5）

- 新しいContentIdが生成される（`ContentIdGenerator::generate(&raw_content)`）
- メモリ上で新しいContentオブジェクトを構築

**コミットフェーズ（永続化）**:

4. **新しいContentIdでCEKを保存** (`ContentEncryptionKeyStore::save(new_content_id, &new_cek)`)
5. **新しいContentIdでContentを保存** (`ContentRepository::save(new_content_id, &reencrypted_content)`)
6. **古いContentIdのCEKを削除** (`ContentEncryptionKeyStore::delete(old_content_id)`)
7. **古いContentIdのContentを削除** (`ContentRepository::delete(old_content_id)`)

**エラーハンドリング**:

- Step 4が失敗: エラーを返す（まだ何も保存されていない）
- Step 5が失敗: 新しいContentIdのCEKを削除してロールバック、エラーを返す
- Step 6が失敗: 新しいContentIdのCEKとContentを削除してロールバック、エラーを返す
- Step 7が失敗: 新しいContentIdのCEKとContentを削除してロールバック、エラーを返す

**重要なポイント**:

- 新しいContentIdを使用することで、古いデータと新しいデータが一時的に同時に存在することを許容
- すべての操作が成功した場合のみ、古いデータを削除
- いずれかの操作が失敗した場合、新しいデータを削除することで、常に整合性が保たれた状態を維持
- メモリ上での準備が完了してから永続化を開始するため、「途中まで実行している」状態が発生しない
- 「CEKの生成はできたけど暗号化はうまくできなかった」などの整合性を満たせない状態は発生しない

#### 4.3 アトミック性検証のテスト

以下のテストケースを追加して、アトミック性が保証されていることを確認：

1. **正常系**: すべての操作が成功する場合

- 前提条件: すべての操作が成功
- 期待結果: 
    - 新しいContentIdでCEKとContentが保存される
    - 古いContentIdのCEKとContentが削除される
    - 新しいContentIdのデータのみが存在する
    - 整合性が保たれる

2. **異常系**: 新しいContentIdでCEK保存が失敗した場合

- 前提条件: `ContentEncryptionKeyStore::save()`がエラーを返す
- 期待結果: 
    - 何も保存されない（古いデータはそのまま）
    - エラーが返される

3. **異常系**: 新しいContentIdでContent保存が失敗した場合

- 前提条件: `ContentRepository::save()`がエラーを返す
- 期待結果: 
    - 新しいContentIdのCEKが削除される
    - 古いデータはそのまま
    - エラーが返される

4. **異常系**: 古いContentIdのCEK削除が失敗した場合

- 前提条件: `ContentEncryptionKeyStore::delete()`がエラーを返す
- 期待結果: 
    - 新しいContentIdのCEKとContentが削除される（ロールバック）
    - 古いデータはそのまま
    - エラーが返される

5. **異常系**: 古いContentIdのContent削除が失敗した場合

- 前提条件: `ContentRepository::delete()`がエラーを返す
- 期待結果: 
    - 新しいContentIdのCEKとContentが削除される（ロールバック）
    - 古いデータはそのまま
    - エラーが返される

6. **整合性チェック**: 再暗号化後、ContentとCEKの整合性を確認

- 前提条件: 再暗号化が成功
- 期待結果: 
    - 新しいContentIdで`ContentRepository::find_by_id()`でContentが取得できる
    - 新しいContentIdで`ContentEncryptionKeyStore::load()`でCEKが取得できる
    - `Content::decrypt()`でCEKを使ってContentを復号できる
    - 古いContentIdのデータは存在しない

### 5. テスト戦略

Owner権限のモック実装に関するテスト：

1. **正常系**: Owner権限を持つユーザが再暗号化を実行
2. **異常系**: Owner権限が設定されていない場合、再暗号化不可（`OwnerPermissionDenied`エラー）
3. **異常系**: Owner権限が設定されている場合、Owner権限を持たないユーザは再暗号化不可（`OwnerPermissionDenied`エラー）

#### 5.1 アトミック性保証のテスト

4. **正常系**: すべての操作が成功する場合

- 前提条件: すべての操作が成功
- 期待結果: 
    - 新しいContentIdでCEKとContentが保存される
    - 古いContentIdのCEKとContentが削除される
    - 新しいContentIdのデータのみが存在する
    - 整合性が保たれる

5. **異常系**: 新しいContentIdでCEK保存が失敗した場合

- 前提条件: `ContentEncryptionKeyStore::save()`がエラーを返す
- 期待結果: 何も保存されない（古いデータはそのまま）、エラーが返される

6. **異常系**: 新しいContentIdでContent保存が失敗した場合

- 前提条件: `ContentRepository::save()`がエラーを返す
- 期待結果: 新しいContentIdのCEKが削除される（ロールバック）、古いデータはそのまま、エラーが返される

7. **異常系**: 古いContentIdのCEK削除が失敗した場合

- 前提条件: `ContentEncryptionKeyStore::delete()`がエラーを返す
- 期待結果: 新しいContentIdのCEKとContentが削除される（ロールバック）、古いデータはそのまま、エラーが返される

8. **異常系**: 古いContentIdのContent削除が失敗した場合

- 前提条件: `ContentRepository::delete()`がエラーを返す
- 期待結果: 新しいContentIdのCEKとContentが削除される（ロールバック）、古いデータはそのまま、エラーが返される

9. **整合性チェック**: 再暗号化後、ContentとCEKの整合性を確認

- 前提条件: 再暗号化が成功
- 期待結果: 
    - 新しいContentIdで`ContentRepository::find_by_id()`でContentが取得できる
    - 新しいContentIdで`ContentEncryptionKeyStore::load()`でCEKが取得できる
    - `Content::decrypt()`でCEKを使ってContentを復号できる
    - 古いContentIdのデータは存在しない

## 将来の削除計画

### 削除対象

1. `Permission::Owner` enum variant
2. `Share::owner_key_id` フィールド
3. `Share::grant_owner()` メソッド
4. `Share::owner_key_id()` メソッド
5. `Share::can_manage_permissions()` メソッド（プライベート）
6. `Permission::can_manage_permissions()` メソッド
7. `check_reencrypt_permission()` のOwner権限チェック部分

### 削除後の動作

- 権限管理はmonas-state-nodeが担当
- Owner権限チェックはmonas-state-node側で行われる

## ファイル構成

```bash
monas-content/src/
├── domain/share/
│   └── share.rs (Permission::Owner追加、Share::owner_key_id追加 - モック実装)
├── application_service/content_service/
│   ├── command.rs (ReencryptContentCommand, ReencryptContentResult追加)
│   ├── service.rs (reencryptメソッド追加 - Owner権限チェック含む)
│   └── mod.rs (ReencryptError追加)
└── presentation/
    └── content.rs (再暗号化APIエンドポイント追加)
```
