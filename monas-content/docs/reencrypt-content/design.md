# コンテンツ再暗号化機能の設計書

## 概要

Owner権限を持つユーザが、特定のkey idを持つRead権限ユーザのアクセスを拒否するために、コンテンツを再暗号化する機能を実装します。

**要件**: 
- 再暗号化処理完了後、ciphertext（暗号化されたコンテンツ）が返される
- 新しいCEKはローカルに保存される（既存の`create()`と同様）
- monas-sdk側で、残っている正当なユーザに対して`ShareService::grant_share()`を呼び出すことで、再暗号化されたコンテンツに対する新しい`KeyEnvelope`を生成できる必要があります（Pull型、既存の`share_content` APIと同様）

**想定使用箇所**: この再暗号化操作は、`monas-sdk/src/controller/share.rs`の`revoke_share`メソッド（264行目付近）で使用されます。共有を取り消した後、取り消されたユーザがコンテンツにアクセスできないようにするため、コンテンツを再暗号化する必要があります。

## Owner権限の実装について

### 設計方針

1. **Owner権限の実装**: Owner権限を持つユーザのみが再暗号化を実行できる
2. **権限の階層**: Owner > Write > Read の階層を定義
3. **権限管理**: Owner権限を持つユーザのみが権限の付与・削除を行える
4. **将来の移行可能性**: 将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮

### 実装範囲

- **ドメイン層**: `Permission::Owner`を追加、`ShareRecipient::permissions`に`Permission::Owner`を含める方式を採用
- **アプリケーション層**: Owner権限チェックを追加
- **再暗号化機能**: Owner権限チェックを優先的に使用

### 実装の位置づけ

- Owner権限の実装は本実装として扱う
- `Share`は`monas-content`で管理されているため、Owner権限も`monas-content`で管理する
- クライアント側でOwner権限を確認できる必要がある
- 将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画は残しておく

### Owner権限の設計

Owner権限は`ShareRecipient::permissions()`に`Permission::Owner`を含める方式で実装する。`ShareRecipient::permissions()`は既に以下の用途で使用されている：

- **APIレスポンス**: `get_share` APIで権限情報を返す（`presentation/share.rs`）
- **権限チェック**: `ShareRecipient::can_read()` と `can_write()` の内部実装で使用
- **権限の取得**: `Share::permissions_of()` の内部実装で使用

この既存パターンに従い、Owner権限も`ShareRecipient::permissions()`に含めることで、クライアント側での権限確認が容易になり、既存の権限確認パターンと一貫性を保つ。

## 処理フロー

### 概要

再暗号化処理は以下の10つのステップで構成されます：

1. **APIリクエスト受信**: Owner権限保持者が`requester_key_id`と`revoked_key_id`を指定して再暗号化APIを呼び出す
2. **事前確認**: コンテンツの取得と検証（存在確認、削除状態確認、Share取得、Owner権限確認、削除確認、更新確認）を実行
3. **復号**: 取得したコンテンツを既存のCEKで復号し、プレーンテキストを取得
4. **CEK生成**: 新しいCEKを生成
5. **再暗号化**: プレーンテキストを新しいCEKで再暗号化し、新しいContentオブジェクトを作成
6. **CEK保存**: 新しいCEKを`ContentEncryptionKeyStore`に保存
7. **Content保存**: 再暗号化されたContentを`ContentRepository`に保存（失敗時はCEKを削除してロールバック）
8. **古いContent削除**: 古いContentIdのContentを削除（失敗時は新しいデータを削除してロールバック）
9. **古いCEK削除**: 古いContentIdのCEKを削除（失敗時は新しいデータを削除してロールバック）
10. **結果返却**: 暗号化されたコンテンツ（ciphertext）を含む`ReencryptContentResult`を返す

### 詳細実装

#### 1. APIリクエスト受信（プレゼンテーション層）

**ファイル**: `monas-content/src/presentation/content.rs`

**実装**:
```rust
#[derive(Deserialize)]
pub struct ReencryptContentRequest {
    pub requester_key_id_base64: String,  // Owner権限を持つユーザのKeyId（base64エンコード）
    pub revoked_key_id_base64: String,    // 削除されたKeyId（base64エンコード）
}
```

**処理**:
- `content_id`: URLパスから取得（`ContentId`型）
- `requester_key_id_base64`と`revoked_key_id_base64`をbase64デコードして`KeyId`に変換
- `ReencryptContentCommand`を構築

**`requester_key_id`について**:

- **現時点**: `requester_key_id`は必要（Owner権限チェックに使用）
  - `monas-content`側でOwner権限チェックを実施するため、`requester_key_id`が必要
  - APIリクエストとコマンドに含める
  
- **将来（monas-state-node移行後）**: `requester_key_id`は不要（権限チェックはmonas-state-node側で実施）
  - 権限チェックは`monas-state-node`側で実施されるため、`monas-content`側では`requester_key_id`は不要
  - APIリクエストから`requester_key_id`を削除し、`monas-state-node`側で権限チェック後に再暗号化APIを呼ぶ

**出力**:
```rust
#[derive(Serialize)]
pub struct ReencryptContentResponse {
    pub content_id: String,
    pub series_id: String,
    pub name: String,
    pub path: String,
    pub updated_at: String,                    // ISO 8601形式
    pub encrypted_content_base64: String,     // 暗号化されたコンテンツ（base64エンコード）
}
```

**注意**: `new_cek_base64`は含まない（既存の`create()`と同様に、CEKはローカルに保存されるのみ）




#### 2. 事前確認（アプリケーションサービス層・ドメイン層）

##### 2.1 コンテンツの取得（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::find_by_id(&content_id)` を呼び出し
- **戻り値**: `Result<Option<Content>, ContentRepositoryError>`
- **期待される値**:
  - 成功時: `Ok(Some(Content))` - 既存の`Content`構造体（`monas-content/src/domain/content/content.rs`）
  - コンテンツが存在しない場合: `Ok(None)`
- **エラー処理**: `Ok(None)`の場合、`ReencryptError::ContentNotFound`エラーを返す

##### 2.2 削除状態の確認（ドメイン層）

- **ドメイン層**: `Content::is_deleted()` を呼び出し
- **戻り値**: `bool`
- **エラー処理**: `true`の場合、`ReencryptError::ContentDeleted`エラーを返す

##### 2.3 Shareの取得（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ShareRepository::load(&content_id)` を呼び出し
- **戻り値**: `Result<Option<Share>, ShareRepositoryError>`
- **期待される値**:
  - 成功時: `Ok(Some(Share))` - 既存の`Share`構造体（`monas-content/src/domain/share/share.rs`）
    - Owner権限を持つユーザは、`ShareRecipient::permissions`に`Permission::Owner`を含む
  - Shareが存在しない場合: `Ok(None)`
- **エラー処理**: `Ok(None)`の場合、`ReencryptError::ShareNotFound`エラーを返す

##### 2.4 権限の確認（ドメイン層）

- **ドメイン層**: `Share::owner_key_id()` を呼び出し（Owner権限の確認）
- **実装**: `ShareRecipient`の`permissions`に`Permission::Owner`を含むKeyIdを検索
- **戻り値**: `Option<&KeyId>`
- **処理**:
  - Owner権限が設定されている場合（`Option::Some(owner_key_id)`）:
    - `owner_key_id == requester_key_id` を確認
    - 不一致の場合: `ReencryptError::OwnerPermissionDenied` エラーを返す
  - Owner権限が未設定の場合（`Option::None`）:
    - `ReencryptError::OwnerPermissionDenied` エラーを返す（Owner権限を前提とするため、Write権限での代替は行わない）

##### 2.5 削除確認（ドメイン層）

- **ドメイン層**: `Share::recipients()` を呼び出し
- **戻り値**: `&HashMap<KeyId, ShareRecipient>`
- **期待される値**:
  - `recipients`は`HashMap<KeyId, ShareRecipient>`型
  - `revoked_key_id`が`recipients`に含まれていないこと（`contains_key(&revoked_key_id) == false`）
- **エラー処理**: `recipients.contains_key(&revoked_key_id) == true`の場合、`ReencryptError::RevokedKeyIdStillExists`エラーを返す

##### 2.6 更新確認（ドメイン層）

- **ドメイン層**: `Content::metadata()` を呼び出し
- **戻り値**: `&Metadata` - 既存の`Metadata`構造体（`monas-content/src/domain/content/metadata.rs`）
- **ドメイン層**: `Metadata::updated_at()` を呼び出し
- **戻り値**: `DateTime<Utc>`
- **更新確認のロジック**: 暫定的な実装方針に従う（現時点では詳細未定）

#### 3. 取得したコンテンツを既存のCEKで復号（アプリケーションサービス層）

- **前提**: Step 2.1で取得した`Content`オブジェクトを使用
- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::load(&content_id)` を呼び出し
- **ドメイン層**: 取得した`Content`オブジェクトに対して`Content::decrypt(&old_cek, &encryptor)` を呼び出し
- **戻り値**: プレーンテキスト（`Vec<u8>`）
- **エラー処理**:
  - CEKが存在しない場合: `ReencryptError::MissingContentEncryptionKey`エラーを返す
  - 復号に失敗した場合: `ReencryptError::Domain(ContentError)`エラーを返す

#### 4. 新しいCEKを生成（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyGenerator::generate()` を呼び出し
- **戻り値**: `ContentEncryptionKey`

#### 5. 再暗号化されたContentを作成（ドメイン層）

- **ドメイン層**: `Content::update_content(raw_content, &id_generator, &new_cek, &encryptor)` を呼び出し
- **戻り値**: 新しい`ContentId`を持つ`Content`オブジェクト（`series_id`は維持される）
- **重要**: `Content::update_content()`は内部で暗号化を行うため、事前に`ContentEncryption::encrypt()`を呼び出す必要はない（二重暗号化を避けるため）
- **エラー処理**: 失敗時、`ReencryptError::Domain(ContentError)`エラーを返す

#### 6-9. コミットフェーズ（永続化・アトミック性保証）

**重要**: メモリ上での準備（Step 3-5）が完了してから、以下の永続化操作を実行します。

##### 6. 新しいContentIdでCEKを保存（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::save(new_content_id, &new_cek)` を呼び出し
- **エラー処理**: 失敗時、エラーを返す（まだ何も保存されていないため、ロールバック不要）

##### 7. 新しいContentIdでContentを保存（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::save(new_content_id, &reencrypted_content)` を呼び出し
- **エラー処理とロールバック**: Content保存が失敗した場合、新しいContentIdのCEKを削除してロールバック

##### 8. 古いContentIdのCEKを削除（アプリケーションサービス層）

- **事前準備**: 削除前に古いCEKをメモリ上に保存（`ContentEncryptionKeyStore::load(old_content_id)`）
- **CEKを先に削除する理由**: Step 9でContent削除が失敗した場合にCEKを復元する必要があるため。CEKは32バイトと小さいため、メモリ効率も良い。
- **インフラストラクチャ層（ポート）**: `ContentEncryptionKeyStore::delete(old_content_id)` を呼び出し
- **エラー処理とロールバック**: CEK削除が失敗した場合、新しいContentIdのCEKとContentを削除してロールバック

##### 9. 古いContentIdのContentを削除（アプリケーションサービス層）

- **インフラストラクチャ層（ポート）**: `ContentRepository::delete(old_content_id)` を呼び出し
- **エラー処理とロールバック**: Content削除が失敗した場合、新しいContentIdのCEKとContentを削除し、古いContentIdのCEKを復元してロールバック（`ContentEncryptionKeyStore::save(old_content_id, &old_cek)`）

**アトミック性保証**: この実装により、すべての操作が成功した場合のみ、新しいContentIdで保存されたデータ（ContentとCEK）が残り、古いContentIdのデータ（ContentとCEK）が削除される。いずれかの操作が失敗した場合、新しいContentIdで保存されたデータ（ContentとCEK）が削除され、古いContentIdのデータ（ContentとCEK）がそのまま残る。これにより、「途中まで実行している」状態や「CEKの生成はできたけど暗号化はうまくできなかった」などの整合性を満たせない状態が発生しない。

#### 10. ciphertextを返す（アプリケーションサービス層）

- **アプリケーションサービス層**: `ReencryptContentResult` を構築して返す（新規追加）
- **戻り値**: `Result<ReencryptContentResult, ReencryptError>`
- **`ReencryptContentResult`構造体（新規追加）**:
  - `content_id: ContentId` - 再暗号化後の新しいContentId
  - `series_id: ContentId` - 論理的な系列ID（維持される）
  - `metadata: Metadata` - 更新されたメタデータ
  - `encrypted_content: Vec<u8>` - 暗号化されたコンテンツ（ciphertext）
- **重要**:
  - `encrypted_content`は`Content::encrypted_content()`から取得した暗号化されたコンテンツのバイト列
  - 新しいCEKはローカルに保存されるが、返り値には含まれない（既存の`create()`と同様）
  - KeyEnvelopeの生成は`ShareService::grant_share()`で行う（Pull型）




## 実装内容

### 1. ドメイン層（Owner権限の実装）

#### 1.1 Permission enumの拡張

**ファイル**: `monas-content/src/domain/share/share.rs`

**実装**:
```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    Read,
    Write,
    Owner,  // Owner権限（将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
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

    // Owner権限チェック用のヘルパーメソッド（将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
    pub fn can_manage_permissions(perms: &[Permission]) -> bool {
        perms.iter().any(|p| matches!(p, Permission::Owner))
    }
}
```



#### 1.2 Share構造体の拡張

**ファイル**: `monas-content/src/domain/share/share.rs`

**実装**:
```rust
impl Share {
    // Owner権限を付与（将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
    pub fn grant_owner(&mut self, key_id: KeyId) -> Result<ShareEvent, ShareError> {
        // 既にOwner権限を持つユーザが存在するか確認
        if self.owner_key_id().is_some() {
            return Err(ShareError::InvalidOperation(
                "Owner already exists".to_string()
            ));
        }
        
        // ShareRecipientにOwner権限を追加
        if let Some(recipient) = self.recipients.get_mut(&key_id) {
            // 既存のShareRecipientにOwner権限を追加
            if !recipient.permissions().contains(&Permission::Owner) {
                recipient.permissions.push(Permission::Owner);
            }
        } else {
            // 新しいShareRecipientを作成してOwner権限を付与
            let recipient = ShareRecipient::new(
                key_id.clone(),
                vec![Permission::Owner],
            );
            self.recipients.insert(key_id.clone(), recipient);
        }
        
        Ok(ShareEvent::RecipientGranted {
            content_id: self.content_id.clone(),
            key_id,
            permissions: vec![Permission::Owner],
        })
    }

    // Owner権限を持つKeyIdを取得（ShareRecipientから導出、将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
    pub fn owner_key_id(&self) -> Option<&KeyId> {
        self.recipients.iter()
            .find(|(_, recipient)| {
                recipient.permissions().contains(&Permission::Owner)
            })
            .map(|(key_id, _)| key_id)
    }

    // 権限管理可能かを確認（将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
    fn can_manage_permissions(&self, key_id: &KeyId) -> bool {
        self.recipients
            .get(key_id)
            .map(|r| Permission::can_manage_permissions(r.permissions()))
            .unwrap_or(false)
    }
}
```

**設計方針**:
- `Share`構造体に`owner_key_id`フィールドは追加しない（`ShareRecipient`から導出）
- `ShareRecipient`構造体は変更不要（`permissions: Vec<Permission>`に`Permission::Owner`を含める）

**注意**: `grant_read()`、`grant_write()`、`revoke()`メソッドへの権限チェック追加は**行わない**。将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮。

### 2. アプリケーションサービス層

#### 2.0 コマンド/結果構造体の追加

**ファイル**: `monas-content/src/application_service/content_service/command.rs`

**実装**:
```rust
/// コンテンツ再暗号化ユースケースの入力。
#[derive(Debug)]
pub struct ReencryptContentCommand {
    pub content_id: ContentId,
    pub requester_key_id: KeyId,
    pub revoked_key_id: KeyId,
}

/// コンテンツ再暗号化ユースケースの出力。
#[derive(Debug)]
pub struct ReencryptContentResult {
    pub content_id: ContentId,                    // 再暗号化後の新しいContentId
    pub series_id: ContentId,                     // 論理的な系列ID（維持される）
    pub metadata: Metadata,                       // 更新されたメタデータ
    pub encrypted_content: Vec<u8>,                // 暗号化されたコンテンツ（ciphertext）
}
```

#### 2.1 再暗号化機能の権限チェック

**ファイル**: `monas-content/src/application_service/content_service/service.rs`

**実装**:
```rust
// Owner権限チェック（将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮）
fn check_reencrypt_permission(share: &Share, requester_key_id: &KeyId) -> bool {
    // Owner権限の確認（Owner権限を前提とする）
    // Share::owner_key_id()はShareRecipientからOwner権限を持つKeyIdを検索して返す
    if let Some(owner_key_id) = share.owner_key_id() {
        return owner_key_id == requester_key_id;
    }
    // Owner権限が未設定の場合はエラー（Write権限での代替は行わない）
    false
}
```



#### 2.2 再暗号化処理の実装（整合性保証含む）

**ファイル**: `monas-content/src/application_service/content_service/service.rs`

**実装**:
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
    
    // Step 6: 新しいContentIdでCEKを保存
    self.cek_store
        .save(&new_content_id, &new_cek)
        .map_err(ReencryptError::KeyStore)?;
    
    // Step 7: 新しいContentIdでContentを保存
    if let Err(e) = self.content_repository.save(&new_content_id, &reencrypted_content) {
        // ロールバック: 新しいContentIdのCEKを削除
        let _ = self.cek_store.delete(&new_content_id);
        return Err(ReencryptError::ContentRepository(e));
    }
    
    // Step 8: 古いContentIdのCEKを削除する前に保存（メモリ効率のため、CEKのみを保存）
    let old_cek = match self.cek_store.load(&old_content_id) {
        Ok(Some(cek)) => Some(cek),
        _ => None,
    };
    
    // Step 8: 古いContentIdのCEKを削除
    if let Err(e) = self.cek_store.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        return Err(ReencryptError::KeyStore(e));
    }
    
    // Step 9: 古いContentIdのContentを削除
    if let Err(e) = self.content_repository.delete(&old_content_id) {
        // ロールバック: 新しいContentIdのCEKとContentを削除
        // 古いContentIdのCEKを復元（アトミック性を保証するため）
        if let Some(cek) = old_cek {
            let _ = self.cek_store.save(&old_content_id, &cek);
        }
        let _ = self.cek_store.delete(&new_content_id);
        let _ = self.content_repository.delete(&new_content_id);
        return Err(ReencryptError::ContentRepository(e));
    }
    
    // すべて成功: 新しいContentIdで保存されたデータ（ContentとCEK）のみが残る
    Ok(ReencryptContentResult {
        content_id: new_content_id,
        series_id: reencrypted_content.series_id().clone(),
        metadata: reencrypted_content.metadata().clone(),
        encrypted_content: reencrypted_content.encrypted_content()
            .ok_or(ReencryptError::MissingEncryptedContent)?
            .clone(),
        // new_cekは返さない（既存のcreate()と同様に、ローカルに保存されるのみ）
    })
}
```

**アトミック性保証**:
- メモリ上で全ての準備（復号、CEK生成、再暗号化）を完了してから永続化を開始
- 新しいContentIdでCEKとContentを保存し、すべて成功したら古いContentIdのデータ（ContentとCEK）を削除
- いずれかの操作が失敗した場合、新しいContentIdで保存されたデータ（ContentとCEK）を削除してロールバック
- これにより、「途中まで実行している」状態や「CEKの生成はできたけど暗号化はうまくできなかった」などの整合性を満たせない状態が発生しない

**注意**: `ContentRepository`トレイトに`delete`メソッドを追加する必要があります。既存の実装を確認し、必要に応じて追加します。

#### 2.3 ShareServiceの変更（オプション）

**注意**: `ShareService::grant_share()`と`revoke_share()`へのOwner権限チェック追加は**行わない**。将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画を考慮。

### 3. エラーハンドリング

**ファイル**: `monas-content/src/application_service/content_service/mod.rs` または `error.rs`

**実装**:
```rust
#[error("owner permission denied: requester_key_id={requester_key_id}, content_id={content_id}")]
OwnerPermissionDenied { 
    requester_key_id: KeyId, 
    content_id: ContentId 
},
```



### 4. アトミック性を保証する設計

#### 4.1 設計方針

**設計方針**: **2フェーズコミットパターン**を採用し、すべての操作をアトミックに完了させる

**採用理由**:
1. **要件の明確性**: 「途中まで実行している」状態を許容しない要件に合う
2. **データ整合性の重要性**: 暗号化システムでは整合性が重要、CEKとContentの不整合は致命的
3. **実装コストは許容範囲**: `delete`メソッドの追加は既存パターンに沿う
4. **ContentId変更への対応**: `Content::update_content()`が既に新しいContentIdを生成

**実装**: 詳細は「2.2 再暗号化処理の実装（整合性保証含む）」を参照

### 5. テスト戦略

Owner権限の実装に関するテスト：

1. **正常系**: Owner権限を持つユーザが再暗号化を実行
2. **異常系**: Owner権限が設定されていない場合、再暗号化不可（`OwnerPermissionDenied`エラー）
3. **異常系**: Owner権限が設定されている場合、Owner権限を持たないユーザは再暗号化不可（`OwnerPermissionDenied`エラー）

#### 5.1 アトミック性保証のテスト

以下のテストケースを追加して、アトミック性が保証されていることを確認：

1. **正常系**: すべての操作が成功する場合
   - 前提条件: すべての操作が成功
   - 期待結果: 
     - 新しいContentIdでCEKとContentが保存される
     - 古いContentIdのCEKとContentが削除される
     - 新しいContentIdで保存されたデータ（ContentとCEK）のみが存在する
     - 整合性が保たれる

2. **異常系**: 新しいContentIdでCEK保存が失敗した場合
   - 前提条件: `ContentEncryptionKeyStore::save()`がエラーを返す
   - 期待結果: 何も保存されない（古いContentIdのデータ（ContentとCEK）はそのまま）、エラーが返される

3. **異常系**: 新しいContentIdでContent保存が失敗した場合
   - 前提条件: `ContentRepository::save()`がエラーを返す
   - 期待結果: 新しいContentIdのCEKが削除される（ロールバック）、古いContentIdのデータ（ContentとCEK）はそのまま、エラーが返される

4. **異常系**: 古いContentIdのCEK削除が失敗した場合（Step 8）
   - 前提条件: `ContentEncryptionKeyStore::delete()`がエラーを返す
   - 期待結果: 新しいContentIdで保存されたデータ（ContentとCEK）が削除される（ロールバック）、古いContentIdのデータ（ContentとCEK）はそのまま、エラーが返される

5. **異常系**: 古いContentIdのContent削除が失敗した場合（Step 9）
   - 前提条件: `ContentRepository::delete()`がエラーを返す
   - 期待結果: 新しいContentIdで保存されたデータ（ContentとCEK）が削除される（ロールバック）、古いContentIdのCEKが復元される（アトミック性を保証するため）、古いContentIdのデータ（ContentとCEK）はそのまま、エラーが返される

6. **整合性チェック**: 再暗号化後、ContentとCEKの整合性を確認
   - 前提条件: 再暗号化が成功
   - 期待結果: 
     - 新しいContentIdで`ContentRepository::find_by_id()`でContentが取得できる
     - 新しいContentIdで`ContentEncryptionKeyStore::load()`でCEKが取得できる
     - `Content::decrypt()`でCEKを使ってContentを復号できる
     - 古いContentIdのデータ（ContentとCEK）は存在しない

## 将来の移行計画（オプション）

将来的にmonas-state-nodeが権限管理を引き継ぐ場合の移行計画です。現時点ではOwner権限は`monas-content`で管理する本実装として扱いますが、将来的な移行可能性を考慮して記載しています。

### 移行対象（将来monas-state-nodeが権限管理を引き継ぐ場合）

1. `Permission::Owner` enum variantの権限チェックロジック
2. `ShareRecipient::permissions`から`Permission::Owner`の管理方法（ShareRecipient自体は残す）
3. `Share::grant_owner()` メソッドの権限管理ロジック
4. `Share::owner_key_id()` メソッドの権限チェックロジック（ShareRecipientから導出するヘルパーメソッド）
5. `Share::can_manage_permissions()` メソッドの権限チェックロジック（プライベート）
6. `Permission::can_manage_permissions()` メソッドの権限チェックロジック
7. `check_reencrypt_permission()` のOwner権限チェック部分
8. `ReencryptContentRequest::requester_key_id_base64` フィールド
9. `ReencryptContentCommand::requester_key_id` フィールド

**注意**: `Share`構造体に`owner_key_id`フィールドは存在しないため、移行対象には含まれない。Owner権限は`ShareRecipient::permissions`に`Permission::Owner`を含める方式で実装される。

### 移行後の動作（将来monas-state-nodeが権限管理を引き継ぐ場合）

- 権限管理はmonas-state-nodeが担当
- Owner権限チェックはmonas-state-node側で行われる
- `requester_key_id`は不要（権限チェックはmonas-state-node側で実施）
  - APIリクエストから`requester_key_id`を削除
  - `monas-state-node`側で権限チェック後に再暗号化APIを呼ぶ

## 統合・使用箇所

### monas-sdkでの使用

この再暗号化操作は、`monas-sdk/src/controller/share.rs`の`revoke_share`メソッド（264行目付近）で使用されます。

**使用フロー**:
1. `ShareService::revoke_share()`を呼び出して共有を取り消す
2. State Node側へ権限の送信（TODO）
3. **コンテンツの再暗号処理**（本設計書で定義する再暗号化APIを呼び出す）
   - 再暗号化処理が完了し、ciphertext（`encrypted_content`）が返される
   - 新しいCEKはローカルに保存される（既存の`create()`と同様）
4. **KeyEnvelopeの再生成**（monas-sdk側で実装、Pull型）
   - 残っている正当なユーザに対して`ShareService::grant_share()`を呼び出し、新しいKeyEnvelopeを生成
   - `ShareService::grant_share()`は既存の実装で、ローカルに保存されたCEKを取得してciphertextを含むKeyEnvelopeを生成できる
5. 各ユーザにKeyEnvelopeを配布（既存の`share_content` APIと同様）
6. 結果を返す

**目的**: 共有を取り消した後、取り消されたユーザがコンテンツにアクセスできないようにするため、コンテンツを新しいCEKで再暗号化する必要があります。

**KeyEnvelope生成について**:
- KeyEnvelopeの生成は`ShareService::grant_share()`で行う（既存実装を利用、Pull型）
- 再暗号化APIはciphertextを返すのみで、KeyEnvelopeの生成は行わない
- 新しいCEKはローカルに保存されるため、`ShareService::grant_share()`で取得可能
- monas-sdk側で、残っている正当なユーザに対して`ShareService::grant_share()`を呼び出す（既存の`share_content` APIと同様のフロー）

## ファイル構成

```bash
monas-content/src/
├── domain/share/
│   └── share.rs (Permission::Owner追加、ShareRecipient::permissionsにOwner権限を含める方式)
├── application_service/content_service/
│   ├── command.rs (ReencryptContentCommand, ReencryptContentResult追加)
│   ├── service.rs (reencryptメソッド追加 - Owner権限チェック含む)
│   └── mod.rs (ReencryptError追加)
└── presentation/
    └── content.rs (再暗号化APIエンドポイント追加)
```
