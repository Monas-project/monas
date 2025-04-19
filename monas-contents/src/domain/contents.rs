use crate::domain::metadata::Metadata;
use crate::domain::state_nodes::StateNodes;
use crate::infrastructure::key_pair::{KeyPair, KeyPairFactory, KeyType};
use crate::infrastructure::storage::StorageError;
use chrono::{DateTime, Utc};
// use std::fmt;

// 削除状態を表す列挙型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteStatus {
    Active,
    Deleting,
    Deleted,
}

// エラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentsError {
    ContentsAlreadyDeleted,
    EncryptionError(String),
    DecryptionError(String),
    StorageError(String), // Storage関連のエラーを追加
    DeleteNotInProgress, // 削除処理が進行中でない場合のエラー
}

// ドメインイベント
#[derive(Debug, Clone)]
pub enum ContentsEvent {
    ContentsCreated {
        name: String,
        path: String,
        public_key: String, // KeyPairから取得
        nodes: StateNodes,
    },
    ContentsUpdated {
        name: String,
        path: String,
        public_key: String, // KeyPairから取得
        version: u32,       // Metadataから取得
        nodes: StateNodes,
    },
    ContentsDeleted {
        name: String,
        path: String,
        public_key: String, // KeyPairから取得
    },
}

#[derive(Debug)]
pub struct Contents {
    raw_contents: Option<Vec<u8>>, // 暗号化前の生データ (Option)
    encrypted_contents: Option<Vec<u8>>, // 暗号化後のデータ (Option)
    key_pair: Box<dyn KeyPair>,
    metadata: Metadata,
    deleted: bool,
    delete_status: DeleteStatus, // 削除状態を追加
}

impl Contents {
    // コンテンツの作成
    pub fn create(
        name: String,
        raw_contents: Vec<u8>,
        path: String,
        nodes: StateNodes,
        key_pair: Box<dyn KeyPair>,
    ) -> Result<(Self, ContentsEvent), ContentsError> {
        let metadata = Metadata::new(name.clone(), &raw_contents, path.clone(), nodes.clone());

        let mut contents = Self {
            raw_contents: Some(raw_contents),
            encrypted_contents: None, // 初期状態では暗号化されていない
            key_pair,
            metadata,
            deleted: false,
            delete_status: DeleteStatus::Active,
        };

        // 作成時に暗号化を実行
        contents.encrypt()?;

        let event = ContentsEvent::ContentsCreated {
            name,
            path,
            public_key: contents.key_pair.public_key(),
            nodes,
        };

        Ok((contents, event))
    }

    // コンテンツの更新
    pub fn update(
        &mut self,
        new_raw_contents: Vec<u8>,
    ) -> Result<ContentsEvent, ContentsError> {
        if self.deleted {
            return Err(ContentsError::ContentsAlreadyDeleted);
        }

        // バージョンの更新
        self.metadata.increment_version();

        // 生データの更新
        self.raw_contents = Some(new_raw_contents);
        // 暗号化データの更新
        self.encrypt()?;

        // イベント発行
        let event = ContentsEvent::ContentsUpdated {
            name: self.metadata.name().to_string(),
            path: self.metadata.path().to_string(),
            public_key: self.key_pair.public_key(),
            version: self.metadata.version(),
            nodes: self.metadata.nodes().clone(),
        };

        Ok(event)
    }

    // コンテンツの削除 (論理削除)
    pub fn delete(&mut self) -> Result<ContentsEvent, ContentsError> {
        if self.deleted {
            return Err(ContentsError::ContentsAlreadyDeleted);
        }

        self.deleted = true; // 本番ではアトミックな処理が必要，今のところトランザクション性がない
        // 削除時には生データと暗号化データをクリアする (任意)
        self.raw_contents = None;
        self.encrypted_contents = None;

        // イベント発行
        let event = ContentsEvent::ContentsDeleted {
            name: self.metadata.name().to_string(),
            path: self.metadata.path().to_string(),
            public_key: self.key_pair.public_key(),
        };

        Ok(event)
    }

    // 暗号化 (内部メソッド)
    fn encrypt(&mut self) -> Result<(), ContentsError> {
        if let Some(contents) = &self.raw_contents {
            let encrypted = self.key_pair.encrypt(contents);
            self.encrypted_contents = Some(encrypted);
            Ok(())
        } else {
            // 生データがない場合はエラー or 何もしない
            Err(ContentsError::EncryptionError("No raw content to encrypt".to_string()))
        }
    }

    // 復号化 (必要に応じて公開メソッドにする)
    pub fn decrypt(&self) -> Result<Option<Vec<u8>>, ContentsError> {
        if self.deleted {
            return Ok(None); // 削除済みならNone
        }
        if let Some(encrypted) = &self.encrypted_contents {
            let decrypted = self.key_pair.decrypt(encrypted);
            Ok(Some(decrypted))
        } else {
            Ok(None) // 暗号化データがない
        }
    }

    // ゲッター
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn key_pair(&self) -> &dyn KeyPair {
        &*self.key_pair
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    // 暗号化されたコンテンツデータを取得するゲッター
    pub fn encrypted_contents(&self) -> Option<&Vec<u8>> {
        self.encrypted_contents.as_ref()
    }

    // 暗号化鍵を生成してコンテンツを作成するファクトリメソッド
    pub fn create_with_generated_key(
        name: String,
        raw_contents: Vec<u8>,
        path: String,
        nodes: StateNodes,
        key_type: KeyType,
    ) -> Result<(Self, ContentsEvent), ContentsError> {
        let key_pair = KeyPairFactory::generate(key_type);
        Self::create(name, raw_contents, path, nodes, key_pair)
    }

    // 削除状態を取得
    pub fn delete_status(&self) -> &DeleteStatus {
        &self.delete_status
    }

    // 削除状態を設定
    pub fn set_delete_status(&mut self, status: DeleteStatus) {
        self.delete_status = status;
    }

    // 削除処理を開始
    pub fn begin_delete(&mut self) -> Result<(), ContentsError> {
        if self.delete_status != DeleteStatus::Active {
            return Err(ContentsError::ContentsAlreadyDeleted);
        }
        self.delete_status = DeleteStatus::Deleting;
        Ok(())
    }

    // 削除処理を実行
    pub fn execute_delete(&mut self) -> Result<ContentsEvent, ContentsError> {
        if self.delete_status != DeleteStatus::Deleting {
            return Err(ContentsError::DeleteNotInProgress);
        }
        self.delete_status = DeleteStatus::Deleted;
        self.deleted = true;

        // イベント発行
        let event = ContentsEvent::ContentsDeleted {
            name: self.metadata.name().to_string(),
            path: self.metadata.path().to_string(),
            public_key: self.key_pair.public_key(),
        };

        Ok(event)
    }

    // 削除処理をキャンセル
    pub fn cancel_delete(&mut self) -> Result<(), ContentsError> {
        if self.delete_status != DeleteStatus::Deleting {
            return Err(ContentsError::DeleteNotInProgress);
        }
        self.delete_status = DeleteStatus::Active;
        Ok(())
    }
}

// StorageErrorからContentsErrorへの変換を実装
#[cfg(test)]
impl From<StorageError> for ContentsError {
    fn from(error: StorageError) -> Self {
        // テストケース用に簡略化した実装
        ContentsError::StorageError("Storage error".to_string())
    }
}

// 本番環境用の実装
#[cfg(not(test))]
impl From<StorageError> for ContentsError {
    fn from(error: StorageError) -> Self {
        // StorageErrorにDisplayトレイトが実装されていないため、エラーメッセージを直接指定
        ContentsError::StorageError("Storage error occurred".to_string())
    }
}

// テストケース用のClone実装
#[cfg(test)]
impl Clone for Contents {
    fn clone(&self) -> Self {
        Self {
            raw_contents: self.raw_contents.clone(),
            encrypted_contents: self.encrypted_contents.clone(),
            // key_pair はクローンせず、新しい Box を作成
            key_pair: self.key_pair.clone_box(),
            metadata: self.metadata.clone(),
            deleted: self.deleted,
            delete_status: self.delete_status.clone(),
        }
    }
}

// 本番環境用のClone実装
#[cfg(not(test))]
impl Clone for Contents {
    fn clone(&self) -> Self {
        Self {
            raw_contents: self.raw_contents.clone(),
            encrypted_contents: self.encrypted_contents.clone(),
            // key_pair はクローンせず、新しい Box を作成
            key_pair: self.key_pair.clone_box(),
            metadata: self.metadata.clone(),
            deleted: self.deleted,
            delete_status: self.delete_status.clone(),
        }
    }
}
