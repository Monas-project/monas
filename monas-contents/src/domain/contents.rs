use crate::domain::metadata::Metadata;
use crate::domain::license::License;
use crate::domain::state_nodes::StateNodes;
use crate::infrastructure::key_pair::{KeyPair, KeyPairFactory, KeyPairType};
use chrono::{DateTime, Utc};
use std::fmt;

// エラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentsError {
    ContentsAlreadyDeleted,
    EncryptionError(String),
    DecryptionError(String),
    StorageError(String), // Storage関連のエラーを追加
}

// ドメインイベント
#[derive(Debug, Clone)]
pub enum ContentsEvent {
    ContentsCreated {
        name: String,
        path: String,
        public_key: String, // KeyPairから取得
        license: License,
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

#[derive(Debug, Clone)]
pub struct Contents {
    raw_contents: Option<Vec<u8>>, // 暗号化前の生データ (Option)
    encrypted_contents: Option<Vec<u8>>, // 暗号化後のデータ (Option)
    key_pair: Box<dyn KeyPair>,
    metadata: Metadata,
    deleted: bool,
}

impl Contents {
    // コンテンツの作成
    pub fn create(
        name: String,
        raw_contents: Vec<u8>,
        path: String,
        license: License,
        nodes: StateNodes,
        key_pair: Box<dyn KeyPair>,
    ) -> Result<(Self, ContentsEvent), ContentsError> {
        let metadata = Metadata::new(name.clone(), &raw_contents, path.clone(), license.clone(), nodes.clone());

        let mut contents = Self {
            raw_contents: Some(raw_contents),
            encrypted_contents: None, // 初期状態では暗号化されていない
            key_pair,
            metadata,
            deleted: false,
        };

        // 作成時に暗号化を実行
        contents.encrypt()?;

        let event = ContentsEvent::ContentsCreated {
            name,
            path,
            public_key: contents.key_pair.public_key(),
            license,
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
        license: License,
        nodes: StateNodes,
        key_type: KeyPairType,
    ) -> Result<(Self, ContentsEvent), ContentsError> {
        // 鍵の生成
        let key_pair: Box<dyn KeyPair> = Box::new(KeyPairFactory::generate(key_type));

        // 通常のcreateメソッドを呼び出す
        Self::create(
            name,
            raw_contents,
            path,
            license,
            nodes,
            key_pair,
        )
    }
}

// chrono クレートを使うためにCargo.tomlに追加する必要があります
// [dependencies]
// chrono = { version = "0.4", features = ["serde"] }
