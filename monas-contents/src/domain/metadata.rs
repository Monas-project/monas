use crate::domain::state_nodes::StateNodes;
use chrono::{DateTime, Utc};
use crate::infrastructure::storage::StorageError;
use crate::domain::contents::ContentsError;

#[derive(Debug, Clone)]
pub struct Metadata {
    name: String,
    version: u32,
    path: String,
    nodes: StateNodes,
    hash: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Metadata {
    pub fn new(
        name: String,
        raw_contents: &[u8],
        path: String,
        nodes: StateNodes,
    ) -> Self {
        let now = Utc::now();
        Self {
            name,
            version: 1,
            path,
            nodes,
            hash: Self::calculate_hash(raw_contents),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn increment_version(&mut self) {
        self.version += 1;
        self.updated_at = Utc::now();
    }

    fn calculate_hash(raw_contents: &[u8]) -> String {
        // ハッシュ計算のダミー実装 (sha2 クレートを使う例)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw_contents);
        hex::encode(hasher.finalize())
    }

    // ゲッター
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn nodes(&self) -> &StateNodes {
        &self.nodes
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_hash() {
        // 空のバイト配列のハッシュ
        let empty_hash = Metadata::calculate_hash(&[]);
        assert_eq!(
            empty_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // "hello" のハッシュ
        let hello_hash = Metadata::calculate_hash(b"hello");
        assert_eq!(
            hello_hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        // 日本語のハッシュ
        let japanese_hash = Metadata::calculate_hash("こんにちは".as_bytes());
        assert_eq!(
            japanese_hash,
            "125aeadf27b0459b8760c13a3d80912dfa8a81a68261906f60d87f4a0268646c"
        );

        // 長いテキストのハッシュ
        let long_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let long_text_hash = Metadata::calculate_hash(long_text.as_bytes());
        assert_eq!(
            long_text_hash,
            "1f38b148591b024f56cd04fa661758d758dd31d855a225c4645126e76be72f32"
        );

        // // バイナリデータのハッシュ
        let binary_data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let binary_hash = Metadata::calculate_hash(&binary_data);
        println!("binary_hash: {}", binary_hash);
        assert_eq!(
            binary_hash,
            "1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3"
        );
    }
    
    #[test]
    // メタデータ生成プロセスの整合性を検証
    fn test_metadata_hash_in_new() {
        // テスト用のデータを準備
        let name = "テストメタデータ".to_string();
        let raw_contents = "テストコンテンツ".as_bytes();
        let path = "/test/path".to_string();
        let nodes = StateNodes::new(Vec::new());
        
        // メタデータを作成
        let metadata = Metadata::new(name, raw_contents, path, nodes);
        
        // ハッシュが正しく計算されていることを確認
        let expected_hash = Metadata::calculate_hash(raw_contents);
        assert_eq!(metadata.hash(), expected_hash);
    }
}
