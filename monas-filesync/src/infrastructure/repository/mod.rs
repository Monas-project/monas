pub trait FileRepository: Send + Sync {
    fn put(&self, key: &str, value: Vec<u8>);
    fn get(&self, key: &str) -> Option<Vec<u8>>;
}

use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemoryFileRepository(RwLock<HashMap<String, Vec<u8>>>);

impl Default for MemoryFileRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryFileRepository {
    pub fn new() -> Self { Self(RwLock::new(HashMap::new())) }
}

impl FileRepository for MemoryFileRepository {
    fn put(&self, key: &str, value: Vec<u8>) {
        self.0.write().unwrap().insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.0.read().unwrap().get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_repository_new() {
        let repo = MemoryFileRepository::new();
        assert!(repo.get("nonexistent").is_none());
    }

    #[test]
    fn test_memory_repository_put_and_get() {
        let repo = MemoryFileRepository::new();
        let key = "test_key";
        let value = b"test_value".to_vec();

        repo.put(key, value.clone());
        
        let retrieved = repo.get(key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), value);
    }

    #[test]
    fn test_memory_repository_get_nonexistent() {
        let repo = MemoryFileRepository::new();
        assert!(repo.get("nonexistent_key").is_none());
    }

    #[test]
    fn test_memory_repository_overwrite() {
        let repo = MemoryFileRepository::new();
        let key = "test_key";
        
        repo.put(key, b"first_value".to_vec());
        repo.put(key, b"second_value".to_vec());
        
        let retrieved = repo.get(key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), b"second_value".to_vec());
    }

    #[test]
    fn test_memory_repository_multiple_keys() {
        let repo = MemoryFileRepository::new();
        
        repo.put("key1", b"value1".to_vec());
        repo.put("key2", b"value2".to_vec());
        repo.put("key3", b"value3".to_vec());
        
        assert_eq!(repo.get("key1").unwrap(), b"value1".to_vec());
        assert_eq!(repo.get("key2").unwrap(), b"value2".to_vec());
        assert_eq!(repo.get("key3").unwrap(), b"value3".to_vec());
    }

    #[test]
    fn test_memory_repository_empty_value() {
        let repo = MemoryFileRepository::new();
        let key = "empty_key";
        
        repo.put(key, vec![]);
        
        let retrieved = repo.get(key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), vec![]);
    }
}
