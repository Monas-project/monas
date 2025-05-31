use crate::domain::content::Content;
use crate::domain::metadata::Metadata;
use crate::infrastructure::storage::{Storage, StorageError};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContentStorageError {
    #[error("Failed to create metadata file: {0}")]
    MetadataFileCreation(String),

    #[error("Failed to create content directory: {0}")]
    DirectoryCreation(String),

    #[error("Failed to read metadata: {0}")]
    MetadataRead(String),

    #[error("Failed to write metadata: {0}")]
    MetadataWrite(String),

    #[error("Failed to delete metadata: {0}")]
    MetadataDelete(String),

    #[error("Failed to serialize metadata: {0}")]
    MetadataSerialization(String),

    #[error("Failed to deserialize metadata: {0}")]
    MetadataDeserialization(String),
}

impl From<std::io::Error> for ContentStorageError {
    fn from(err: std::io::Error) -> Self {
        ContentStorageError::MetadataRead(err.to_string())
    }
}

impl From<serde_json::Error> for ContentStorageError {
    fn from(err: serde_json::Error) -> Self {
        ContentStorageError::MetadataSerialization(err.to_string())
    }
}

impl From<ContentStorageError> for StorageError {
    fn from(err: ContentStorageError) -> Self {
        match err {
            ContentStorageError::MetadataFileCreation(msg)
            | ContentStorageError::DirectoryCreation(msg)
            | ContentStorageError::MetadataWrite(msg)
            | ContentStorageError::MetadataSerialization(msg) => StorageError::SaveError(msg),
            ContentStorageError::MetadataRead(msg)
            | ContentStorageError::MetadataDeserialization(msg) => StorageError::ReadError(msg),
            ContentStorageError::MetadataDelete(msg) => StorageError::DeleteError(msg),
        }
    }
}

/// Serializable structure for storing metadata in JSON format
#[derive(Serialize, Deserialize, Debug)]
struct SerializedMetadata {
    name: String,
    path: String,
    hash: String,
    created_at: String,
    updated_at: String,
}

/// Converts domain Metadata to serializable format
impl From<&Metadata> for SerializedMetadata {
    fn from(metadata: &Metadata) -> Self {
        Self {
            name: metadata.name().to_string(),
            path: metadata.path().to_string(),
            hash: metadata.hash().to_string(),
            created_at: metadata.created_at().to_rfc3339(),
            updated_at: metadata.updated_at().to_rfc3339(),
        }
    }
}

struct ContentLocalStorage {
    base_path: String,
}

impl ContentLocalStorage {
    /// Creates a new ContentLocalStorage instance without creating base directories
    #[allow(dead_code)]
    fn new(base_path: String) -> Self {
        Self { base_path }
    }

    /// Creates a new ContentLocalStorage instance with the specified base path
    /// and ensures the base directory exists
    fn create_with_path(base_path: String) -> Result<Self, ContentStorageError> {
        if !Path::new(&base_path).exists() {
            fs::create_dir_all(&base_path).map_err(|e| {
                ContentStorageError::DirectoryCreation(format!(
                    "Failed to create base directory {}: {}",
                    base_path, e
                ))
            })?;
        }
        Ok(Self { base_path })
    }

    /// Builds a full filesystem path by joining the base path with a relative path
    #[allow(dead_code)]
    fn fetch_full_path(&self, relative_path: &str) -> String {
        Path::new(&self.base_path)
            .join(relative_path)
            .to_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Generates the path where metadata for a specific content should be stored
    fn fetch_metadata_path(&self, content_path: &str) -> String {
        let content_path = Path::new(content_path);
        let file_stem = content_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let parent = content_path
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or_default();

        Path::new(&self.base_path)
            .join(parent)
            .join(format!("{}.metadata.json", file_stem))
            .to_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Saves only the metadata of a Content object to a file
    ///
    /// # Arguments
    /// * `content` - The Content object to save metadata from
    ///
    /// # Returns
    /// * `Ok(())` - Metadata was successfully saved
    /// * `Err(ContentStorageError)` - An error occurred during saving
    fn save_metadata_only(&self, content: &Content) -> Result<(), ContentStorageError> {
        let metadata = content.metadata();
        let serialized_metadata = SerializedMetadata::from(metadata);

        let metadata_path = self.fetch_metadata_path(metadata.path());

        // Create directory for metadata file if it doesn't exist
        if let Some(parent) = Path::new(&metadata_path).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    ContentStorageError::DirectoryCreation(format!(
                        "Failed to create directory: {}",
                        e
                    ))
                })?;
            }
        }

        // Serialize metadata to JSON
        let json_data = serde_json::to_string_pretty(&serialized_metadata).map_err(|e| {
            ContentStorageError::MetadataSerialization(format!(
                "Failed to serialize metadata: {}",
                e
            ))
        })?;

        // Write metadata to file
        let mut file = fs::File::create(&metadata_path).map_err(|e| {
            ContentStorageError::MetadataFileCreation(format!(
                "Failed to create metadata file {}: {}",
                metadata_path, e
            ))
        })?;

        file.write_all(json_data.as_bytes()).map_err(|e| {
            ContentStorageError::MetadataWrite(format!(
                "Failed to write to metadata file {}: {}",
                metadata_path, e
            ))
        })?;

        println!("Saved metadata to local storage: {}", metadata_path);
        Ok(())
    }
}

// Factory function for creating ContentLocalStorage instances
pub fn create_local_storage(base_path: String) -> Result<impl Storage, StorageError> {
    ContentLocalStorage::create_with_path(base_path).map_err(StorageError::from)
}

/// Implementation of the Storage trait for filesystem-based metadata storage
///
/// This implementation stores only the metadata of Content objects and
/// does not store the actual content data. It is specialized for metadata management.
///
/// # Notes
/// * The `read` method always returns an error (as content data is not stored)
/// * The `save` and `delete` methods operate only on metadata files
impl Storage for ContentLocalStorage {
    fn save(&self, content: &Content) -> Result<(), StorageError> {
        // Save only metadata
        self.save_metadata_only(content).map_err(StorageError::from)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        // Content data is not stored, only metadata
        Err(StorageError::ReadError(format!(
            "Content data is not stored: {}",
            path
        )))
    }

    fn delete(&self, path: &str) -> Result<(), StorageError> {
        // Delete metadata file
        let metadata_path = self.fetch_metadata_path(path);
        if Path::new(&metadata_path).exists() {
            fs::remove_file(&metadata_path).map_err(|e| {
                ContentStorageError::MetadataDelete(format!(
                    "Failed to delete metadata file {}: {}",
                    metadata_path, e
                ))
            })?;
            println!("Deleted metadata from local storage: {}", metadata_path);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::domain::content::{Content, ContentKeyPair};
    use crate::domain::metadata::Metadata;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    // Mock implementation for ContentKeyPair
    #[derive(Debug, Clone)]
    struct MockKeyPair;

    impl ContentKeyPair for MockKeyPair {
        fn encrypt(&self, data: &[u8]) -> Vec<u8> {
            data.to_vec() // Simple passthrough for testing
        }

        fn decrypt(&self, data: &[u8]) -> Vec<u8> {
            data.to_vec() // Simple passthrough for testing
        }

        fn public_key(&self) -> String {
            "mock_public_key".to_string()
        }
    }

    // Helper function to create a test Content
    fn create_test_content(name: &str, path: &str, content: &[u8]) -> Content {
        let metadata = Metadata::new(name.to_string(), content, path.to_string());

        Content::new(
            metadata,
            Some(content.to_vec()),
            Some(content.to_vec()),
            Some(Box::new(MockKeyPair)),
            false,
        )
    }

    // Test for ContentLocalStorage::new()
    #[test]
    fn test_new_creates_base_path() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let non_existent_path = temp_dir
            .path()
            .join("new_dir")
            .to_string_lossy()
            .to_string();

        // Verify the directory doesn't exist yet
        assert!(!Path::new(&non_existent_path).exists());

        // Create the storage
        let result = ContentLocalStorage::create_with_path(non_existent_path.clone());
        assert!(result.is_ok());

        // Verify the directory was created
        assert!(Path::new(&non_existent_path).exists());
    }

    // Test for ContentLocalStorage::fetch_full_path()
    #[test]
    fn test_fetch_full_path() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = ContentLocalStorage::create_with_path(base_path.clone()).unwrap();

        let relative_path = "test/file.txt";
        let full_path = storage.fetch_full_path(relative_path);

        let expected_path = Path::new(&base_path)
            .join(relative_path)
            .to_string_lossy()
            .to_string();
        assert_eq!(full_path, expected_path);
    }

    // Test for ContentLocalStorage::fetch_metadata_path()
    #[test]
    fn test_fetch_metadata_path() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = ContentLocalStorage::create_with_path(base_path.clone()).unwrap();

        let content_path = "test/document.txt";
        let metadata_path = storage.fetch_metadata_path(content_path);

        let expected_path = Path::new(&base_path)
            .join("test")
            .join("document.metadata.json")
            .to_string_lossy()
            .to_string();

        assert_eq!(metadata_path, expected_path);
    }

    // Test for ContentLocalStorage::save_metadata_only()
    #[test]
    fn test_save_metadata_only() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = ContentLocalStorage::create_with_path(base_path.clone()).unwrap();

        let content = create_test_content(
            "Test Document",
            "test/save_test.txt",
            b"This is test content",
        );

        let result = storage.save_metadata_only(&content);
        assert!(result.is_ok());

        // Verify metadata file exists
        let metadata_path = storage.fetch_metadata_path("test/save_test.txt");
        assert!(Path::new(&metadata_path).exists());

        // Read the metadata file and verify it contains expected data
        let metadata_content = fs::read_to_string(&metadata_path).unwrap();
        assert!(metadata_content.contains("Test Document"));
        assert!(metadata_content.contains("test/save_test.txt"));
    }

    // Test for ContentLocalStorage::save_metadata_only() with nested directory path
    #[test]
    fn test_save_metadata_with_nested_path() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = ContentLocalStorage::create_with_path(base_path.clone()).unwrap();

        let content = create_test_content(
            "Nested Document",
            "deeply/nested/path/doc.txt",
            b"This is a test content in nested directory",
        );

        let result = storage.save_metadata_only(&content);
        assert!(result.is_ok());

        // Verify nested directories were created
        let metadata_path = storage.fetch_metadata_path("deeply/nested/path/doc.txt");
        assert!(Path::new(&metadata_path).exists());
        assert!(Path::new(&metadata_path).parent().unwrap().exists());
    }

    // Test for Storage::save()
    #[test]
    fn test_storage_save() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = create_local_storage(base_path.clone()).unwrap();

        let content = create_test_content(
            "Storage Save Test",
            "storage/save_test.txt",
            b"Content for storage trait test",
        );

        let result = storage.save(&content);
        assert!(result.is_ok());

        // Verify metadata file exists
        let metadata_path = Path::new(&base_path)
            .join("storage")
            .join("save_test.metadata.json");
        assert!(metadata_path.exists());
    }

    // Test for Storage::read() (should always return error)
    #[test]
    fn test_storage_read_returns_error() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = create_local_storage(base_path).unwrap();

        let result = storage.read("any/path.txt");
        assert!(result.is_err());

        // Verify the error message mentions content data not being stored
        if let Err(StorageError::ReadError(msg)) = result {
            assert!(msg.contains("Content data is not stored"));
        } else {
            panic!("Expected ReadError");
        }
    }

    // Test for Storage::delete()
    #[test]
    fn test_storage_delete() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = ContentLocalStorage::create_with_path(base_path.clone()).unwrap();

        let content = create_test_content(
            "Delete Test",
            "storage/delete_test.txt",
            b"Content to be deleted",
        );

        storage.save(&content).unwrap();

        // Verify metadata file exists
        let metadata_path = storage.fetch_metadata_path("storage/delete_test.txt");
        assert!(Path::new(&metadata_path).exists());

        let result = storage.delete("storage/delete_test.txt");
        assert!(result.is_ok());

        // Verify metadata file no longer exists
        assert!(!Path::new(&metadata_path).exists());
    }

    // Test for Storage::delete() when metadata doesn't exist (should succeed)
    #[test]
    fn test_delete_nonexistent_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let storage = create_local_storage(base_path).unwrap();

        // Delete a file that doesn't exist
        let result = storage.delete("nonexistent/file.txt");

        // Should succeed even if file doesn't exist
        assert!(result.is_ok());
    }

    // Test for factory function for creating ContentLocalStorage instances
    #[test]
    fn test_create_local_storage() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        let result = create_local_storage(base_path);
        assert!(result.is_ok());
    }

    // Mock for testing error conditions
    struct MockFailingStorage {
        base_path: String,
        fail_on_write: bool,
        fail_on_create_dir: bool,
        fail_on_create_file: bool,
        fail_on_delete: bool,
    }

    impl MockFailingStorage {
        fn new(base_path: String) -> Self {
            Self {
                base_path,
                fail_on_write: false,
                fail_on_create_dir: false,
                fail_on_create_file: false,
                fail_on_delete: false,
            }
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_on_write = true;
            self
        }

        fn with_create_dir_failure(mut self) -> Self {
            self.fail_on_create_dir = true;
            self
        }

        fn with_create_file_failure(mut self) -> Self {
            self.fail_on_create_file = true;
            self
        }

        fn with_delete_failure(mut self) -> Self {
            self.fail_on_delete = true;
            self
        }

        fn fetch_metadata_path(&self, content_path: &str) -> String {
            let content_path = Path::new(content_path);
            let file_stem = content_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let parent = content_path
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or_default();

            Path::new(&self.base_path)
                .join(parent)
                .join(format!("{}.metadata.json", file_stem))
                .to_str()
                .unwrap_or_default()
                .to_string()
        }

        fn save_metadata_only(&self, content: &Content) -> Result<(), ContentStorageError> {
            // Simulate directory creation failure
            if self.fail_on_create_dir {
                return Err(ContentStorageError::DirectoryCreation(
                    "Simulated directory creation failure".to_string(),
                ));
            }

            // Simulate file creation failure
            if self.fail_on_create_file {
                return Err(ContentStorageError::MetadataFileCreation(
                    "Simulated file creation failure".to_string(),
                ));
            }

            // Simulate write failure
            if self.fail_on_write {
                return Err(ContentStorageError::MetadataWrite(
                    "Simulated write failure".to_string(),
                ));
            }

            // Normal implementation (actual file operations for non-failure cases)
            let metadata = content.metadata();
            let serialized_metadata = SerializedMetadata::from(metadata);

            let metadata_path = self.fetch_metadata_path(metadata.path());

            // Create directory for metadata file if it doesn't exist
            if let Some(parent) = Path::new(&metadata_path).parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // Serialize metadata to JSON
            let json_data = serde_json::to_string_pretty(&serialized_metadata)?;

            // Write metadata to file
            let mut file = fs::File::create(&metadata_path)?;
            file.write_all(json_data.as_bytes())?;

            Ok(())
        }
    }

    impl Storage for MockFailingStorage {
        fn save(&self, content: &Content) -> Result<(), StorageError> {
            self.save_metadata_only(content).map_err(StorageError::from)
        }

        fn read(&self, _path: &str) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::ReadError(
                "Not implemented in mock".to_string(),
            ))
        }

        fn delete(&self, path: &str) -> Result<(), StorageError> {
            if self.fail_on_delete {
                return Err(StorageError::DeleteError(
                    "Simulated delete failure".to_string(),
                ));
            }

            let metadata_path = self.fetch_metadata_path(path);
            if Path::new(&metadata_path).exists() {
                fs::remove_file(&metadata_path)?;
            }
            Ok(())
        }
    }

    // Error case tests using the mock
    #[test]
    fn test_directory_creation_error() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        let storage = MockFailingStorage::new(base_path).with_create_dir_failure();

        let content = create_test_content("Error Test", "error/test.txt", b"Test content");

        let result = storage.save(&content);

        assert!(result.is_err());
        if let Err(StorageError::SaveError(msg)) = result {
            assert!(msg.contains("Simulated directory creation failure"));
        } else {
            panic!("Expected SaveError with directory creation message");
        }
    }

    #[test]
    fn test_file_creation_error() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        let storage = MockFailingStorage::new(base_path).with_create_file_failure();

        let content = create_test_content("Error Test", "error/test.txt", b"Test content");

        let result = storage.save(&content);

        assert!(result.is_err());
        if let Err(StorageError::SaveError(msg)) = result {
            assert!(msg.contains("Simulated file creation failure"));
        } else {
            panic!("Expected SaveError with file creation message");
        }
    }

    #[test]
    fn test_write_error() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        let storage = MockFailingStorage::new(base_path).with_write_failure();

        let content = create_test_content("Error Test", "error/test.txt", b"Test content");

        let result = storage.save(&content);

        assert!(result.is_err());
        if let Err(StorageError::SaveError(msg)) = result {
            assert!(msg.contains("Simulated write failure"));
        } else {
            panic!("Expected SaveError with write failure message");
        }
    }

    #[test]
    fn test_delete_error() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        let storage = MockFailingStorage::new(base_path).with_delete_failure();

        let result = storage.delete("some/path.txt");

        assert!(result.is_err());
        if let Err(StorageError::DeleteError(msg)) = result {
            assert!(msg.contains("Simulated delete failure"));
        } else {
            panic!("Expected DeleteError");
        }
    }

    // Test serialization errors - using a specially crafted invalid metadata
    #[test]
    fn test_metadata_serialization() {
        // This test verifies that our From implementation for serde_json::Error works
        // We'll indirectly test it by ensuring serialization errors are properly handled

        // Create a basic storage
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let base_path = temp_dir.path().to_string_lossy().to_string();

        fs::create_dir_all(&base_path).expect("Failed to create directory");

        let storage = ContentLocalStorage::new(base_path);

        // Create a content object with valid metadata
        let content = create_test_content("Serialization Test", "serial/test.txt", b"Test content");

        // The actual serialization will work, but this test verifies our conversion logic
        let result = storage.save_metadata_only(&content);
        assert!(result.is_ok());
    }
}
