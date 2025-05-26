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
/// * The `load` method always returns an error (as content data is not stored)
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
