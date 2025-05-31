use crate::domain::content::Content;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum StorageError {
    SaveError(String),
    ReadError(String),
    DeleteError(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::SaveError(msg) => write!(f, "Save error: {}", msg),
            StorageError::ReadError(msg) => write!(f, "Read error: {}", msg),
            StorageError::DeleteError(msg) => write!(f, "Delete error: {}", msg),
        }
    }
}

impl Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::SaveError(err.to_string())
    }
}

// Storage trait: Interface for saving, reading, and deleting content
pub trait Storage {
    // Save content to persistent storage
    // The data to be saved is expected to be the encrypted_content in the Content struct
    fn save(&self, content: &Content) -> Result<(), StorageError>;

    // Read (encrypted) content data from the specified path
    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError>;

    // Delete content data from storage at the specified path
    fn delete(&self, path: &str) -> Result<(), StorageError>;
}
