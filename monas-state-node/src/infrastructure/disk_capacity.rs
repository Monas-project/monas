//! Disk capacity utilities for the state node.
//!
//! Provides cross-platform disk capacity queries with WASM fallback.

use anyhow::Result;
use std::path::Path;

/// Get disk capacity information for the given path.
///
/// Returns a tuple of (total_capacity, available_capacity) in bytes.
///
/// # Arguments
/// * `path` - The path to query disk capacity for
///
/// # Returns
/// * `Ok((total, available))` - Total and available disk space in bytes
/// * `Err(e)` - If the query fails
#[cfg(not(target_arch = "wasm32"))]
pub fn get_disk_capacity(path: &Path) -> Result<(u64, u64)> {
    use fs2::{available_space, total_space};

    let total = total_space(path)?;
    let available = available_space(path)?;
    Ok((total, available))
}

/// WASM fallback - returns placeholder values.
///
/// In WASM environments, use navigator.storage.estimate() for actual values.
#[cfg(target_arch = "wasm32")]
pub fn get_disk_capacity(_path: &Path) -> Result<(u64, u64)> {
    // WASM では navigator.storage.estimate() を使う（将来実装）
    // 現時点では 0 を返す
    Ok((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_get_disk_capacity() {
        // Use current directory for testing
        let path = PathBuf::from(".");
        let result = get_disk_capacity(&path);
        assert!(result.is_ok());

        let (total, available) = result.unwrap();
        // Total should be greater than 0
        assert!(total > 0);
        // Available should be less than or equal to total
        assert!(available <= total);
    }

    #[test]
    fn test_get_disk_capacity_root() {
        // Test with root directory
        let path = PathBuf::from("/");
        let result = get_disk_capacity(&path);
        assert!(result.is_ok());
    }
}

