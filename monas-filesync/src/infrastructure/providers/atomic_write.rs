//! Replace a file's contents so that a failure part-way leaves the old
//! contents intact.
//!
//! `fs::write` truncates the target before writing. When the target is the
//! only copy of a record (monas-content keeps one record per file and
//! overwrites it on every edit), a write that fails part-way — disk full, an
//! I/O error, a crash — leaves a truncated file and the record is lost. Here
//! the bytes go to a temporary file in the same directory, are flushed to
//! disk, and only then renamed over the target. rename within one directory
//! replaces the target in a single step on the supported platforms.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(".{name}.tmp-{}-{unique}", std::process::id()))
}

/// Writes `data` to `path`, replacing any existing file only once every byte
/// is on disk.
pub(crate) fn write_atomically(path: &Path, data: &[u8]) -> io::Result<()> {
    write_atomically_with(path, |file| file.write_all(data))
}

pub(crate) fn write_atomically_with(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let temp = temp_path_for(path);
    let result = (|| {
        let mut file = File::create(&temp)?;
        write(&mut file)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn replaces_the_contents() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("record.json");
        write_atomically(&path, b"old").unwrap();
        write_atomically(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(leftovers(dir.path()).is_empty());
    }

    /// A write that fails after some bytes were written (disk full, I/O
    /// error) keeps the old contents and leaves no temporary file behind.
    #[test]
    fn a_write_failing_part_way_keeps_the_old_contents() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("record.json");
        write_atomically(&path, b"{\"old\":true}").unwrap();

        let err = write_atomically_with(&path, |file| {
            file.write_all(b"{\"new\":")?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "disk full");

        assert_eq!(fs::read(&path).unwrap(), b"{\"old\":true}");
        assert!(leftovers(dir.path()).is_empty());
    }
}
