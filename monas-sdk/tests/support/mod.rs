use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

pub struct TestProcessLock {
    path: PathBuf,
}

impl Drop for TestProcessLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn acquire_test_lock() -> TestProcessLock {
    let path = std::env::temp_dir().join("monas-sdk-integration-test.lock");
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => return TestProcessLock { path },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for test lock at {}", path.display());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("failed to create test lock {}: {e}", path.display()),
        }
    }
}

#[allow(dead_code)]
pub fn cleanup_content_artifacts() {
    for dir in ["content", "monas-sdk/content"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}
