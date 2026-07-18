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

/// crsl-lib の `Node<ContentPayload, ContentMetadata>` と同じ CBOR 形状になる
/// ミラー(フィールド名・順序を一致させる)。ミラーの正しさは monas-content の
/// node_verification にある crsl-lib パリティテストで担保されている。
/// State Node の read 応答(Node CBOR)をテストで模擬生成するために使う。
#[allow(dead_code)]
pub mod node_mirror {
    use cid::Cid;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestPayload {
        data: Vec<u8>,
        access_policy: Option<()>,
    }
    #[derive(Serialize)]
    struct TestMetadata {
        policy_type: Option<String>,
    }
    #[derive(Serialize)]
    struct TestNode {
        payload: TestPayload,
        parents: Vec<Cid>,
        genesis: Option<Cid>,
        timestamp: u64,
        metadata: TestMetadata,
    }

    pub fn make_node_bytes(
        ciphertext: &[u8],
        parents: Vec<&str>,
        genesis: Option<&str>,
    ) -> Vec<u8> {
        let node = TestNode {
            payload: TestPayload {
                data: ciphertext.to_vec(),
                access_policy: None,
            },
            parents: parents.iter().map(|p| p.parse().unwrap()).collect(),
            genesis: genesis.map(|g| g.parse().unwrap()),
            timestamp: 42,
            metadata: TestMetadata { policy_type: None },
        };
        serde_cbor::to_vec(&node).unwrap()
    }
}
