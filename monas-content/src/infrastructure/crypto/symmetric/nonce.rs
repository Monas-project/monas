use rand::{rng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum NonceError {
    CounterOverflow,
    SystemTimeError,
}

#[derive(Debug)]
pub struct NonceGenerator {
    counter: AtomicU64,
    // TODO: 今後カウンターの永続化の実装を検討する
    // storage: Option<Box<dyn CounterStorage>>, // カウンター値を永続化するためのストレージインターフェース
    // last_saved_counter: AtomicU64, // 最後に保存したカウンター値
    // save_interval: Duration, // ウンター値を保存する間隔
}

impl Default for NonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    pub fn generate(&self) -> Result<[u8; 12], NonceError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NonceError::SystemTimeError)?
            .as_nanos() as u32;

        let counter = self.counter.load(Ordering::Relaxed);
        // オーバーフローをチェック
        if counter >= u32::MAX as u64 {
            return Err(NonceError::CounterOverflow);
        }

        let counter = self.counter.fetch_add(1, Ordering::SeqCst);

        // TODO: ランダムネスの保証
        let mut rng = rng();
        let mut random_bytes = [0u8; 4];
        rng.fill_bytes(&mut random_bytes);

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&timestamp.to_be_bytes());
        nonce[4..8].copy_from_slice(&(counter as u32).to_be_bytes());
        nonce[8..].copy_from_slice(&random_bytes);

        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_generate_unique_nonce() {
        let generator = NonceGenerator::new();
        let mut nonces = HashSet::new();

        for i in 0..1000 {
            let nonce = generator.generate().unwrap();
            assert!(
                nonces.insert(nonce),
                "Duplicate nonce detected at iteration {}",
                i + 1
            );

            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn test_nonce_format() {
        let generator = NonceGenerator::new();
        let nonce = generator.generate().unwrap();

        let timestamp = u32::from_be_bytes(nonce[..4].try_into().unwrap());
        assert!(timestamp > 0);

        let counter = u32::from_be_bytes(nonce[4..8].try_into().unwrap());
        assert_eq!(counter, 0);

        let random_bytes = &nonce[8..];
        assert_ne!(random_bytes, &[0u8; 4]);
    }

    #[test]
    fn test_thread_safety() {
        let generator = std::sync::Arc::new(NonceGenerator::new());
        let all_nonces = std::sync::Arc::new(std::sync::Mutex::new(HashSet::new()));
        let mut handles = vec![];

        for _ in 0..10 {
            let generator = generator.clone();
            let all_nonces = all_nonces.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let nonce = generator.generate().unwrap();
                    let mut all_nonces = all_nonces.lock().unwrap();
                    assert!(all_nonces.insert(nonce), "Duplicate nonce detected");
                }
            }));
        }
    }

    #[test]
    fn test_counter_overflow() {
        let generator = NonceGenerator::new();

        unsafe {
            let counter_ptr = &generator.counter as *const AtomicU64 as *mut AtomicU64;
            (*counter_ptr).store(u32::MAX as u64 - 1, Ordering::SeqCst);
        }

        // 1回目のNonceGenerator::generate()でcounterをu32::MAXとする
        let _ = generator.generate().unwrap();

        assert!(matches!(
            generator.generate(),
            Err(NonceError::CounterOverflow)
        ));
    }
}
