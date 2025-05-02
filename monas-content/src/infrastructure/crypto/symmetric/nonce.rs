use rand::{thread_rng, RngCore};
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
        let mut rng = thread_rng();
        let mut random_bytes = [0u8; 4];
        rng.fill_bytes(&mut random_bytes);

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&timestamp.to_be_bytes());
        nonce[4..8].copy_from_slice(&(counter as u32).to_be_bytes());
        nonce[8..].copy_from_slice(&random_bytes);

        Ok(nonce)
    }
}
