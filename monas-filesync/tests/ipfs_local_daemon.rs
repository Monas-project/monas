#![cfg(feature = "cloud-connectivity")]

use std::{env, time::SystemTime};

use cid::Cid;
use monas_filesync::infrastructure::providers::ipfs::IpfsProvider;
use monas_filesync::{AuthSession, StorageProvider};
use multihash::Multihash;
use sha2::{Digest, Sha256};

fn raw_block_cid_v1_sha2_256(data: &[u8]) -> String {
    // IPFS `block put --format=raw --mhtype=sha2-256` と同じCIDを生成する。
    // multicodec: raw (0x55)
    // multihash code: sha2-256 (0x12)
    let digest = Sha256::digest(data);
    let mh = Multihash::<64>::wrap(0x12, digest.as_slice()).expect("digest size must fit");
    Cid::new_v1(0x55, mh).to_string()
}

#[tokio::test]
#[ignore]
async fn ipfs_local_daemon_roundtrip() {
    let api_base = env::var("IPFS_API_BASE").unwrap_or_else(|_| "http://127.0.0.1:5001".into());
    let provider = IpfsProvider::new(api_base);
    let auth = AuthSession {
        access_token: env::var("IPFS_API_TOKEN").unwrap_or_default(),
    };

    let data = b"monas-filesync ipfs roundtrip test";
    let cid = raw_block_cid_v1_sha2_256(data);
    let uri = format!("ipfs://{cid}");

    provider.save(&auth, &uri, data).await.unwrap();
    let fetched = provider.fetch(&auth, &uri).await.unwrap();
    let (size, mtime) = provider.size_and_mtime(&auth, &uri).await.unwrap();

    assert_eq!(fetched, data);
    assert_eq!(size, data.len() as u64);
    assert_eq!(mtime, SystemTime::UNIX_EPOCH);
}
