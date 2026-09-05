//! On-disk record of peers this node has successfully talked to.
//!
//! Configured bootstrap peers are an entry point, not a dependency: a node
//! should be able to rejoin even when every bootstrap address is down or has
//! moved. Remembering the peers we actually reached — and re-dialling them on
//! startup — removes that single point of failure, which matters more as the
//! network grows beyond nodes that a single operator runs.
//!
//! Only addresses are stored. The peer id is the durable identity (it comes
//! from `peer_key.ed25519`, which already survives restarts), while addresses
//! are disposable hints that are refreshed whenever we learn better ones.

use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Cap on remembered peers, so the file cannot grow without bound on a
/// long-lived node. Oldest-seen entries are dropped first.
const MAX_PEERS: usize = 256;

/// Cap on addresses kept per peer — a multi-homed node can announce many.
const MAX_ADDRS_PER_PEER: usize = 4;

#[derive(Debug, Default, Serialize, Deserialize)]
struct PeerStoreFile {
    /// peer id (base58) -> multiaddrs (string form).
    ///
    /// Stored as strings so the file stays readable and survives libp2p type
    /// changes; entries that no longer parse are skipped on load.
    peers: Vec<(String, Vec<String>)>,
}

/// Peers we have met, persisted to the data directory.
#[derive(Debug, Default)]
pub struct PeerStore {
    peers: HashMap<PeerId, Vec<Multiaddr>>,
    /// Insertion order, oldest first, used to enforce `MAX_PEERS`.
    order: Vec<PeerId>,
}

impl PeerStore {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("known_peers.json")
    }

    /// Load the store, returning an empty one when the file is missing or
    /// unreadable. A corrupt cache must never stop the node from starting —
    /// it is a hint, and bootstrap addresses remain as a fallback.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path(data_dir);
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::default();
        };
        let parsed: PeerStoreFile = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "Ignoring unreadable peer store at {}: {}",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };

        let mut store = Self::default();
        for (peer, addrs) in parsed.peers {
            let Ok(peer_id) = PeerId::from_str(&peer) else {
                continue;
            };
            let addrs: Vec<Multiaddr> = addrs
                .iter()
                .filter_map(|a| Multiaddr::from_str(a).ok())
                .collect();
            if !addrs.is_empty() {
                store.order.push(peer_id);
                store.peers.insert(peer_id, addrs);
            }
        }
        store
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let file = PeerStoreFile {
            peers: self
                .order
                .iter()
                .filter_map(|p| {
                    self.peers
                        .get(p)
                        .map(|a| (p.to_string(), a.iter().map(|m| m.to_string()).collect()))
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file).context("serialize peer store")?;

        // Write via a temporary file so a crash mid-write cannot leave a
        // truncated store behind.
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    }

    /// Record an address for a peer. Returns true if this changed anything,
    /// so callers can avoid writing the file on every duplicate observation.
    pub fn record(&mut self, peer: PeerId, addr: Multiaddr) -> bool {
        // Loopback and link-local addresses are useless to a *remote* node and
        // actively misleading after a restart elsewhere.
        if !is_shareable(&addr) {
            return false;
        }

        let entry = self.peers.entry(peer).or_insert_with(|| {
            self.order.push(peer);
            Vec::new()
        });
        if entry.contains(&addr) {
            return false;
        }
        entry.push(addr);
        if entry.len() > MAX_ADDRS_PER_PEER {
            entry.remove(0);
        }

        // Evict the oldest peer if we are over the cap.
        if self.order.len() > MAX_PEERS {
            let oldest = self.order.remove(0);
            self.peers.remove(&oldest);
        }
        true
    }

    /// Replace everything we know about a peer with the addresses it just
    /// announced. Returns true if this changed anything.
    ///
    /// `record` only learns the address *we* dialled, so a peer that connected
    /// to us — which is how every member reaches the bootstrap node, and how
    /// any node reaches a peer that has just moved — never updated its entry.
    /// After an ECS restart gives a peer a new IP, the store kept the old one
    /// and `maintain_connectivity` re-dialled it forever. Identify carries the
    /// peer's own listen addresses, which is the freshest information there
    /// is; it wins over anything remembered.
    pub fn replace(&mut self, peer: PeerId, addrs: impl IntoIterator<Item = Multiaddr>) -> bool {
        let mut fresh: Vec<Multiaddr> = Vec::new();
        for a in addrs {
            if is_shareable(&a) && !fresh.contains(&a) {
                fresh.push(a);
            }
        }
        // A peer that announces nothing usable tells us nothing; keep what we had.
        if fresh.is_empty() {
            return false;
        }
        fresh.truncate(MAX_ADDRS_PER_PEER);

        if self.peers.get(&peer) == Some(&fresh) {
            return false;
        }
        if !self.peers.contains_key(&peer) {
            self.order.push(peer);
        }
        self.peers.insert(peer, fresh);
        if self.order.len() > MAX_PEERS {
            let oldest = self.order.remove(0);
            self.peers.remove(&oldest);
        }
        true
    }

    pub fn addrs(&self, peer: &PeerId) -> Option<&Vec<Multiaddr>> {
        self.peers.get(peer)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Vec<Multiaddr>)> {
        self.peers.iter()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Whether an address is worth telling a future self about.
///
/// Rejects addresses that cannot get us back to the peer from a fresh process:
/// loopback, link-local and unspecified addresses, and relayed
/// (`/p2p-circuit`) addresses — a circuit is only valid while that particular
/// relay connection lives, so persisting one just means re-dialling a dead
/// path every maintenance tick.
fn is_shareable(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    !addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback() || ip.is_link_local() || ip.is_unspecified(),
        Protocol::Ip6(ip) => {
            ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        Protocol::P2pCircuit => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        libp2p::identity::Keypair::ed25519_from_bytes(bytes)
            .unwrap()
            .public()
            .to_peer_id()
    }

    fn addr(s: &str) -> Multiaddr {
        Multiaddr::from_str(s).unwrap()
    }

    /// The production failure: a peer restarts on a new IP, connects to us,
    /// and Identify announces the new address. The stale one must be gone —
    /// with it still first in the list, every maintenance tick re-dialled a
    /// dead address.
    #[test]
    fn identify_replaces_a_stale_address_with_the_announced_one() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(store.record(p, addr("/ip4/10.0.1.196/tcp/9001")));

        // Identify announces the peer's own listen addresses: the new private
        // IP plus the loopback and link-local ones every node also binds.
        assert!(store.replace(
            p,
            [
                addr("/ip4/127.0.0.1/tcp/9001"),
                addr("/ip4/169.254.172.2/tcp/9001"),
                addr("/ip4/10.0.1.111/tcp/9001"),
            ]
        ));
        assert_eq!(
            store.addrs(&p).unwrap(),
            &[addr("/ip4/10.0.1.111/tcp/9001")]
        );
    }

    #[test]
    fn replace_with_the_same_addresses_is_a_no_op() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(store.replace(p, [addr("/ip4/10.0.1.111/tcp/9001")]));
        assert!(!store.replace(p, [addr("/ip4/10.0.1.111/tcp/9001")]));
        assert_eq!(store.len(), 1);
    }

    /// A peer that announces only loopback or link-local addresses has told
    /// us nothing we can use from a fresh process; what we had stays.
    #[test]
    fn replace_with_nothing_shareable_keeps_the_old_entry() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(store.record(p, addr("/ip4/10.0.1.196/tcp/9001")));
        assert!(!store.replace(
            p,
            [
                addr("/ip4/127.0.0.1/tcp/9001"),
                addr("/ip4/169.254.1.1/tcp/9001")
            ]
        ));
        assert_eq!(
            store.addrs(&p).unwrap(),
            &[addr("/ip4/10.0.1.196/tcp/9001")]
        );
    }

    #[test]
    fn replace_caps_addresses_per_peer() {
        let mut store = PeerStore::default();
        let p = peer(1);
        let many: Vec<Multiaddr> = (0..10)
            .map(|i| addr(&format!("/ip4/10.0.2.{i}/tcp/9001")))
            .collect();
        assert!(store.replace(p, many));
        assert_eq!(store.addrs(&p).unwrap().len(), MAX_ADDRS_PER_PEER);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(store.record(p, addr("/ip4/10.0.1.60/tcp/9001")));
        store.save(dir.path()).unwrap();

        let loaded = PeerStore::load(dir.path());
        assert_eq!(
            loaded.addrs(&p).map(|v| v.as_slice()),
            Some([addr("/ip4/10.0.1.60/tcp/9001")].as_slice())
        );
    }

    #[test]
    fn recording_the_same_address_twice_is_a_no_op() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(store.record(p, addr("/ip4/10.0.1.60/tcp/9001")));
        assert!(!store.record(p, addr("/ip4/10.0.1.60/tcp/9001")));
        assert_eq!(store.addrs(&p).unwrap().len(), 1);
    }

    /// Remembering 127.0.0.1 for a peer would be worse than remembering
    /// nothing: on the next start we would dial ourselves.
    #[test]
    fn skips_loopback_and_unspecified_addresses() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(!store.record(p, addr("/ip4/127.0.0.1/tcp/9001")));
        assert!(!store.record(p, addr("/ip4/0.0.0.0/tcp/9001")));
        assert!(!store.record(p, addr("/ip6/::1/tcp/9001")));
        assert!(store.is_empty());
    }

    /// IPv6 link-local is as useless as the IPv4 kind; the two arms used to
    /// disagree, so `fe80::/10` was persisted while `169.254.0.0/16` was not.
    #[test]
    fn skips_ipv6_link_local_addresses() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(!store.record(p, addr("/ip6/fe80::1/tcp/9001")));
        assert!(!store.record(p, addr("/ip4/169.254.1.1/tcp/9001")));
        assert!(store.is_empty());
    }

    /// A relayed address is only good while that relay connection lives.
    /// Persisting one means re-dialling a dead circuit on every tick — the
    /// same "frozen address" class this store exists to escape.
    #[test]
    fn skips_relayed_circuit_addresses() {
        let mut store = PeerStore::default();
        let p = peer(1);
        assert!(!store.record(
            p,
            addr("/ip4/10.0.1.60/tcp/9001/p2p/12D3KooWH17aFKSgbVAJRZ7Tk8sG7khB9y5xte83LnqcnA16W2aD/p2p-circuit")
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn keeps_a_bounded_number_of_addresses_per_peer() {
        let mut store = PeerStore::default();
        let p = peer(1);
        for i in 0..(MAX_ADDRS_PER_PEER + 3) {
            store.record(p, addr(&format!("/ip4/10.0.0.{i}/tcp/9001")));
        }
        assert_eq!(store.addrs(&p).unwrap().len(), MAX_ADDRS_PER_PEER);
        // The most recent observation survived; the oldest was dropped.
        assert!(store.addrs(&p).unwrap().contains(&addr(&format!(
            "/ip4/10.0.0.{}/tcp/9001",
            MAX_ADDRS_PER_PEER + 2
        ))));
        assert!(!store
            .addrs(&p)
            .unwrap()
            .contains(&addr("/ip4/10.0.0.0/tcp/9001")));
    }

    #[test]
    fn a_corrupt_file_loads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(PeerStore::path(dir.path()), b"{not json").unwrap();
        assert!(PeerStore::load(dir.path()).is_empty());
    }

    #[test]
    fn a_missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(PeerStore::load(dir.path()).is_empty());
    }

    /// Entries written by a future version (or a different libp2p) must not
    /// take the whole store down with them.
    #[test]
    fn unparseable_entries_are_skipped_individually() {
        let dir = tempfile::tempdir().unwrap();
        let good = peer(2).to_string();
        std::fs::write(
            PeerStore::path(dir.path()),
            format!(
                r#"{{"peers":[["not-a-peer-id",["/ip4/10.0.0.1/tcp/1"]],["{good}",["/ip4/10.0.0.2/tcp/2","!!bad"]]]}}"#
            ),
        )
        .unwrap();

        let loaded = PeerStore::load(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.addrs(&peer(2)).map(|v| v.as_slice()),
            Some([addr("/ip4/10.0.0.2/tcp/2")].as_slice())
        );
    }
}
