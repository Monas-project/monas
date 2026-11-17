//! Process-level network and NFS I/O counters for the periodic `metrics:` log line.
//!
//! On the hosted ECS Fargate nodes the data directory is an EFS (NFS) mount, so
//! block-device I/O (what Container Insights reports as storage) does not show
//! the node's data traffic. These counters come straight from procfs instead:
//!
//! - `/proc/net/dev`: bytes received/sent on every interface except loopback.
//!   With awsvpc networking this is the task's own network namespace.
//! - `/proc/self/mountstats`: data bytes carried by NFS READ/WRITE calls
//!   (`serverread`/`serverwrite`) for every nfs/nfs4 mount. Metadata calls
//!   (GETATTR, COMMIT, ...) and TLS overhead are not included.
//!
//! All values are cumulative since the counters were created (task start for
//! the network namespace, mount time for NFS). Readers compute rates from the
//! difference between two lines. Both files exist only on Linux; elsewhere the
//! corresponding fields are `None`.

use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetBytes {
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NfsBytes {
    pub read: u64,
    pub write: u64,
    pub mounts: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceStats {
    pub net: Option<NetBytes>,
    pub nfs: Option<NfsBytes>,
}

impl ResourceStats {
    pub fn is_empty(&self) -> bool {
        self.net.is_none() && self.nfs.is_none()
    }
}

/// `net_rx_bytes=.. net_tx_bytes=.. nfs_read_bytes=.. nfs_write_bytes=.. nfs_mounts=..`
/// A source is omitted only when its procfs file cannot be read. A readable
/// mountstats with no NFS mount still logs `nfs_*=0 nfs_mounts=0`.
impl fmt::Display for ResourceStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(n) = self.net {
            parts.push(format!("net_rx_bytes={} net_tx_bytes={}", n.rx, n.tx));
        }
        if let Some(n) = self.nfs {
            parts.push(format!(
                "nfs_read_bytes={} nfs_write_bytes={} nfs_mounts={}",
                n.read, n.write, n.mounts
            ));
        }
        f.write_str(&parts.join(" "))
    }
}

/// Reads both procfs sources. Never fails: an unreadable source is `None`.
pub async fn read() -> ResourceStats {
    let net = tokio::fs::read_to_string("/proc/net/dev")
        .await
        .ok()
        .and_then(|s| parse_net_dev(&s));
    let nfs = tokio::fs::read_to_string("/proc/self/mountstats")
        .await
        .ok()
        .map(|s| parse_mountstats(&s));
    ResourceStats { net, nfs }
}

/// Parses `/proc/net/dev`. Each interface line is `name: <8 rx fields> <8 tx fields>`;
/// field 0 is rx bytes and field 8 is tx bytes. Loopback is excluded.
pub fn parse_net_dev(content: &str) -> Option<NetBytes> {
    let mut total = NetBytes::default();
    let mut seen = false;
    for line in content.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        let fields: Vec<u64> = rest
            .split_whitespace()
            .map_while(|v| v.parse().ok())
            .collect();
        if fields.len() < 9 {
            continue;
        }
        total.rx = total.rx.saturating_add(fields[0]);
        total.tx = total.tx.saturating_add(fields[8]);
        seen = true;
    }
    seen.then_some(total)
}

/// Parses `/proc/self/mountstats`. A mount section starts with
/// `device <dev> mounted on <dir> with fstype <type> ...`; NFS sections carry a
/// `bytes:` line whose fields are normalread normalwrite directread directwrite
/// serverread serverwrite readpages writepages. serverread/serverwrite are the
/// data bytes of NFS READ/WRITE calls sent to the server, so page-cache hits
/// are not counted; metadata calls and TLS overhead are not included either.
pub fn parse_mountstats(content: &str) -> NfsBytes {
    let mut total = NfsBytes::default();
    let mut in_nfs = false;
    for line in content.lines() {
        if line.starts_with("device ") {
            in_nfs = line
                .split_whitespace()
                .skip_while(|w| *w != "fstype")
                .nth(1)
                .is_some_and(|t| t == "nfs" || t == "nfs4");
            if in_nfs {
                total.mounts += 1;
            }
            continue;
        }
        if !in_nfs {
            continue;
        }
        if let Some(rest) = line.trim_start().strip_prefix("bytes:") {
            let fields: Vec<u64> = rest
                .split_whitespace()
                .map_while(|v| v.parse().ok())
                .collect();
            if fields.len() >= 6 {
                total.read = total.read.saturating_add(fields[4]);
                total.write = total.write.saturating_add(fields[5]);
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999     100    0    0    0     0          0         0  9999999     100    0    0    0     0       0          0
  eth0:  1000      10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0
  eth1:   300       3    0    0    0     0          0         0      400       4    0    0    0     0       0          0
";

    #[test]
    fn net_dev_sums_non_loopback_interfaces() {
        assert_eq!(
            parse_net_dev(NET_DEV),
            Some(NetBytes { rx: 1300, tx: 2400 })
        );
    }

    #[test]
    fn net_dev_with_only_loopback_is_none() {
        let only_lo = NET_DEV
            .lines()
            .filter(|l| !l.contains("eth"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_net_dev(&only_lo), None);
        assert_eq!(parse_net_dev(""), None);
    }

    const MOUNTSTATS: &str = "\
device overlay mounted on / with fstype overlay
device proc mounted on /proc with fstype proc
device 127.0.0.1:/ mounted on /data with fstype nfs4 statvers=1.1
\topts:\trw,vers=4.1,rsize=1048576,wsize=1048576
\tage:\t3600
\tbytes:\t500 600 0 0 50 60 0 0
\tevents:\t1 2 3
device 127.0.0.1:/other mounted on /other with fstype nfs statvers=1.1
\tbytes:\t1 2 3 4 5 6 7 8
";

    #[test]
    fn mountstats_sums_server_bytes_of_nfs_mounts() {
        assert_eq!(
            parse_mountstats(MOUNTSTATS),
            NfsBytes {
                read: 55,
                write: 66,
                mounts: 2
            }
        );
    }

    #[test]
    fn mountstats_ignores_bytes_lines_outside_nfs_sections() {
        let content = "\
device tmpfs mounted on /tmp with fstype tmpfs
\tbytes:\t9 9 9 9 9 9 9 9
";
        assert_eq!(parse_mountstats(content), NfsBytes::default());
    }

    #[test]
    fn display_omits_missing_sources() {
        let both = ResourceStats {
            net: Some(NetBytes { rx: 1, tx: 2 }),
            nfs: Some(NfsBytes {
                read: 3,
                write: 4,
                mounts: 1,
            }),
        };
        assert_eq!(
            both.to_string(),
            "net_rx_bytes=1 net_tx_bytes=2 nfs_read_bytes=3 nfs_write_bytes=4 nfs_mounts=1"
        );
        let net_only = ResourceStats {
            net: Some(NetBytes { rx: 1, tx: 2 }),
            nfs: None,
        };
        assert_eq!(net_only.to_string(), "net_rx_bytes=1 net_tx_bytes=2");
        assert!(ResourceStats::default().is_empty());
    }
}
