//! Parsing of bootstrap peer addresses.
//!
//! A bootstrap entry is a multiaddr ending in `/p2p/<peer-id>`, e.g.
//! `/dns4/node1.example.net/tcp/9001/p2p/12D3KooW…`.
//!
//! **Prefer `/dns4/` (or `/dns6/`, `/dns`) over `/ip4/`.** libp2p resolves a
//! DNS multiaddr on every dial, so a bootstrap node that comes back on a new
//! address is still reachable. A literal `/ip4/` address is frozen at the
//! value it had when the process started: if that node is later recreated
//! elsewhere, every dial fails with `DialFailure` and nothing ever re-resolves
//! it. That is not hypothetical — it took down a 4-node deployment, where each
//! node had baked a *different*, mostly stale, address for the same bootstrap
//! peer.

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use std::str::FromStr;

/// Why a bootstrap entry could not be used.
#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapParseError {
    /// The string is not a valid multiaddr.
    Malformed,
    /// The multiaddr carries no `/p2p/<peer-id>` component, so we would not
    /// know who we are supposed to be talking to. Dialling an address without
    /// pinning the peer id would let anything on that address impersonate the
    /// bootstrap node.
    MissingPeerId,
}

/// Split a bootstrap entry into the peer id and the address to dial.
///
/// The returned address has the `/p2p/` component stripped, which is the form
/// Kademlia and the swarm address book expect.
pub fn parse_bootstrap_addr(s: &str) -> Result<(PeerId, Multiaddr), BootstrapParseError> {
    let addr = Multiaddr::from_str(s).map_err(|_| BootstrapParseError::Malformed)?;

    // The peer id is conventionally last, but accept it anywhere so that
    // circuit-relay style addresses (…/p2p/<relay>/p2p-circuit/p2p/<target>)
    // still yield the *target* peer.
    // `Multiaddr::Iter` is not double-ended, so fold to keep the last match.
    let peer_id = addr
        .iter()
        .filter_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .last()
        .ok_or(BootstrapParseError::MissingPeerId)?;

    let dial_addr: Multiaddr = addr
        .iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();

    Ok((peer_id, dial_addr))
}

/// True if the address is re-resolved on every dial (i.e. survives the peer
/// moving to a different IP). Used to warn operators about frozen addresses.
pub fn is_dns_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| {
        matches!(
            p,
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWH17aFKSgbVAJRZ7Tk8sG7khB9y5xte83LnqcnA16W2aD";

    #[test]
    fn parses_a_dns4_bootstrap_address() {
        let (peer, addr) =
            parse_bootstrap_addr(&format!("/dns4/node1.monas.local/tcp/9001/p2p/{PEER}")).unwrap();

        assert_eq!(peer.to_string(), PEER);
        // The dial address keeps the hostname — it must NOT be resolved here,
        // otherwise we are back to a frozen IP.
        assert_eq!(addr.to_string(), "/dns4/node1.monas.local/tcp/9001");
        assert!(is_dns_addr(&addr));
    }

    #[test]
    fn parses_a_literal_ip_bootstrap_address() {
        let (peer, addr) =
            parse_bootstrap_addr(&format!("/ip4/10.0.0.136/tcp/9001/p2p/{PEER}")).unwrap();

        assert_eq!(peer.to_string(), PEER);
        assert_eq!(addr.to_string(), "/ip4/10.0.0.136/tcp/9001");
        // Flagged as frozen: this is the shape that caused the outage.
        assert!(!is_dns_addr(&addr));
    }

    #[test]
    fn rejects_an_address_without_a_peer_id() {
        assert_eq!(
            parse_bootstrap_addr("/dns4/node1.monas.local/tcp/9001"),
            Err(BootstrapParseError::MissingPeerId)
        );
    }

    #[test]
    fn rejects_a_malformed_address() {
        assert_eq!(
            parse_bootstrap_addr("node1.monas.local:9001"),
            Err(BootstrapParseError::Malformed)
        );
    }

    #[test]
    fn takes_the_target_peer_from_a_circuit_relay_address() {
        let relay = "12D3KooWBRFJbcST8PdP1uafxmDGvVV9982siUffojoZQBS32fZR";
        let (peer, addr) = parse_bootstrap_addr(&format!(
            "/dns4/relay.example.net/tcp/9001/p2p/{relay}/p2p-circuit/p2p/{PEER}"
        ))
        .unwrap();

        // The peer we want to reach is the one behind the circuit, not the relay.
        assert_eq!(peer.to_string(), PEER);
        assert_eq!(
            addr.to_string(),
            "/dns4/relay.example.net/tcp/9001/p2p-circuit"
        );
    }

    #[test]
    fn dns_detection_covers_every_dns_protocol() {
        for a in [
            "/dns/example.net/tcp/9001",
            "/dns4/example.net/tcp/9001",
            "/dns6/example.net/tcp/9001",
        ] {
            assert!(is_dns_addr(&Multiaddr::from_str(a).unwrap()), "{a}");
        }
        assert!(!is_dns_addr(
            &Multiaddr::from_str("/ip4/1.2.3.4/tcp/9001").unwrap()
        ));
    }
}
