//! Transport layer configuration for libp2p.
//!
//! Provides transport builders for server-to-server communication:
//! - TCP + QUIC + WebRTC with Noise encryption and Yamux multiplexing
//!
//! WebRTC is included for future browser-to-server communication support.

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    dns,
    identity::Keypair,
    noise, quic, tcp, yamux, PeerId, Transport,
};

/// Build the transport layer for native platforms.
///
/// Combines TCP, QUIC, and WebRTC transports:
/// - TCP: Traditional transport with Noise + Yamux
/// - QUIC: Modern, efficient transport with built-in encryption
/// - WebRTC: Required for browser communication (future)
pub fn build_transport(keypair: &Keypair) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    build_transport_inner(keypair, None)
}

/// Build the transport with circuit-relay dialling folded in.
///
/// The relay client is a *transport*, not just a behaviour: dialling
/// `/…/p2p-circuit/p2p/<peer>` has to be handled at the transport layer, and
/// the transport half can only be obtained together with the behaviour half
/// from `relay::client::new`. So a node that wants to reach peers through a
/// relay must build its transport with this function and register the matching
/// behaviour — the two halves are useless apart.
pub fn build_transport_with_relay(
    keypair: &Keypair,
    relay_transport: libp2p::relay::client::Transport,
) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    build_transport_inner(keypair, Some(relay_transport))
}

fn build_transport_inner(
    keypair: &Keypair,
    relay_transport: Option<libp2p::relay::client::Transport>,
) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    use rand::rngs::OsRng;

    // TCP transport with DNS resolution
    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let dns_tcp = dns::tokio::Transport::system(tcp_transport)?;

    // Apply Noise encryption and Yamux multiplexing to TCP
    let tcp_upgraded = dns_tcp
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(keypair)?)
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20));

    // QUIC transport (includes its own encryption)
    let quic_transport = quic::tokio::Transport::new(quic::Config::new(keypair));

    // WebRTC transport for browser communication
    let webrtc_transport = libp2p_webrtc::tokio::Transport::new(
        keypair.clone(),
        libp2p_webrtc::tokio::Certificate::generate(&mut OsRng)?,
    );

    // Combine all transports
    let transport = tcp_upgraded
        .or_transport(quic_transport)
        .map(|either, _| match either {
            futures::future::Either::Left((peer_id, muxer)) => {
                (peer_id, StreamMuxerBox::new(muxer))
            }
            futures::future::Either::Right((peer_id, muxer)) => {
                (peer_id, StreamMuxerBox::new(muxer))
            }
        })
        .or_transport(webrtc_transport)
        .map(|either, _| match either {
            futures::future::Either::Left((peer_id, muxer)) => (peer_id, muxer),
            futures::future::Either::Right((peer_id, muxer)) => {
                (peer_id, StreamMuxerBox::new(muxer))
            }
        });

    // Relay connections still need to be authenticated and multiplexed: the
    // circuit only carries bytes, and the relay itself must not be able to
    // read or tamper with what flows through it. Noise runs end-to-end between
    // the two clients, so a relay sees ciphertext only.
    let transport = match relay_transport {
        Some(relay) => {
            let relay_upgraded = relay
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::Config::new(keypair)?)
                .multiplex(yamux::Config::default())
                .timeout(std::time::Duration::from_secs(20));
            transport
                .or_transport(relay_upgraded)
                .map(|either, _| match either {
                    futures::future::Either::Left((peer_id, muxer)) => (peer_id, muxer),
                    futures::future::Either::Right((peer_id, muxer)) => {
                        (peer_id, StreamMuxerBox::new(muxer))
                    }
                })
                .boxed()
        }
        None => transport.boxed(),
    };

    Ok(transport)
}

/// Build a TCP-only transport for testing or simpler setups.
pub fn build_tcp_transport(keypair: &Keypair) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let dns_tcp = dns::tokio::Transport::system(tcp_transport)?;

    let transport = dns_tcp
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(keypair)?)
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();

    Ok(transport)
}

/// Build a QUIC-only transport.
pub fn build_quic_transport(keypair: &Keypair) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let quic_transport = quic::tokio::Transport::new(quic::Config::new(keypair));
    let transport = quic_transport
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();
    Ok(transport)
}

/// Build a WebRTC-only transport for browser communication (future).
pub fn build_webrtc_transport(
    keypair: &Keypair,
) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    use rand::rngs::OsRng;

    let webrtc_transport = libp2p_webrtc::tokio::Transport::new(
        keypair.clone(),
        libp2p_webrtc::tokio::Certificate::generate(&mut OsRng)?,
    );
    let transport = webrtc_transport
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();
    Ok(transport)
}

// ============================================================
// WASM Support (Future)
// ============================================================
// The following function is prepared for future WASM/browser support.
// To enable, uncomment and add the required WASM dependencies.
//
// #[cfg(target_arch = "wasm32")]
// pub fn build_transport(
//     keypair: &Keypair,
// ) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
//     use libp2p::webrtc_websys;
//     let config = webrtc_websys::Config::new(keypair);
//     let transport = webrtc_websys::Transport::new(config);
//     Ok(transport.boxed())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tcp_transport() {
        let keypair = Keypair::generate_ed25519();
        let result = build_tcp_transport(&keypair);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_quic_transport() {
        let keypair = Keypair::generate_ed25519();
        let result = build_quic_transport(&keypair);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_webrtc_transport() {
        let keypair = Keypair::generate_ed25519();
        let result = build_webrtc_transport(&keypair);
        assert!(result.is_ok());
    }
}
