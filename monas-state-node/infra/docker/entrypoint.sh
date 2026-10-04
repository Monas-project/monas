#!/bin/bash
set -eu

DATA_DIR="${DATA_DIR:-/data}"
HTTP_LISTEN="${HTTP_LISTEN:-0.0.0.0:8080}"
P2P_PORT="${P2P_PORT:-9001}"
LOG_LEVEL="${LOG_LEVEL:-info}"
NODE_ROLE="${NODE_ROLE:-member}"
BOOTSTRAP_ADDR="${BOOTSTRAP_ADDR:-}"
BOOTSTRAP_DNS="${BOOTSTRAP_DNS:-}"
BOOTSTRAP_PEER_ID="${BOOTSTRAP_PEER_ID:-}"
DISABLE_MDNS="${DISABLE_MDNS:-}"
DISABLE_NAT_TRAVERSAL="${DISABLE_NAT_TRAVERSAL:-}"
RELAY_SERVICE="${RELAY_SERVICE:-}"
EXTERNAL_ADDR="${EXTERNAL_ADDR:-}"

ARGS=(
    --data-dir "$DATA_DIR"
    --listen "$HTTP_LISTEN"
    --p2p-port "$P2P_PORT"
    --log-level "$LOG_LEVEL"
)

# mDNS only reaches a broadcast domain, so it never works in a VPC. It does
# work locally, well enough to hide a broken bootstrap/Kademlia path — which is
# how a local run "passed" while the deployment could not reconverge. Set
# DISABLE_MDNS=true to run a local cluster under production-like conditions.
case "$DISABLE_MDNS" in
    1|true|TRUE|yes|YES) ARGS+=(--disable-mdns) ;;
esac

# Externally reachable addresses to advertise (comma-separated multiaddrs).
if [ -n "$EXTERNAL_ADDR" ]; then
    IFS=',' read -ra EXT_ADDRS <<< "$EXTERNAL_ADDR"
    for a in "${EXT_ADDRS[@]}"; do
        a="$(echo "$a" | tr -d '[:space:]')"
        [ -n "$a" ] && ARGS+=(--external-address "$a")
    done
fi

# NAT traversal is on by default; this is the switch that turns it off
# without a code change.
if [ -n "$DISABLE_NAT_TRAVERSAL" ]; then
    ARGS+=(--disable-nat-traversal)
fi

# Acting as a relay for other peers is opt-in: it carries traffic for nodes
# we know nothing about. Requires EXTERNAL_ADDR.
if [ -n "$RELAY_SERVICE" ]; then
    ARGS+=(--relay-service)
fi

# Bootstrap addresses.
#
# BOOTSTRAP_ADDR accepts a comma-separated list of full multiaddrs, so a node
# can be given several entry points and still join when one of them is down.
#
# BOOTSTRAP_DNS is turned into a `/dns4/` multiaddr rather than being resolved
# to an IP here. Resolving once at startup baked a fixed IP into the process:
# when the bootstrap node was recreated with a new address, every other node
# kept dialling the old one forever (DialFailure), and nothing re-resolved it.
# libp2p resolves `/dns4/` on every dial, so an address change now heals by
# itself. The transport wraps TCP in a DNS resolver (see transport.rs).
if [ "$NODE_ROLE" != "bootstrap" ]; then
    if [ -n "$BOOTSTRAP_ADDR" ]; then
        IFS=',' read -ra ADDRS <<< "$BOOTSTRAP_ADDR"
        for a in "${ADDRS[@]}"; do
            a="$(echo "$a" | tr -d '[:space:]')"
            [ -n "$a" ] && ARGS+=(--bootstrap "$a")
        done
    elif [ -n "$BOOTSTRAP_DNS" ] && [ -n "$BOOTSTRAP_PEER_ID" ]; then
        IFS=',' read -ra HOSTS <<< "$BOOTSTRAP_DNS"
        for h in "${HOSTS[@]}"; do
            h="$(echo "$h" | tr -d '[:space:]')"
            [ -z "$h" ] && continue
            echo "Bootstrap peer: /dns4/${h}/tcp/${P2P_PORT}/p2p/${BOOTSTRAP_PEER_ID}"
            ARGS+=(--bootstrap "/dns4/${h}/tcp/${P2P_PORT}/p2p/${BOOTSTRAP_PEER_ID}")
        done
    fi
fi

exec state-node "${ARGS[@]}"
