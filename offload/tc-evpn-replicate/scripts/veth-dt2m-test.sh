#!/usr/bin/env bash
#
# End-to-end load test for the EVPN BUM replication TC/clsact leaf `End.DT2M`
# datapath (RFC 9524 SR replication segment): decap + native bridge flood.
#
# What it proves: a leaf PE receives a replicated BUM copy addressed to its
# local End.DT2M SID — outer IPv6 (reduced SRv6 encap, Next Header = Ethernet)
# wrapping the inner Ethernet frame. The stock kernel has no SID behavior that
# strips that and floods the inner frame into the L2 domain. This datapath does:
# it pops the outer IPv6, restores the inner Ethernet frame, and redirects it
# into a bridge port's ingress so the bridge floods it to every local
# attachment circuit.
#
# Topology (root ns unless noted):
#
#   ns evpndt2m-ns        root ns
#   ┌──────────────┐      ┌──────────────────────────────────────────────────┐
#   │ evpndl1      │──────│ evpndl0  [clsact ingress: tc_evpn_replicate]      │
#   │ send 1 frame │ veth │   match DT2M SID → strip outer IPv6 → redirect    │
#   │ dst=DT2M SID │      │   inner frame to evpninj0 ingress (a bridge port) │
#   └──────────────┘      │                          │                        │
#                         │   brevpn (bridge) ◄───────┘ floods to other ports  │
#                         │     ├─ evpninj0 (injection port, redirect target)  │
#                         │     └─ evpnap0 ──veth── evpnap1  [capture inbound] │
#                         └──────────────────────────────────────────────────┘
#
# The injection port matters: redirecting a decapped frame to a bridge *port's*
# ingress makes the bridge flood it to the other ports (split-horizon skips the
# injection port); redirecting to the bridge *master* would just send it up the
# host stack, not flood. The inner frame is a broadcast ARP so the bridge floods
# it unconditionally; we capture it leaving the access port (evpnap0 → evpnap1).
#
# Run as root:
#   sudo bash offload/tc-evpn-replicate/scripts/veth-dt2m-test.sh
set -u

NS=evpndt2m-ns
DL0=evpndl0          # underlay root-ns end — classifier attaches here
DL1=evpndl1         # underlay namespace end — the sender
BR=brevpn            # leaf bridge
INJ0=evpninj0        # bridge injection port (redirect target) ...
INJ1=evpninj1        # ... and its peer (just needs carrier)
AP0=evpnap0          # bridge access port ...
AP1=evpnap1          # ... and its peer, where flooded BUM is captured

VNI=100
DT2M_SID="2001:db8:beef::2"   # this leaf's End.DT2M SID (outer DA we send to)
SRC="2001:db8:0:fe::1"        # arbitrary ingress source
ARP_SENDER_IP=10.0.0.1
ARP_TARGET_IP=10.0.0.2
INNER_SRC_MAC=02:00:00:00:0a:01

RUNTIME=12        # seconds the loader stays attached (stdin held open)
CAP_SECS=7        # tcpdump capture window

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../target/release/tc-evpn-replicate"
LOG=/tmp/evpndt2m_loader.log
CAPOUT=/tmp/evpndt2m_tcpdump.out
CAPERR=/tmp/evpndt2m_tcpdump.err

LOADER_PID=""
cleanup() {
    [ -n "$LOADER_PID" ] && kill "$LOADER_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS" 2>/dev/null
    ip link del "$DL0" 2>/dev/null
    ip link del "$INJ0" 2>/dev/null
    ip link del "$AP0" 2>/dev/null
    ip link del "$BR" 2>/dev/null
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root (sudo)"; exit 1; fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found: $BIN"
    echo "       build it first:  (cd $SCRIPT_DIR/.. && cargo build --release)"
    exit 1
fi

echo "== 1. fresh bridge + veths + namespace =="
cleanup 2>/dev/null   # clean slate
ip netns add "$NS"
# Underlay veth: namespace sender <-> root-ns classifier.
ip link add "$DL0" type veth peer name "$DL1"
ip link set "$DL1" netns "$NS"
ip link set "$DL0" up
ip netns exec "$NS" ip link set "$DL1" up
ip netns exec "$NS" ip link set lo up
# Disable GRO/GSO/TSO on the underlay path: GRO on the receive side can present
# the skb as GSO, which makes bpf_skb_adjust_room shrink return -ENOTSUPP.
ethtool -K "$DL0" gro off gso off tso off lro off 2>/dev/null || true
ip netns exec "$NS" ethtool -K "$DL1" gro off gso off tso off lro off 2>/dev/null || true
# Bridge with STP off (ports forward immediately).
ip link add "$BR" type bridge
ip link set "$BR" type bridge stp_state 0
ip link set "$BR" up
# Injection + access ports (both veth pairs; both ends up so the enslaved end
# has carrier and the bridge forwards on it).
ip link add "$INJ0" type veth peer name "$INJ1"
ip link add "$AP0" type veth peer name "$AP1"
ip link set "$INJ0" master "$BR"; ip link set "$INJ0" up; ip link set "$INJ1" up
ip link set "$AP0" master "$BR";  ip link set "$AP0" up;  ip link set "$AP1" up
MAC_DST=$(cat "/sys/class/net/$DL0/address")
MAC_SRC=$(ip netns exec "$NS" cat "/sys/class/net/$DL1/address")
echo "   underlay: $DL0 ($MAC_DST) <-> $NS:$DL1 ($MAC_SRC)"
echo "   bridge $BR ports: $INJ0 (inject), $AP0 (access; capture on $AP1)"

echo "== 2. attach leaf on $DL0 (clsact ingress), flood -> bridge port $INJ0 =="
( printf 'leaf-add %s %s\n' "$VNI" "$DT2M_SID"; sleep "$RUNTIME" ) \
    | RUST_LOG=info "$BIN" -i "$DL0" -d ingress -b "$INJ0" >"$LOG" 2>&1 &
LOADER_PID=$!
sleep 2
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "ERROR: loader exited early:"; cat "$LOG"; exit 1
fi
grep -iE 'attached|leaf-add' "$LOG" | sed 's/^/   /'

echo "== 3. capture inbound on $AP1, then send 3 encapsulated BUM frames =="
ip netns exec "$NS" true 2>/dev/null   # noop to keep ns warm
timeout "$CAP_SECS" tcpdump -lnei "$AP1" -Q in >"$CAPOUT" 2>"$CAPERR" &
TCPDUMP_PID=$!
sleep 1
MAC_DST="$MAC_DST" MAC_SRC="$MAC_SRC" SRC="$SRC" DST="$DT2M_SID" IFACE="$DL1" \
INNER_SRC_MAC="$INNER_SRC_MAC" ARP_SENDER_IP="$ARP_SENDER_IP" ARP_TARGET_IP="$ARP_TARGET_IP" \
    ip netns exec "$NS" python3 - <<'PY'
import os, socket, time

def mac(s): return bytes(int(b, 16) for b in s.split(":"))
def ip6(s): return socket.inet_pton(socket.AF_INET6, s)
def ip4(s): return socket.inet_aton(s)

iface = os.environ["IFACE"]
# Inner Ethernet BUM frame: broadcast ARP request (floods unconditionally).
inner_smac = mac(os.environ["INNER_SRC_MAC"])
inner_eth = b"\xff\xff\xff\xff\xff\xff" + inner_smac + b"\x08\x06"   # dst=bcast, ARP
arp = (b"\x00\x01\x08\x00\x06\x04\x00\x01"                          # htype/ptype/hlen/plen/op=req
       + inner_smac + ip4(os.environ["ARP_SENDER_IP"])
       + b"\x00\x00\x00\x00\x00\x00" + ip4(os.environ["ARP_TARGET_IP"]))
# Pad to the 60-byte Ethernet minimum (14 header + 46 payload), as a real NIC
# would: the inner BUM frame is a full Ethernet frame, which also keeps its
# length above the kernel's bpf_skb_change_tail minimum so decap can trim cleanly.
arp = arp.ljust(46, b"\x00")
inner = inner_eth + arp

# Outer: link Ethernet + IPv6 (reduced SRv6 encap, Next Header = Ethernet/143).
link_eth = mac(os.environ["MAC_DST"]) + mac(os.environ["MAC_SRC"]) + b"\x86\xdd"
ipv6 = (b"\x60\x00\x00\x00"
        + len(inner).to_bytes(2, "big")
        + b"\x8f" + b"\x40"        # next_header=143 (Ethernet), hop_limit=64
        + ip6(os.environ["SRC"]) + ip6(os.environ["DST"]))
frame = link_eth + ipv6 + inner

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
for _ in range(3):
    s.send(frame); time.sleep(0.2)
print("   sent 3x encapsulated BUM (inner ARP) -> %s (End.DT2M SID)" % os.environ["DST"])
PY
wait "$TCPDUMP_PID" 2>/dev/null

echo "== 4. result =="
echo "-- loader log --"; grep -iE 'attached|leaf-add|exiting' "$LOG" | sed 's/^/   /' || true
echo "-- tcpdump (inbound on $AP1) --"; sed 's/^/   /' "$CAPOUT"

# A PASS is the inner ARP flooded out the access port: broadcast dst, ARP, and
# the inner sender MAC — none of which appear in the encapsulated outer frame.
arp_n=$(grep -c -iE "Request who-has $ARP_TARGET_IP tell $ARP_SENDER_IP" "$CAPOUT" 2>/dev/null) || true
arp_n=${arp_n:-0}
echo
echo "   inner ARP frames flooded to $AP1: $arp_n"
if [ "$arp_n" -ge 1 ]; then
    echo
    echo "PASS: End.DT2M decapped the outer IPv6 and the bridge flooded the inner"
    echo "      BUM frame to the local access port (strip + redirect via TC clsact)"
    exit 0
else
    echo
    echo "FAIL: inner ARP not observed on the access port"
    echo "-- tcpdump stderr --"; sed 's/^/   /' "$CAPERR"
    echo "-- full loader log --"; sed 's/^/   /' "$LOG"
    exit 2
fi
