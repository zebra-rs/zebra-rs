#!/usr/bin/env bash
#
# End-to-end load test for the EVPN BUM replication TC/clsact `End.Replicate`
# datapath (RFC 9524 SR replication segment).
#
# What it proves: the stock kernel cannot replicate one packet into N copies
# each with a different rewritten header. This datapath can. We send ONE
# SRv6-style frame addressed to a tree's replication SID and observe N copies
# come back out, each with its outer IPv6 Destination Address rewritten to a
# different leaf SID.
#
# Topology (one veth pair; the namespace end is both sender and collector):
#
#   ns evpnrepl-ns                      root ns
#   ┌───────────────┐                   ┌──────────────────────────────────┐
#   │ evpnr1        │── veth pair ──────│ evpnr0  [clsact ingress:          │
#   │ (send 1 frame │                   │          tc_evpn_replicate]       │
#   │  dst = SID_R) │◄── N clones ──────│  clone_redirect each copy out     │
#   │  capture in   │                   │  evpnr0 egress, DA = leaf_i       │
#   └───────────────┘                   └──────────────────────────────────┘
#
# Putting the sender in its own namespace forces the frame across the veth so
# the clsact ingress hook on evpnr0 actually fires (a same-netns destination
# would be delivered locally and never hit the wire). The replicated copies are
# clone_redirect'd back out evpnr0's egress, arriving *inbound* on evpnr1 where
# tcpdump -Q in observes them.
#
# Run as root:
#   sudo bash offload/tc-evpn-replicate/scripts/veth-replicate-test.sh
set -u

NS=evpnrepl-ns
V0=evpnr0           # root-ns end — classifier attaches here (clsact ingress)
V1=evpnr1          # namespace end — sender + collector

VNI=100
TREE=100
SID_R="2001:db8:cafe::1"      # the tree's replication SID (outer DA we send to)
L1="2001:db8:0:1::100"        # leaf 1 End.DT2M SID
L2="2001:db8:0:2::100"        # leaf 2 End.DT2M SID
SRC="2001:db8:0:fe::1"        # arbitrary ingress source

RUNTIME=12        # seconds the loader stays attached (stdin held open)
CAP_SECS=7        # tcpdump capture window

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../target/release/tc-evpn-replicate"
LOG=/tmp/evpnrepl_loader.log
CAPOUT=/tmp/evpnrepl_tcpdump.out
CAPERR=/tmp/evpnrepl_tcpdump.err

LOADER_PID=""
cleanup() {
    [ -n "$LOADER_PID" ] && kill "$LOADER_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS" 2>/dev/null
    ip link del "$V0" 2>/dev/null   # also removes the clsact qdisc + program
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root (sudo)"; exit 1; fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found: $BIN"
    echo "       build it first:  (cd $SCRIPT_DIR/.. && cargo build --release)"
    exit 1
fi

echo "== 1. fresh veth pair + namespace =="
ip netns del "$NS" 2>/dev/null; ip link del "$V0" 2>/dev/null   # clean slate
ip netns add "$NS"
ip link add "$V0" type veth peer name "$V1"
ip link set "$V1" netns "$NS"
ip link set "$V0" up
ip netns exec "$NS" ip link set "$V1" up
ip netns exec "$NS" ip link set lo up
MAC_DST=$(cat "/sys/class/net/$V0/address")
MAC_SRC=$(ip netns exec "$NS" cat "/sys/class/net/$V1/address")
echo "   root ns: $V0 ($MAC_DST)   |   $NS: $V1 ($MAC_SRC)"

echo "== 2. attach replicator on $V0 (clsact ingress), copies -> $V0 egress =="
# Feed the replication segment on stdin, then hold stdin open with a sleep so
# the loader stays attached for the capture window; EOF makes it detach.
( printf 'repl-add %s %s 1 %s %s %s\n' "$VNI" "$TREE" "$SID_R" "$L1" "$L2"; sleep "$RUNTIME" ) \
    | RUST_LOG=info "$BIN" -i "$V0" -d ingress >"$LOG" 2>&1 &
LOADER_PID=$!
sleep 2
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "ERROR: loader exited early:"; cat "$LOG"; exit 1
fi
grep -iE 'attached|repl-add' "$LOG" | sed 's/^/   /'

echo "== 3. capture inbound ip6 on $V1, then send 3 trigger frames (dst $SID_R) =="
ip netns exec "$NS" timeout "$CAP_SECS" tcpdump -lnei "$V1" -Q in 'ip6' \
    >"$CAPOUT" 2>"$CAPERR" &
TCPDUMP_PID=$!
sleep 1
MAC_DST="$MAC_DST" MAC_SRC="$MAC_SRC" SRC="$SRC" DST="$SID_R" IFACE="$V1" \
    ip netns exec "$NS" python3 - <<'PY'
import os, socket, time

def mac(s): return bytes(int(b, 16) for b in s.split(":"))
def ip6(s): return socket.inet_pton(socket.AF_INET6, s)

iface = os.environ["IFACE"]
eth   = mac(os.environ["MAC_DST"]) + mac(os.environ["MAC_SRC"]) + b"\x86\xdd"
# IPv6: ver/tc/flow=0x60000000, payload_len, next_header=59 (No Next Header),
# hop_limit=64, src, dst. Outer-only frame: the datapath touches the DA + hop
# limit, nothing inner, so a header-only payload is enough to be observable.
payload = b"BUMFLOOD"
ipv6 = (b"\x60\x00\x00\x00"
        + len(payload).to_bytes(2, "big")
        + b"\x3b" + b"\x40"
        + ip6(os.environ["SRC"]) + ip6(os.environ["DST"]))
frame = eth + ipv6 + payload

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
for _ in range(3):
    s.send(frame); time.sleep(0.2)
print("   sent 3x  %s -> %s (replication SID)" % (os.environ["SRC"], os.environ["DST"]))
PY
wait "$TCPDUMP_PID" 2>/dev/null

echo "== 4. result =="
echo "-- loader log --"; grep -iE 'attached|repl-add|exiting' "$LOG" | sed 's/^/   /' || true
echo "-- tcpdump (inbound ip6 on $V1) --"; sed 's/^/   /' "$CAPOUT"

n1=$(grep -c "> $L1" "$CAPOUT" 2>/dev/null) || true
n2=$(grep -c "> $L2" "$CAPOUT" 2>/dev/null) || true
n1=${n1:-0}; n2=${n2:-0}
echo
echo "   copies to leaf 1 ($L1): $n1"
echo "   copies to leaf 2 ($L2): $n2"
if [ "$n1" -ge 1 ] && [ "$n2" -ge 1 ]; then
    echo
    echo "PASS: one frame to the replication SID was replicated to BOTH leaf SIDs"
    echo "      (End.Replicate: clone + per-branch outer-DA rewrite via TC clsact)"
    exit 0
else
    echo
    echo "FAIL: expected >=1 copy to each leaf SID"
    echo "-- tcpdump stderr --"; sed 's/^/   /' "$CAPERR"
    echo "-- full loader log --"; sed 's/^/   /' "$LOG"
    exit 2
fi
