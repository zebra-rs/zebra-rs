#!/usr/bin/env bash
#
# End-to-end load test for the root H.Encaps-from-bare-frame datapath
# (RFC 9524 SR replication segment, ingress PE).
#
# What it proves: a BUM frame arriving *bare* (just an inner Ethernet frame)
# from the local bridge is wrapped in a reduced SRv6 encapsulation (link
# Ethernet + outer IPv6, Next Header = Ethernet, src = the root SID) and fanned
# out — one copy per leaf, each with the outer IPv6 destination set to that
# leaf's SID. The stock kernel has no way to do this header push + per-copy
# rewrite for an L2 payload.
#
# Topology — the overlay port + underlay egress live in their own namespace so
# the host's own multicast (mDNS, etc.) can't leak onto the overlay port and get
# encapsulated too; only the injected BUM frame egresses enc0:
#
#   ns evpnencap-ns                                    root ns
#   ┌────────────────────────────────────────────┐
#   │ enc1 ── veth ── enc0 [clsact egress:         │
#   │ (carrier)        |   tc_evpn_encap]          │
#   │                  |  AF_PACKET send bare ARP  │
#   │                  v  encap + clone per leaf   │
#   │           ul0 ───────────── veth ───────────────── ul1 [capture inbound]
#   └────────────────────────────────────────────┘
#
# Run as root:
#   sudo bash offload/tc-evpn-replicate/scripts/veth-encap-test.sh
set -u

NS=evpnencap-ns
E0=evpnenc0          # overlay-port end (in ns) — tc_evpn_encap attaches (egress)
E1=evpnenc1         # its peer (in ns, carrier only)
U0=evpnul0           # underlay end (in ns) — encapsulated copies leave here
U1=evpnul1          # underlay peer (root ns) — copies captured here

VNI=100
ROOT_SID="2001:db8:aaaa::1"   # this PE's root SID (outer IPv6 source)
L1="2001:db8:0:1::100"        # leaf 1 SID
L2="2001:db8:0:2::100"        # leaf 2 SID
INNER_SRC_MAC=02:00:00:00:0b:01

RUNTIME=12
CAP_SECS=7

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../target/release/tc-evpn-replicate"
LOG=/tmp/evpnencap_loader.log
CAPOUT=/tmp/evpnencap_tcpdump.out
CAPERR=/tmp/evpnencap_tcpdump.err

LOADER_PID=""
cleanup() {
    [ -n "$LOADER_PID" ] && kill "$LOADER_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS" 2>/dev/null
    ip link del "$U1" 2>/dev/null   # root-ns end (also removes ul0 if still here)
    ip link del "$E0" 2>/dev/null
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root (sudo)"; exit 1; fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found: $BIN"
    echo "       build it first:  (cd $SCRIPT_DIR/.. && cargo build --release)"
    exit 1
fi

echo "== 1. fresh namespace + veth pairs =="
cleanup 2>/dev/null
ip netns add "$NS"
ip link add "$E0" type veth peer name "$E1"
ip link add "$U0" type veth peer name "$U1"
ip link set "$E0" netns "$NS"; ip link set "$E1" netns "$NS"
ip link set "$U0" netns "$NS"   # U1 stays in the root ns for capture
ip netns exec "$NS" ip link set lo up
for d in "$E0" "$E1" "$U0"; do
    # Disable IPv6 autoconf so the veths don't emit their own MLD/RS frames
    # (which would egress the overlay port and get encapsulated as noise); the
    # AF_PACKET inject + clone_redirect datapath is unaffected.
    ip netns exec "$NS" sysctl -qw "net.ipv6.conf.$d.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$NS" ip link set "$d" up
    ip netns exec "$NS" ethtool -K "$d" gro off gso off tso off lro off 2>/dev/null || true
done
ip link set "$U1" up
ethtool -K "$U1" gro off gso off tso off lro off 2>/dev/null || true
MAC_U0=$(ip netns exec "$NS" cat "/sys/class/net/$U0/address")
MAC_U1=$(cat "/sys/class/net/$U1/address")
echo "   ns $NS: overlay port $E0, underlay $U0 ($MAC_U0)  ->  root ns: $U1 ($MAC_U1)"

echo "== 2. attach root encap on $E0 (clsact egress), copies -> $U0 =="
# encap-cfg sets the outer src=root SID + underlay + outer MACs; repl-add fills
# the leaf set (REPL_SEG[vni]) the encap fans out to.
( printf 'encap-cfg %s %s %s %s %s\n' "$VNI" "$U0" "$ROOT_SID" "$MAC_U1" "$MAC_U0"
  printf 'repl-add %s %s 1 %s %s %s\n'  "$VNI" "$VNI" "$ROOT_SID" "$L1" "$L2"
  sleep "$RUNTIME" ) \
    | ip netns exec "$NS" env RUST_LOG=info "$BIN" -i "$E0" --encap >"$LOG" 2>&1 &
LOADER_PID=$!
sleep 2
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "ERROR: loader exited early:"; cat "$LOG"; exit 1
fi
grep -iE 'attached|encap-cfg|repl-add' "$LOG" | sed 's/^/   /'

echo "== 3. capture inbound on $U1, then send 3 bare BUM frames out $E0 =="
timeout "$CAP_SECS" tcpdump -lnei "$U1" -Q in 'ip6' >"$CAPOUT" 2>"$CAPERR" &
TCPDUMP_PID=$!
sleep 1
INNER_SRC_MAC="$INNER_SRC_MAC" IFACE="$E0" \
    ip netns exec "$NS" python3 - <<'PY'
import errno, os, socket, time

def mac(s): return bytes(int(b, 16) for b in s.split(":"))

iface = os.environ["IFACE"]
smac = mac(os.environ["INNER_SRC_MAC"])
# Bare inner BUM frame: broadcast ARP request, padded to the 60-byte minimum.
eth = b"\xff\xff\xff\xff\xff\xff" + smac + b"\x08\x06"
arp = (b"\x00\x01\x08\x00\x06\x04\x00\x01"
       + smac + socket.inet_aton("10.0.0.1")
       + b"\x00\x00\x00\x00\x00\x00" + socket.inet_aton("10.0.0.2"))
frame = (eth + arp).ljust(60, b"\x00")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
# A raw send through the qdisc on a veth can return ENOBUFS even though the frame
# was queued + transmitted (so the egress clsact hook — the encap classifier —
# still runs). Treat ENOBUFS as sent and do NOT retry (retrying double-sends);
# PACKET_QDISC_BYPASS is not an option here because it would skip egress clsact.
sent = 0
for _ in range(3):
    try:
        s.send(frame)
    except OSError as e:
        if e.errno != errno.ENOBUFS:
            raise
    sent += 1
    time.sleep(0.2)
print("   sent %d/3 bare BUM (broadcast ARP) out %s" % (sent, iface))
PY
wait "$TCPDUMP_PID" 2>/dev/null

echo "== 4. result =="
echo "-- loader log --"; grep -iE 'attached|encap-cfg|repl-add|exiting' "$LOG" | sed 's/^/   /' || true
echo "-- tcpdump (inbound ip6 on $U1) --"; sed 's/^/   /' "$CAPOUT"

# Assert on the full encap: outer src = root SID, outer dst = each leaf SID, and
# the decoded inner ARP (tcpdump understands Next Header = Ethernet/143), so the
# match can only be our injected BUM frame.
n1=$(grep -c "$ROOT_SID > $L1:.*Request who-has 10.0.0.2" "$CAPOUT" 2>/dev/null) || true
n2=$(grep -c "$ROOT_SID > $L2:.*Request who-has 10.0.0.2" "$CAPOUT" 2>/dev/null) || true
n1=${n1:-0}; n2=${n2:-0}
echo
echo "   encapped ARP $ROOT_SID > $L1 : $n1"
echo "   encapped ARP $ROOT_SID > $L2 : $n2"
if [ "$n1" -ge 1 ] && [ "$n2" -ge 1 ]; then
    echo
    echo "PASS: a bare BUM frame was H.Encaps'd (outer IPv6 src = root SID, inner"
    echo "      frame intact) and fanned out to BOTH leaf SIDs via TC clsact egress"
    exit 0
else
    echo
    echo "FAIL: expected an encapsulated copy of the inner ARP to each leaf SID"
    echo "-- tcpdump stderr --"; sed 's/^/   /' "$CAPERR"
    echo "-- full loader log --"; sed 's/^/   /' "$LOG"
    exit 2
fi
