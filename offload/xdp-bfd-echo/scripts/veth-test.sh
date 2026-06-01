#!/usr/bin/env bash
#
# End-to-end load test for the XDP BFD Echo reflector.
#
# Why a namespace: if both veth ends live in the same netns, the kernel delivers
# 10.123.0.2 -> 10.123.0.1 locally via loopback and never puts it on the wire,
# so the XDP hook never fires. Putting the *sender* end in its own namespace
# forces the frame across the veth pair and through the reflector on the other
# end.
#
# Flow: sender (ns) --udp/3785--> veth-root [XDP: swap MAC, XDP_TX] --> back to
# the sender end, where we observe it arriving *inbound* with the MACs swapped.
#
# Run as root:
#   sudo bash offload/xdp-bfd-echo/scripts/veth-test.sh
set -u

NS=bfdecho-ns
V0=bfde0            # root-ns end — reflector attaches its XDP program here
V1=bfde1           # namespace end — the sender
IP0=10.123.0.1
IP1=10.123.0.2
PORT=3785

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../target/release/xdp-bfd-echo"
REFLOG=/tmp/bfde_reflector.log
CAPOUT=/tmp/bfde_tcpdump.out
CAPERR=/tmp/bfde_tcpdump.err

REFLECTOR_PID=""
cleanup() {
    # SIGINT lets the loader run its normal exit path (detach XDP); deleting the
    # veth removes the program regardless, and tears down the namespace.
    [ -n "$REFLECTOR_PID" ] && kill -INT "$REFLECTOR_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS" 2>/dev/null
    ip link del "$V0" 2>/dev/null
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
ip addr add "$IP0/24" dev "$V0"
ip link set "$V0" up
ip netns exec "$NS" ip addr add "$IP1/24" dev "$V1"
ip netns exec "$NS" ip link set "$V1" up
ip netns exec "$NS" ip link set lo up
echo "   root ns: $V0 ($IP0)   |   $NS: $V1 ($IP1)"

echo "== 2. attach reflector on $V0 (SKB mode — native XDP does not loop on veth) =="
RUST_LOG=info "$BIN" -i "$V0" -m skb >"$REFLOG" 2>&1 &
REFLECTOR_PID=$!
sleep 2
if ! kill -0 "$REFLECTOR_PID" 2>/dev/null; then
    echo "ERROR: reflector exited early:"; cat "$REFLOG"; exit 1
fi
grep -iE 'attached|mode' "$REFLOG" | sed 's/^/   /'
ip -d link show "$V0" | grep -io 'xdp.*' | head -1 | sed 's/^/   link: /' || true

echo "== 3. capture inbound udp/$PORT on $V1, then send 3 frames =="
# Inbound-only (-Q in) so we see ONLY the reflected frame; the sent one is outbound.
ip netns exec "$NS" timeout 6 tcpdump -lnei "$V1" -c 1 -Q in "udp port $PORT" \
    >"$CAPOUT" 2>"$CAPERR" &
TCPDUMP_PID=$!
sleep 1
ip netns exec "$NS" python3 - <<PY
from socket import socket, AF_INET, SOCK_DGRAM
import time
s = socket(AF_INET, SOCK_DGRAM); s.bind(("$IP1", 0))
for _ in range(3):
    s.sendto(b"bfd-echo-test", ("$IP0", $PORT)); time.sleep(0.2)
print("   sent 3x udp/$PORT  $IP1 -> $IP0")
PY
wait "$TCPDUMP_PID" 2>/dev/null

echo "== 4. result =="
echo "-- reflector log --"; grep -iE 'reflected|attached' "$REFLOG" | sed 's/^/   /' || true
echo "-- tcpdump (inbound on $V1) --"; sed 's/^/   /' "$CAPOUT"

reflected_log=$(grep -c -i 'reflected' "$REFLOG" 2>/dev/null) || true
reflected_cap=$(grep -c -i "$PORT" "$CAPOUT" 2>/dev/null) || true
reflected_log=${reflected_log:-0}
reflected_cap=${reflected_cap:-0}
if [ "$reflected_cap" -ge 1 ] || [ "$reflected_log" -ge 1 ]; then
    echo
    echo "PASS: BFD Echo frame reflected via XDP_TX"
    echo "      (reflector logged $reflected_log reflect(s); $reflected_cap inbound frame(s) on $V1)"
    exit 0
else
    echo
    echo "FAIL: no reflected frame observed"
    echo "-- tcpdump stderr --"; sed 's/^/   /' "$CAPERR"
    echo "-- full reflector log --"; sed 's/^/   /' "$REFLOG"
    exit 2
fi
