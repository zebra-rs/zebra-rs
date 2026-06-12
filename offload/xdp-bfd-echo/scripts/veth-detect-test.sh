#!/usr/bin/env bash
#
# End-to-end test for the in-kernel BFD control-packet expiration watchdog.
#
# Topology (same rationale as veth-test.sh — the sender end lives in its own
# namespace so frames actually cross the veth pair and hit the XDP hook):
#
#   sender (ns) --udp/3784, TTL 255--> veth-root [XDP: observe_control,
#   re-arm CONTROL_TIMERS bpf_timer, XDP_PASS]
#
# Flow:
#   1. `detect-add <discr> 600000` over the helper's stdin (600 ms detection).
#   2. Stream valid BFD control packets carrying that Your Discriminator every
#      150 ms for ~1.2 s. Each one must re-arm the kernel timer, so NO
#      `detect-down` may appear — if the XDP observe path were broken, the
#      helper's userspace bootstrap fallback would fire at 600 ms *during* the
#      stream and the test fails right here.
#   3. Stop sending. The bpf_timer fires ~600 ms later in softirq and the
#      helper must report `detect-down <discr>` on stdout.
#
# Run as root:
#   sudo bash offload/xdp-bfd-echo/scripts/veth-detect-test.sh
set -u

NS=bfddet-ns
V0=bfdd0            # root-ns end — the helper attaches its XDP program here
V1=bfdd1            # namespace end — the control-packet sender
IP0=10.124.0.1
IP1=10.124.0.2
PORT=3784
DISCR=3735928559    # 0xdeadbeef — Your Discriminator the watchdog is keyed on
DETECT_US=600000

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../target/release/xdp-bfd-echo"
CTL=/tmp/bfddet_ctl
OUT=/tmp/bfddet_events.out
LOG=/tmp/bfddet_helper.log

HELPER_PID=""
cleanup() {
    [ -n "$HELPER_PID" ] && kill -INT "$HELPER_PID" 2>/dev/null
    sleep 0.3
    exec 9>&- 2>/dev/null
    rm -f "$CTL"
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

echo "== 2. attach helper on $V0 (SKB mode) and arm the watchdog =="
rm -f "$CTL" "$OUT"; mkfifo "$CTL"
# Event lines (detect-down) go to stdout; env_logger goes to stderr.
RUST_LOG=info "$BIN" -i "$V0" -m skb <"$CTL" >"$OUT" 2>"$LOG" &
HELPER_PID=$!
exec 9>"$CTL"       # hold the control pipe open for the whole run
sleep 2
if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    echo "ERROR: helper exited early:"; cat "$LOG"; exit 1
fi
grep -iE 'attached|mode' "$LOG" | sed 's/^/   /'
echo "detect-add $DISCR $DETECT_US" >&9
echo "   detect-add $DISCR ${DETECT_US}us sent"

echo "== 3. stream BFD control packets (each must re-arm the kernel timer) =="
ip netns exec "$NS" python3 - <<PY
import struct, time
from socket import socket, AF_INET, SOCK_DGRAM, IPPROTO_IP, IP_TTL
s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(IPPROTO_IP, IP_TTL, 255)        # GTSM — the observer requires 255
s.bind(("$IP1", 49152))
# RFC 5880 §4.1: vers 1 | diag 0, state Up, mult 3, len 24, my/your discr,
# desired-tx / required-rx / echo-rx.
pkt = struct.pack("!BBBBIIIII", 0x20, 0xc0, 3, 24, 0x11112222, $DISCR,
                  300000, 300000, 0)
for _ in range(8):
    s.sendto(pkt, ("$IP0", $PORT)); time.sleep(0.15)
print("   sent 8x udp/$PORT (TTL 255) over ~1.2s")
PY

# 1.2 s of traffic > 600 ms detection: a premature detect-down means the XDP
# observe path never re-armed the timer (the bootstrap fallback fired instead).
if grep -q "detect-down" "$OUT"; then
    echo
    echo "FAIL: detect-down fired WHILE control packets were flowing"
    echo "-- events --"; sed 's/^/   /' "$OUT"
    echo "-- helper log --"; sed 's/^/   /' "$LOG"
    exit 2
fi
echo "   no detect-down while traffic flowed (kernel timer kept re-arming)"

echo "== 4. stop the stream; expect detect-down within ~${DETECT_US}us =="
deadline=$(( $(date +%s) + 5 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -q "detect-down $DISCR" "$OUT" && break
    sleep 0.1
done

echo "-- events --"; sed 's/^/   /' "$OUT"
if grep -q "detect-down $DISCR" "$OUT"; then
    echo
    echo "PASS: kernel expiration watchdog re-armed on traffic and fired after it stopped"
    exit 0
else
    echo
    echo "FAIL: no detect-down after the stream stopped"
    echo "-- helper log --"; sed 's/^/   /' "$LOG"
    exit 2
fi
