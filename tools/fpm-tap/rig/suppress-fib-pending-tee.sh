#!/usr/bin/env bash
#
# `bgp suppress-fib-pending`, end to end: a prefix must not reach a peer
# until the forwarding plane has acknowledged programming it.
#
# Every failure mode of this feature is silent. A prefix held forever
# looks like "the peer never learned the route"; a suppressed withdraw
# looks like a stale route somewhere else. Unit tests cover the state
# machine, but only a real peer can show whether the announcement
# actually waited — and whether it ever arrives at all.
#
#   FRR sender (AS 65002) --eBGP--> zebra-rs (AS 65001) --eBGP--> FRR receiver (AS 65003)
#                                        |
#                                        +--FPM--> fpmsyncd --> APPL_DB
#                                                     ^
#                                          the acknowledger under test
#
# Two phases against the same topology:
#
#   A. fpmsyncd running. The ack comes back, so the receiver learns the
#      prefix promptly. This is the case that would break if the release
#      path re-armed the gate instead of consuming it — the prefix would
#      be suppressed forever and nothing would say so.
#
#   B. fpmsyncd stopped before zebra-rs starts. No ack can ever arrive,
#      so the prefix must be ABSENT from the receiver well past the point
#      it would normally appear, and must then be released by the
#      timeout. Advertising late is the designed failure; never
#      advertising would be a black hole.
#
# Requires docker-fpm-frr:latest and docker-database:latest, plus a built
# zebra-rs.

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-sfp}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"
PROFILE=${PROFILE:-release}
# Must match FIB_PENDING_TIMEOUT in src/bgp/route.rs.
TIMEOUT_SECS=${TIMEOUT_SECS:-30}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-sfp.XXXXXX)

[[ "${1:-}" == "--keep" ]] && KEEP="yes"

ZEBRA_BIN="$repo/target/$PROFILE/zebra-rs"
[[ -x "$ZEBRA_BIN" ]] || { echo "missing $ZEBRA_BIN — cargo build --release -p zebra-rs" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "suppress-fib-pending: leaving containers running (--keep)"
    else
        docker rm -f "$CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
        rm -rf "$SOCKDIR"
    fi
}
trap cleanup EXIT

docker rm -f "$CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true

mkdir -p "$SOCKDIR/sonic-db"
docker run --rm --entrypoint /bin/cat "$FRR_IMAGE" \
    /var/run/redis/sonic-db/database_config.json > "$SOCKDIR/sonic-db/database_config.json"
chmod -R 777 "$SOCKDIR"

docker run -d --name "$DB_CONTAINER" --init \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /usr/bin/redis-server "$DB_IMAGE" \
    --unixsocket /var/run/redis/redis.sock --unixsocketperm 777 \
    --port 6379 --bind 127.0.0.1 --databases 100 --save '' >/dev/null

docker run -d --name "$CONTAINER" --init \
    --network "container:$DB_CONTAINER" \
    --privileged \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /bin/sleep "$FRR_IMAGE" infinity >/dev/null

S_LOCAL=10.99.1.1; S_PEER=10.99.1.2     # sender
R_LOCAL=10.99.3.1; R_PEER=10.99.3.2     # receiver
PREFIX=10.66.0.0/24

docker cp "$ZEBRA_BIN" "$CONTAINER:/usr/bin/zebra-rs" >/dev/null
docker exec "$CONTAINER" mkdir -p /usr/share/zebra-rs/yang
docker cp "$repo/zebra-rs/yang/." "$CONTAINER:/usr/share/zebra-rs/yang/" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# NOTE: no backticks below. This block is a double-quoted docker exec
# string, so a backtick is command substitution on the HOST.
#
# sender: originates PREFIX off a dummy via redistribute connected.
# (A static route would not work: FRR 9+ routes static config through
# mgmtd/staticd rather than zebra.conf.)
docker exec "$CONTAINER" bash -euo pipefail -c "
ip netns add sender
ip link add v-s type veth peer name vp-s
ip link set vp-s netns sender
ip addr add $S_LOCAL/24 dev v-s
ip link set v-s up
ip netns exec sender ip addr add $S_PEER/24 dev vp-s
ip netns exec sender ip link set vp-s up
ip netns exec sender ip link set lo up
ip netns exec sender ip link add shared type dummy
ip netns exec sender ip addr add 10.66.0.1/24 dev shared
ip netns exec sender ip link set shared up

mkdir -p /etc/frr/sender /var/run/frr/sender
echo 'hostname sender' > /etc/frr/sender/zebra.conf
cat > /etc/frr/sender/bgpd.conf <<EOF
hostname sender
router bgp 65002
  bgp router-id 10.66.0.1
  no bgp ebgp-requires-policy
  neighbor $S_LOCAL remote-as 65001
  address-family ipv4 unicast
    neighbor $S_LOCAL activate
    redistribute connected
  exit-address-family
EOF

ip netns add receiver
ip link add v-r type veth peer name vp-r
ip link set vp-r netns receiver
ip addr add $R_LOCAL/24 dev v-r
ip link set v-r up
ip netns exec receiver ip addr add $R_PEER/24 dev vp-r
ip netns exec receiver ip link set vp-r up
ip netns exec receiver ip link set lo up

mkdir -p /etc/frr/receiver /var/run/frr/receiver
echo 'hostname receiver' > /etc/frr/receiver/zebra.conf
cat > /etc/frr/receiver/bgpd.conf <<EOF
hostname receiver
router bgp 65003
  bgp router-id 10.99.3.2
  no bgp ebgp-requires-policy
  neighbor $R_LOCAL remote-as 65001
  address-family ipv4 unicast
    neighbor $R_LOCAL activate
  exit-address-family
EOF

chown -R frr:frr /etc/frr /var/run/frr
for n in sender receiver; do
    ip netns exec \$n /usr/lib/frr/zebra -N \$n -A 127.0.0.1 -f /etc/frr/\$n/zebra.conf -d
done
sleep 1
for n in sender receiver; do
    ip netns exec \$n /usr/lib/frr/bgpd -N \$n -A 127.0.0.1 -f /etc/frr/\$n/bgpd.conf -d
done
"

cat > "$SOCKDIR/zebra.conf" <<EOF
set system fpm enabled true
set router bgp global as 65001
set router bgp global router-id 10.99.1.1
set router bgp suppress-fib-pending true
set router bgp neighbor $S_PEER remote-as 65002
set router bgp neighbor $S_PEER enabled true
set router bgp neighbor $S_PEER afi-safi ipv4 enabled true
set router bgp neighbor $R_PEER remote-as 65003
set router bgp neighbor $R_PEER enabled true
set router bgp neighbor $R_PEER afi-safi ipv4 enabled true
EOF
docker cp "$SOCKDIR/zebra.conf" "$CONTAINER:/tmp/zebra.conf" >/dev/null

# Is the receiver's session to zebra-rs actually up?
#
# Load-bearing for Phase B: "the receiver does not have the prefix" is
# trivially true while the session is still coming up, so without this
# the negative check would pass whether or not the gate works. Phase A
# takes ~35s to converge, almost all of it session establishment, which
# is exactly the window that would have made Phase B vacuous.
receiver_session_up() {
    docker exec "$CONTAINER" bash -c \
        "ip netns exec receiver vtysh -N receiver -c 'show bgp summary' 2>/dev/null" \
        | grep -qE "^$R_LOCAL[[:space:]].*[[:space:]](0|[1-9][0-9]*)$|^$R_LOCAL[[:space:]]" \
        && ! docker exec "$CONTAINER" bash -c \
        "ip netns exec receiver vtysh -N receiver -c 'show bgp summary' 2>/dev/null" \
        | grep -qE "^$R_LOCAL[[:space:]].*(Idle|Connect|Active|OpenSent|OpenConfirm)"
}

wait_receiver_session() {
    for _ in $(seq 60); do
        receiver_session_up && return 0
        sleep 1
    done
    return 1
}

# Does the receiver have the prefix?
receiver_has() {
    docker exec "$CONTAINER" bash -c \
        "ip netns exec receiver vtysh -N receiver -c 'show bgp ipv4 unicast $PREFIX' 2>/dev/null" \
        | grep -q "$S_PEER\|65002"
}

start_zebra() {
    docker exec "$CONTAINER" bash -c 'pkill -x zebra-rs || true'
    sleep 1
    docker exec -d "$CONTAINER" bash -c \
        'RUST_LOG=info zebra-rs --yang-path /usr/share/zebra-rs/yang \
            -c /tmp/zebra.conf > /tmp/zebra-rs.log 2>&1'
}

rc=0

# ── Phase A: acks flowing ───────────────────────────────────────────
echo "=== Phase A: fpmsyncd running — the ack should release the prefix ==="
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2
start_zebra

got_a=""
for i in $(seq 40); do
    if receiver_has; then got_a="$i"; break; fi
    sleep 1
done
# WHY it was released matters as much as whether. The timeout would
# release it too, so a pass here without this check proves only that the
# prefix eventually arrives — which the timeout guarantees regardless of
# whether the ack path works at all.
timed_out=$(docker exec "$CONTAINER" bash -c \
    'grep -c "suppress-fib-pending timed out" /tmp/zebra-rs.log || true' | tr -d "[:space:]")
if [[ -n "$got_a" && "${timed_out:-0}" == "0" ]]; then
    echo "PASS — receiver learned $PREFIX after ~${got_a}s, released by the ACK"
    echo "       (no timeout logged, so the offload path did the work)"
elif [[ -n "$got_a" ]]; then
    echo "FAIL — prefix arrived, but via the TIMEOUT ($timed_out logged), not the ack."
    echo "       The offload ack never reached BGP; the gate is holding every"
    echo "       prefix for the full timeout instead of releasing on confirmation."
    docker exec "$CONTAINER" bash -c 'grep -i "fpm\|offload" /tmp/zebra-rs.log | tail -15' || true
    rc=1
else
    echo "FAIL — receiver never learned $PREFIX even with acks flowing"
    docker exec "$CONTAINER" bash -c 'tail -20 /tmp/zebra-rs.log' || true
    rc=1
fi

# ── Phase B: no acknowledger ────────────────────────────────────────
echo
echo "=== Phase B: fpmsyncd stopped — the prefix must wait, then time out ==="
docker exec "$CONTAINER" bash -c 'pkill -x fpmsyncd || true'
docker exec "$CONTAINER" bash -c "ip netns exec receiver vtysh -N receiver -c 'clear bgp *' >/dev/null 2>&1" || true
start_zebra

# Wait for the SESSION before judging the absence of the prefix —
# otherwise this checks nothing (see receiver_session_up).
if ! wait_receiver_session; then
    echo "FAIL — receiver session never established; the negative check below"
    echo "       would have passed vacuously, so the phase is inconclusive"
    docker exec "$CONTAINER" bash -c \
        "ip netns exec receiver vtysh -N receiver -c 'show bgp summary' 2>&1 | tail -6" || true
    rc=1
fi
echo "     receiver session is up; now checking the prefix is withheld"
sleep 10
if receiver_has; then
    echo "FAIL — prefix reached the receiver with no FIB ack (the gate did not hold)"
    rc=1
else
    echo "ok — prefix correctly withheld with the session up and no acknowledger"
fi

# …and it must be released by the timeout rather than suppressed forever.
echo "     waiting out the ${TIMEOUT_SECS}s pending timeout"
released=""
for i in $(seq $((TIMEOUT_SECS + 25))); do
    if receiver_has; then released="$i"; break; fi
    sleep 1
done
if [[ -n "$released" ]]; then
    echo "PASS — timeout released $PREFIX after ~${released}s (advertise late, never never)"
else
    echo "FAIL — prefix never released; a lost ack suppresses it permanently"
    docker exec "$CONTAINER" bash -c 'tail -20 /tmp/zebra-rs.log' || true
    rc=1
fi

echo
[[ "$rc" -eq 0 ]] && echo "PASS — suppress-fib-pending holds on the ack and releases on the timeout" \
                  || echo "FAIL — see above"
exit "$rc"
