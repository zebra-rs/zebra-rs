#!/usr/bin/env bash
#
# Scale: how the FPM tee behaves under a real routing table.
#
# Every other rig here uses three or four routes, which says nothing
# about the parts of the tee that only matter in bulk — the unbounded
# send queue, the desired-state mirror's memory, whether the writer keeps
# up with convergence, and whether a full-table replay after a reconnect
# completes at all.
#
#   bgp-bench (N senders) --BGP--> zebra-rs --FPM--> fpmsyncd --> APPL_DB
#
# bgp-bench is the daemon's own load generator (tools/bgp-bench), so the
# UPDATEs are encoded by the same crate zebra-rs speaks.
#
# Usage:
#   ./scale-tee.sh [--prefixes N] [--keep]
#
# Requires docker-fpm-frr:latest and docker-database:latest, plus release
# builds of zebra-rs and bgp-bench (a debug build distorts the timings
# badly enough to be misleading).

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-scale}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"
PREFIXES=10000
PROFILE=${PROFILE:-release}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-scale.XXXXXX)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefixes) PREFIXES="$2"; shift 2 ;;
        --keep)     KEEP="yes"; shift ;;
        *) echo "usage: $0 [--prefixes N] [--keep]" >&2; exit 1 ;;
    esac
done

ZEBRA_BIN="$repo/target/$PROFILE/zebra-rs"
BENCH_BIN="$repo/target/$PROFILE/bgp-bench"
for b in "$ZEBRA_BIN" "$BENCH_BIN"; do
    [[ -x "$b" ]] || { echo "missing $b — cargo build --release -p zebra-rs -p bgp-bench" >&2; exit 1; }
done

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "scale-tee: leaving containers running (--keep)"
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
    --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /bin/sleep "$FRR_IMAGE" infinity >/dev/null

docker cp "$ZEBRA_BIN" "$CONTAINER:/usr/bin/zebra-rs" >/dev/null
docker cp "$BENCH_BIN" "$CONTAINER:/usr/bin/bgp-bench" >/dev/null
docker exec "$CONTAINER" mkdir -p /usr/share/zebra-rs/yang
docker cp "$repo/zebra-rs/yang/." "$CONTAINER:/usr/share/zebra-rs/yang/" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# bgp-bench's own emit-config, minus `no-fib-install`: that switch exists
# to measure BGP in isolation, and here the whole point is the FIB path.
#
# Caveat worth knowing when reading the numbers: the bench binds
# 127.0.0.x, so every learned route has a loopback nexthop, which the
# kernel refuses to install. fpmsyncd accepts them (it only filters
# eth0/docker0/eth1-midplane), so this measures the *tee* at scale and
# not the kernel path — `ip route show proto bgp` stays empty here by
# design. That the routes reach APPL_DB regardless is itself a real
# property: the tee is independent of kernel-install success, matching
# FRR, whose dplane hands a route to every provider independently.
cat > "$SOCKDIR/zebra.conf" <<'EOF'
set system fpm enabled true
set router bgp global as 65001
set router bgp global router-id 10.255.0.1
set router bgp port 1179
set router bgp timer adv-interval ibgp 1
set router bgp timer adv-interval ebgp 1
set router bgp neighbor 127.0.0.10 remote-as 65100
set router bgp neighbor 127.0.0.10 afi-safi ipv4 enabled true
set router bgp neighbor 127.0.0.10 transport passive-mode true
set router bgp neighbor 127.0.0.200 remote-as 65200
set router bgp neighbor 127.0.0.200 afi-safi ipv4 enabled true
set router bgp neighbor 127.0.0.200 transport passive-mode true
EOF
docker cp "$SOCKDIR/zebra.conf" "$CONTAINER:/tmp/zebra.conf" >/dev/null

echo "scale-tee: starting fpmsyncd"
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2

echo "scale-tee: starting zebra-rs ($PROFILE)"
docker exec -d "$CONTAINER" bash -c \
    'RUST_LOG=info zebra-rs --yang-path /usr/share/zebra-rs/yang \
        -c /tmp/zebra.conf > /tmp/zebra-rs.log 2>&1'
sleep 4

echo "scale-tee: blasting $PREFIXES prefixes"
start=$(date +%s)
docker exec "$CONTAINER" bgp-bench run \
    --target 127.0.0.1:1179 --senders 1 --receivers 1 \
    --prefixes "$PREFIXES" --timeout-secs 300 2>&1 | tail -8 || true

# APPL_DB is written through a ProducerStateTable, so routes stage as
# _ROUTE_TABLE:<prefix>. Poll until the count stops moving rather than
# guessing a settling time.
echo
echo "scale-tee: waiting for APPL_DB to settle"
prev=-1
for _ in $(seq 120); do
    n=$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
        --scan --pattern '_ROUTE_TABLE:*' 2>/dev/null | wc -l)
    [[ "$n" -eq "$prev" && "$n" -gt 0 ]] && break
    prev=$n
    sleep 2
done
elapsed=$(( $(date +%s) - start ))

kernel=$(docker exec "$CONTAINER" bash -c 'ip route show proto bgp | wc -l')
rss=$(docker exec "$CONTAINER" bash -c "ps -o rss= -C zebra-rs | tr -d ' '" || echo 0)

echo
echo "  prefixes advertised : $PREFIXES"
echo "  kernel BGP routes   : $kernel"
echo "  APPL_DB route rows  : $prev"
echo "  wall clock          : ${elapsed}s"
echo "  zebra-rs RSS        : $((rss / 1024)) MiB"
echo
docker exec "$CONTAINER" bash -c 'grep -iE "FPM (connected|disconnected|replaying)" /tmp/zebra-rs.log | tail -5' || true

# The tee reports what it dropped while disconnected; at scale that is
# the number worth watching, since a writer that cannot keep up shows up
# here rather than as an error.
# Replay at scale: a reconnect has to re-send the entire mirror. With
# three routes that is trivially fine; with a full table it is the one
# path that could plausibly stall or drop.
echo "scale-tee: wiping APPL_DB and restarting fpmsyncd to test replay at scale"
docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 FLUSHDB >/dev/null
docker exec "$CONTAINER" bash -c 'pkill -x fpmsyncd || true'
sleep 2
replay_start=$(date +%s)
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd2.log 2>&1'

rprev=-1
for _ in $(seq 120); do
    n=$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
        --scan --pattern '_ROUTE_TABLE:*' 2>/dev/null | wc -l)
    [[ "$n" -eq "$rprev" && "$n" -gt 0 ]] && break
    rprev=$n
    sleep 2
done
replay_elapsed=$(( $(date +%s) - replay_start ))
echo "  replayed $rprev rows in ${replay_elapsed}s"
docker exec "$CONTAINER" bash -c 'grep -iE "FPM (replaying|disconnected)" /tmp/zebra-rs.log | tail -3' || true

echo
if [[ "$prev" -ge "$PREFIXES" && "$rprev" -ge "$PREFIXES" ]]; then
    echo "PASS — all $PREFIXES prefixes reached APPL_DB (${elapsed}s),"
    echo "       and all $rprev replayed after a reconnect (${replay_elapsed}s)"
    exit 0
fi
if [[ "$prev" -ge "$PREFIXES" ]]; then
    echo "FAIL — initial convergence fine, but replay produced $rprev of $PREFIXES"
    exit 1
fi
echo "INCOMPLETE — $prev of $PREFIXES rows in APPL_DB after ${elapsed}s"
docker exec "$CONTAINER" bash -c 'tail -15 /tmp/zebra-rs.log' || true
exit 1
