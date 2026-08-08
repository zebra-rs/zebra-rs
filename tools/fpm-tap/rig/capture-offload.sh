#!/usr/bin/env bash
#
# Capture the FPM **offload-acknowledgement** direction.
#
# This is the half of the protocol `capture.sh` cannot reach. With
# `bgp suppress-fib-pending` (which SONiC's default bgpd template sets),
# BGP holds a prefix out of its Adj-RIB-Out until the FIB confirms the
# route was programmed. That confirmation arrives as an RTM_NEWROUTE with
# RTM_F_OFFLOAD set, sent by fpmsyncd back up the *same* TCP connection.
# zebra-rs has to parse it, so we need to see it.
#
# Topology, all in one network namespace so ifindexes stay consistent
# between zebra and fpmsyncd:
#
#     zebra --(2621)--> fpm-tap --(2620)--> fpmsyncd --> APPL_DB
#           <----------         <----------          <-- offload ack
#                                                        ^
#                                     fake-orchagent.py -+
#
# fpmsyncd's listen port is hardcoded to FPM_DEFAULT_PORT, so the tap
# takes 2621 and zebra is pointed at it with `fpm address ... port 2621`.
#
# Requires docker-fpm-frr:latest and docker-database:latest loaded from a
# sonic-buildimage tree's target/.

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-offload}
DB_CONTAINER="${CONTAINER}-db"
OUT=""
KEEP="no"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-redis.XXXXXX)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)  OUT="$2"; shift 2 ;;
        --keep) KEEP="yes"; shift ;;
        *) echo "usage: $0 --out FILE [--keep]" >&2; exit 1 ;;
    esac
done
[[ -n "$OUT" ]] || { echo "--out is required" >&2; exit 1; }

TAP_BIN=""
for cand in "$here/../../../target/release/fpm-tap" "$here/../../../target/debug/fpm-tap"; do
    [[ -x "$cand" ]] && { TAP_BIN="$cand"; break; }
done
[[ -n "$TAP_BIN" ]] || { echo "build fpm-tap first: cargo build --release -p fpm-tap" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "rig: leaving containers '$CONTAINER' and '$DB_CONTAINER' running (--keep)"
    else
        docker rm -f "$CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
        rm -rf "$SOCKDIR"
    fi
}
trap cleanup EXIT

docker rm -f "$CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true

# Redis, from SONiC's own database image so the server version matches
# what the platform ships. The socket directory is bind-mounted into both
# containers because swsscommon's DBConnector(dbName, ...) connects over
# the unix socket named in database_config.json, not over TCP.
#
# That mount lands on /var/run/redis, which in the image also holds
# sonic-db/database_config.json — the file every swsscommon client reads
# to find the socket in the first place. Bind-mounting over it hides it,
# so stage a copy into the shared directory first.
mkdir -p "$SOCKDIR/sonic-db"
docker run --rm --entrypoint /bin/cat "$FRR_IMAGE" \
    /var/run/redis/sonic-db/database_config.json > "$SOCKDIR/sonic-db/database_config.json"
chmod -R 777 "$SOCKDIR"
docker run -d --name "$DB_CONTAINER" --init \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /usr/bin/redis-server "$DB_IMAGE" \
    --unixsocket /var/run/redis/redis.sock --unixsocketperm 777 \
    --port 6379 --bind 127.0.0.1 --databases 100 --save '' >/dev/null

# The routing container joins the database container's network namespace
# so 127.0.0.1 is shared, and mounts the same socket directory.
docker run -d --name "$CONTAINER" --init \
    --network "container:$DB_CONTAINER" \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /bin/sleep "$FRR_IMAGE" infinity >/dev/null

docker cp "$TAP_BIN" "$CONTAINER:/usr/bin/fpm-tap" >/dev/null
docker cp "$here/fake-orchagent.py" "$CONTAINER:/tmp/fake-orchagent.py" >/dev/null
docker cp "$here/scenarios/basic.sh" "$CONTAINER:/tmp/scenario.sh" >/dev/null

echo "rig: waiting for redis"
for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done
docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping

docker exec "$CONTAINER" bash -euo pipefail -c '
for i in 0 1 2; do
    ip link add dum$i type dummy
    ip addr add 10.0.$i.1/24 dev dum$i
    ip -6 addr add 2001:db8:$i::1/64 dev dum$i
    ip link set dum$i up
done
mkdir -p /var/run/frr /var/log/frr
chown -R frr:frr /var/run/frr /var/log/frr /etc/frr
rm -f /etc/frr/frr.conf
echo "no service integrated-vtysh-config" > /etc/frr/vtysh.conf

# Point zebra at the tap on 2621; fpmsyncd keeps the well-known 2620.
cat > /etc/frr/zebra.conf <<EOF
hostname fpm-tap-offload
log stdout
!
no fpm use-next-hop-groups
fpm address 127.0.0.1 port 2621
!
EOF
chown -R frr:frr /etc/frr

# The single switch that makes fpmsyncd emit acknowledgements at all.
sonic-db-cli CONFIG_DB HSET "DEVICE_METADATA|localhost" suppress-fib-pending enabled
'

echo "rig: starting fpmsyncd"
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2

echo "rig: starting tap (2621 -> fpmsyncd 2620)"
docker exec -d "$CONTAINER" bash -c \
    'fpm-tap record --listen 127.0.0.1:2621 --forward 127.0.0.1:2620 --out /tmp/capture.fpm > /tmp/tap.log 2>&1'
sleep 1

docker exec "$CONTAINER" bash -c '/usr/lib/frr/mgmtd -A 127.0.0.1 -P 0 -d'
sleep 2
docker exec "$CONTAINER" bash -c '
/usr/lib/frr/zebra -A 127.0.0.1 -s 90000000 -M dplane_fpm_sonic \
    --asic-offload=notify_on_offload -f /etc/frr/zebra.conf -d'
sleep 3
docker exec "$CONTAINER" bash -c '/usr/lib/frr/staticd -A 127.0.0.1 -P 0 -d'
sleep 2

docker exec "$CONTAINER" bash -c 'vtysh -c "show fpm status"'

echo "rig: running scenario"
docker exec "$CONTAINER" bash /tmp/scenario.sh
sleep 3

echo "rig: routes now in APPL_DB"
docker exec "$CONTAINER" bash -c 'sonic-db-cli APPL_DB KEYS "_ROUTE_TABLE:*" | sort | head -20'

echo "rig: publishing route responses (orchagent stand-in)"
docker exec "$CONTAINER" python3 /tmp/fake-orchagent.py || true
sleep 3

docker exec "$CONTAINER" bash -c 'pkill -x zebra || true; sleep 1'
sleep 1

mkdir -p "$(dirname "$OUT")"
docker cp "$CONTAINER:/tmp/capture.fpm" "$OUT" >/dev/null
echo "rig: wrote $OUT"
echo
"$TAP_BIN" stats "$OUT"
