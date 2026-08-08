#!/usr/bin/env bash
#
# End-to-end: **zebra-rs itself** programming SONiC's APPL_DB.
#
# `ab-diff.sh` proves the encoder produces the right bytes by replaying
# canned captures. This proves the whole tee: a real zebra-rs, computing
# real routes, teeing them over a real FPM connection to a real
# `fpmsyncd`, landing in a real APPL_DB.
#
#   zebra-rs --(FPM 2620)--> fpmsyncd --> APPL_DB
#
# No FRR anywhere. This is the Phase-1 milestone of the SONiC port.
#
# Requires docker-fpm-frr:latest and docker-database:latest loaded from a
# sonic-buildimage tree's target/, plus a built zebra-rs and vtyctl.

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-live}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"
PROFILE=${PROFILE:-debug}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-live.XXXXXX)

[[ "${1:-}" == "--keep" ]] && KEEP="yes"

ZEBRA_BIN="$repo/target/$PROFILE/zebra-rs"
VTYCTL_BIN="$repo/target/$PROFILE/vtyctl"
for b in "$ZEBRA_BIN" "$VTYCTL_BIN"; do
    [[ -x "$b" ]] || { echo "missing $b — cargo build -p zebra-rs -p vtyctl" >&2; exit 1; }
done

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "live-tee: leaving containers running (--keep)"
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

echo "live-tee: installing zebra-rs ($PROFILE build)"
docker cp "$ZEBRA_BIN" "$CONTAINER:/usr/bin/zebra-rs" >/dev/null
docker cp "$VTYCTL_BIN" "$CONTAINER:/usr/bin/vtyctl" >/dev/null
docker exec "$CONTAINER" mkdir -p /usr/share/zebra-rs/yang
docker cp "$repo/zebra-rs/yang/." "$CONTAINER:/usr/share/zebra-rs/yang/" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# Same interface layout as the capture rig, so ifindexes line up with
# everything else in this directory.
docker exec "$CONTAINER" bash -euo pipefail -c '
for i in 0 1 2; do
    ip link add dum$i type dummy
    ip addr add 10.0.$i.1/24 dev dum$i
    ip -6 addr add 2001:db8:$i::1/64 dev dum$i
    ip link set dum$i up
done'

echo "live-tee: starting fpmsyncd"
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2

# Configuration goes in as a startup config file rather than through
# vtyctl. That is both simpler and closer to the real deployment: a SONiC
# container renders its config and starts the daemon on it. It also
# sidesteps the VTY session model, which ties a session to the caller's
# parent shell and rejects any client whose ppid is <= 1
# (SessionError::OrphanClient) — which is every `docker exec`, including
# `bash -c "vtyctl ..."`, because bash execs a lone command and so
# inherits the same orphaned parent.
echo "live-tee: writing startup config"
cat > "$SOCKDIR/routes.conf" <<'EOF'
set router static ipv4 route 10.100.0.0/24 nexthop 10.0.0.2
set router static ipv4 route 10.100.2.0/24 nexthop 10.0.0.2
set router static ipv4 route 10.100.2.0/24 nexthop 10.0.1.2
set router static ipv6 route 2001:db8:100::/64 nexthop 2001:db8::2
EOF
docker cp "$SOCKDIR/routes.conf" "$CONTAINER:/tmp/routes.conf" >/dev/null

# SONIC_FPM is the env fallback that enables the tee (FpmFib::from_env),
# standing in for the config leaf until that lands.
echo "live-tee: starting zebra-rs with the FPM tee enabled"
docker exec -d "$CONTAINER" bash -c \
    'SONIC_FPM=127.0.0.1:2620 zebra-rs --yang-path /usr/share/zebra-rs/yang \
        -c /tmp/routes.conf > /tmp/zebra-rs.log 2>&1'
sleep 6

echo
echo "live-tee: zebra-rs FPM log lines"
docker exec "$CONTAINER" bash -c 'grep -i fpm /tmp/zebra-rs.log | head -10' || true

echo
echo "live-tee: routes zebra-rs installed in the kernel"
docker exec "$CONTAINER" ip route show 2>&1 | head -8 || true

echo
echo "live-tee: APPL_DB — what fpmsyncd received from zebra-rs"
found=0
for p in 10.100.0.0/24 10.100.2.0/24 2001:db8:100::/64; do
    key="_ROUTE_TABLE:$p"
    if [ "$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 EXISTS "$key")" = "1" ]; then
        echo "== $p"
        docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 HGETALL "$key" | paste - - | sort
        found=$((found + 1))
    else
        echo "== $p  <MISSING>"
    fi
done

echo
if [[ "$found" -eq 3 ]]; then
    echo "PASS — zebra-rs programmed all 3 routes into APPL_DB over FPM"
    exit 0
fi
echo "FAIL — only $found of 3 routes reached APPL_DB"
docker exec "$CONTAINER" bash -c 'echo "--- zebra-rs log ---"; tail -30 /tmp/zebra-rs.log; echo "--- fpmsyncd log ---"; tail -10 /tmp/fpmsyncd.log' || true
exit 1
