#!/usr/bin/env bash
#
# A/B the APPL_DB that FRR and zebra-rs each produce.
#
# Byte-equality against a recorded trace proves the encoder reproduces
# FRR for the shapes that were captured. This proves the thing that
# actually matters: that `fpmsyncd` derives the *same APPL_DB rows* from
# zebra-rs's messages as from FRR's — the rows orchagent will read and
# program into the ASIC.
#
# Both sides are replayed into the same real `fpmsyncd`, so neither
# routing daemon runs and the whole comparison takes seconds:
#
#   1. replay tools/fpm-tap/golden/basic.fpm  (FRR's own bytes) -> dump A
#   2. flush redis, restart fpmsyncd
#   3. replay the zebra-rs-encoded capture                      -> dump B
#   4. diff A B
#
# The comparison is restricted to the scenario's static prefixes. FRR's
# capture also carries connected routes and the container's default
# route, but those come from zebra's kernel dump rather than from
# anything an encoder produces, so they are not zebra-rs's to reproduce
# here.
#
# Interface indexes are load-bearing: fpmsyncd resolves a nexthop
# ifindex to APPL_DB's `ifname` in its own netns, so the dummy links are
# created in the same order as the capture rig (dum0=3, dum1=4, dum2=5).

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-ab}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-ab.XXXXXX)
WORK=$(mktemp -d /tmp/fpm-tap-ab-work.XXXXXX)

[[ "${1:-}" == "--keep" ]] && KEEP="yes"

FRR_CAPTURE="$here/../golden/basic.fpm"
ZEBRA_CAPTURE="$WORK/zebra-rs-basic.fpm"
TAP_BIN="$repo/target/release/fpm-tap"

# The prefixes the scenario configures, as fpmsyncd keys them (host
# routes lose their /32 and /128). 10.100.5.0/24 is the `reject` route:
# fpmsyncd drops blackhole/unreachable with an error, so it must be
# absent from *both* sides — listing it here asserts that.
PREFIXES=(
    "10.100.0.0/24" "10.100.1.0/24" "10.100.2.0/24" "10.100.3.0/24"
    "10.100.4.0/24" "10.100.5.0/24" "10.100.6.7"
    "2001:db8:100::/64" "2001:db8:101::/64" "2001:db8:102::7" "::/0"
)

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "ab-diff: leaving containers and $WORK in place (--keep)"
    else
        docker rm -f "$CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
        rm -rf "$SOCKDIR" "$WORK"
    fi
}
trap cleanup EXIT

[[ -x "$TAP_BIN" ]] || { echo "build fpm-tap first: cargo build --release -p fpm-tap" >&2; exit 1; }
[[ -f "$FRR_CAPTURE" ]] || { echo "missing $FRR_CAPTURE — run capture.sh first" >&2; exit 1; }

echo "ab-diff: encoding the zebra-rs side"
( cd "$repo" && FPM_AB_OUT="$ZEBRA_CAPTURE" \
    cargo test --bin zebra-rs fib::fpm::ab_emit -- --ignored --nocapture 2>&1 \
    | grep -E "^wrote|error" )

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

docker cp "$TAP_BIN" "$CONTAINER:/usr/bin/fpm-tap" >/dev/null
docker cp "$FRR_CAPTURE" "$CONTAINER:/tmp/frr.fpm" >/dev/null
docker cp "$ZEBRA_CAPTURE" "$CONTAINER:/tmp/zebra-rs.fpm" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# Same links, same order, so ifindexes match the capture side.
docker exec "$CONTAINER" bash -euo pipefail -c '
for i in 0 1 2; do
    ip link add dum$i type dummy
    ip addr add 10.0.$i.1/24 dev dum$i
    ip -6 addr add 2001:db8:$i::1/64 dev dum$i
    ip link set dum$i up
done'

# Dump the APPL_DB rows for the prefixes under test, normalized: keys in
# a fixed order, fields sorted, so a diff shows only real differences.
dump() {
    local label="$1"
    docker exec "$CONTAINER" bash -c "
        for p in ${PREFIXES[*]@Q}; do
            key=\"_ROUTE_TABLE:\$p\"
            if [ \"\$(redis-cli -s /var/run/redis/redis.sock -n 0 EXISTS \"\$key\")\" = \"1\" ]; then
                echo \"== \$p\"
                redis-cli -s /var/run/redis/redis.sock -n 0 HGETALL \"\$key\" \
                    | paste - - | sort
            else
                echo \"== \$p  <absent>\"
            fi
        done" > "$WORK/$label"
}

replay() {
    local file="$1"
    docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
    sleep 2
    docker exec "$CONTAINER" fpm-tap replay "$file" --target 127.0.0.1:2620 --quiet
    # fpmsyncd batches APPL_DB writes through a RedisPipeline that is
    # flushed on select timeout, so give it a moment to land.
    sleep 3
    docker exec "$CONTAINER" bash -c 'pkill -x fpmsyncd || true'
    sleep 1
}

echo
echo "ab-diff: side A — replaying FRR's capture"
replay /tmp/frr.fpm
dump A

echo "ab-diff: flushing redis between runs"
docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 FLUSHDB >/dev/null

echo "ab-diff: side B — replaying zebra-rs's encoding"
replay /tmp/zebra-rs.fpm
dump B

echo
if diff -u "$WORK/A" "$WORK/B" > "$WORK/diff"; then
    echo "PASS — zebra-rs and FRR produce identical APPL_DB rows"
    echo
    cat "$WORK/A"
    exit 0
fi

echo "FAIL — APPL_DB differs (-FRR / +zebra-rs)"
echo
cat "$WORK/diff"
exit 1
