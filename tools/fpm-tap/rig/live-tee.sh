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
# container renders its config and starts the daemon on it. (It also used
# to be the only option: older zebra-rs rejected any client whose ppid was
# <= 1 as an orphan — which is every `docker exec`. Since D30 in the VTY
# session design a parent-less client is keyed on its own pid instead.)
echo "live-tee: writing startup config"
cat > "$SOCKDIR/routes.conf" <<'EOF'
set system fpm enabled true
set router static ipv4 route 10.100.0.0/24 nexthop 10.0.0.2
set router static ipv4 route 10.100.2.0/24 nexthop 10.0.0.2
set router static ipv4 route 10.100.2.0/24 nexthop 10.0.1.2
set router static ipv6 route 2001:db8:100::/64 nexthop 2001:db8::2
EOF
# A VRF too. zebra-rs creates the Vrf1 device and picks its kernel table
# id itself; the tee resolves that table back to the device's ifindex,
# which is what FPM's table field actually carries. The name must start
# with "Vrf" — fpmsyncd rejects anything else (routesync.cpp:937-943).
cat >> "$SOCKDIR/routes.conf" <<'EOF'
set vrf Vrf1
set interface dum2 vrf Vrf1
set interface dum2 ipv4 address 10.0.2.1/24
set router static vrf Vrf1 ipv4 route 10.200.0.0/24 nexthop 10.0.2.2
EOF
docker cp "$SOCKDIR/routes.conf" "$CONTAINER:/tmp/routes.conf" >/dev/null

# The tee is turned on by `set system fpm enabled true` in the config
# above — no env var. Address and port default to 127.0.0.1:2620, which
# is where fpmsyncd listens in SONiC's bgp container.
echo "live-tee: starting zebra-rs with the FPM tee enabled"
docker exec -d "$CONTAINER" bash -c \
    'RUST_LOG=info,zebra_rs::fib::fpm=debug,zebra_rs::rib::inst=debug \
        zebra-rs --yang-path /usr/share/zebra-rs/yang \
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
# The VRF route is keyed by VRF name, not by table: fpmsyncd resolves the
# ifindex we sent to an interface name and prefixes the row with it
# (routesync.cpp:931-943). Seeing "Vrf1:" here is the end-to-end proof
# that the table field carried an ifindex and not a table id.
for p in 10.100.0.0/24 10.100.2.0/24 2001:db8:100::/64 Vrf1:10.200.0.0/24; do
    key="_ROUTE_TABLE:$p"
    if [ "$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 EXISTS "$key")" = "1" ]; then
        echo "== $p"
        docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 HGETALL "$key" | paste - - | sort
        found=$((found + 1))
    else
        echo "== $p  <MISSING>"
    fi
done

# The reverse direction: fpmsyncd acknowledges every route it accepts,
# and zebra-rs must parse those and mark the RIB entry offloaded. With
# suppress-fib-pending off (the default here) the acknowledgement is the
# optimistic one, sent on receipt.
echo
echo "live-tee: offload acknowledgements zebra-rs received back"
acks=$(docker exec "$CONTAINER" bash -c 'grep -c "FPM offload ack" /tmp/zebra-rs.log || true')
docker exec "$CONTAINER" bash -c 'grep "FPM offload ack" /tmp/zebra-rs.log | head -5' || true
echo "  ($acks acknowledgements)"

# An acknowledgement that does not resolve to a RIB entry is silently
# useless — the flag never gets set — so make that failure loud. It is
# the shape a prefix-key mismatch would take (a /32 host route, say).
unknown=$(docker exec "$CONTAINER" bash -c 'grep -c "offload ack for unknown prefix" /tmp/zebra-rs.log || true')
if [[ "$unknown" -gt 0 ]]; then
    echo "  WARNING: $unknown acknowledgement(s) did not match a RIB entry:"
    docker exec "$CONTAINER" bash -c 'grep "offload ack for unknown prefix" /tmp/zebra-rs.log | head -5' || true
fi

# ── Reconnect and replay ────────────────────────────────────────────
#
# FPM's contract is explicit: "If the connection to the FPM goes down for
# some reason, the client should send the FPM a complete copy of the
# forwarding table(s) when it reconnects" (fpm.h). Without that, a
# fpmsyncd restart leaves APPL_DB frozen at whatever it held when the
# socket dropped, and nothing corrects it until unrelated route churn
# happens to rewrite each prefix — for a stable table, never.
#
# So: wipe APPL_DB, restart fpmsyncd, and check the routes come back
# without touching the configuration.
echo
echo "live-tee: restarting fpmsyncd to test reconnect + replay"
docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 FLUSHDB >/dev/null
docker exec "$CONTAINER" bash -c 'pkill -x fpmsyncd || true'
sleep 2
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd2.log 2>&1'
sleep 6

replayed=0
for p in 10.100.0.0/24 10.100.2.0/24 2001:db8:100::/64 Vrf1:10.200.0.0/24; do
    if [ "$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 EXISTS "_ROUTE_TABLE:$p")" = "1" ]; then
        replayed=$((replayed + 1))
    else
        echo "  $p did NOT come back after reconnect"
    fi
done
docker exec "$CONTAINER" bash -c 'grep -E "FPM (replaying|disconnected|connected)" /tmp/zebra-rs.log | tail -4' || true
echo "  ($replayed of 4 routes replayed into a wiped APPL_DB)"

echo
if [[ "$found" -eq 4 && "$acks" -ge 4 && "$unknown" -eq 0 && "$replayed" -eq 4 ]]; then
    echo "PASS — zebra-rs programmed all 4 routes (incl. a VRF route) into"
    echo "       APPL_DB over FPM, processed $acks offload acknowledgements"
    echo "       back, and replayed all 4 after a fpmsyncd restart"
    exit 0
fi
if [[ "$found" -eq 3 ]]; then
    echo "FAIL — initial program worked, but a later stage did not"
    echo "       ($acks acks, $unknown unmatched, $replayed/4 replayed)"
    exit 1
fi
echo "FAIL — only $found of 3 routes reached APPL_DB"
docker exec "$CONTAINER" bash -c 'echo "--- zebra-rs log ---"; tail -30 /tmp/zebra-rs.log; echo "--- fpmsyncd log ---"; tail -10 /tmp/fpmsyncd.log' || true
exit 1
