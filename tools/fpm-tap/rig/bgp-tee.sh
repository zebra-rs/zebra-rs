#!/usr/bin/env bash
#
# eBGP end-to-end: zebra-rs learns routes from a real BGP peer and tees
# them to SONiC's APPL_DB.
#
# Everything else in this directory exercises *static* routes. That
# leaves the actual workload untested: BGP routes arrive by protocol
# rather than by config, their nexthops are resolved through the RIB
# rather than given, and they carry a different protocol byte (186, which
# APPL_DB renders as `bgp` — unlike static's raw `0xc4`, since libnl's
# rt_protos knows 186 by name).
#
#   FRR bgpd (AS 65002) --eBGP--> zebra-rs (AS 65001) --FPM--> fpmsyncd --> APPL_DB
#         [netns "peer"]  veth   [default netns]
#
# The peer is real FRR from the SONiC image, so the routes are produced
# by the same implementation SONiC ships today.
#
# The peer lives in its own network namespace joined by a veth, rather
# than in a second container over the docker bridge. That is not
# incidental: `fpmsyncd` explicitly drops any route whose nexthop
# interface is `eth0`, `docker0` or `eth1-midplane` (routesync.cpp:2718,
# 2736, 2878) because SONiC treats those as management. Peering over the
# docker bridge produces exactly such routes, so they reach fpmsyncd,
# get acknowledged, and are then silently discarded — a rig that looks
# like a zebra-rs bug and is not one.
#
# Requires docker-fpm-frr:latest and docker-database:latest, plus a built
# zebra-rs.

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-bgp}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"
PROFILE=${PROFILE:-debug}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-bgp.XXXXXX)

[[ "${1:-}" == "--keep" ]] && KEEP="yes"

ZEBRA_BIN="$repo/target/$PROFILE/zebra-rs"
[[ -x "$ZEBRA_BIN" ]] || { echo "missing $ZEBRA_BIN — cargo build -p zebra-rs" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "bgp-tee: leaving containers running (--keep)"
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

# The zebra-rs side shares the database container's netns (so redis is on
# 127.0.0.1) and therefore uses its IP for BGP.
# --privileged rather than the usual cap-adds: `ip netns add` needs to
# make /run/netns a shared mount, which Docker's default propagation
# forbids even with CAP_SYS_ADMIN. Only this rig needs it — the others
# run with NET_ADMIN alone.
docker run -d --name "$CONTAINER" --init \
    --network "container:$DB_CONTAINER" \
    --privileged \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /bin/sleep "$FRR_IMAGE" infinity >/dev/null

LOCAL_IP=10.99.0.1
PEER_IP=10.99.0.2
echo "bgp-tee: zebra-rs at $LOCAL_IP (AS 65001), FRR peer at $PEER_IP (AS 65002), over a veth"

docker cp "$ZEBRA_BIN" "$CONTAINER:/usr/bin/zebra-rs" >/dev/null
docker exec "$CONTAINER" mkdir -p /usr/share/zebra-rs/yang
docker cp "$repo/zebra-rs/yang/." "$CONTAINER:/usr/share/zebra-rs/yang/" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# ── The FRR peer, in its own netns ──────────────────────────────────
# Advertises three prefixes off dummy interfaces via redistribute
# connected, so they are ordinary BGP routes with a real nexthop.
docker exec "$CONTAINER" bash -euo pipefail -c "
ip netns add peer
ip link add v-main type veth peer name v-peer
ip link set v-peer netns peer
ip addr add $LOCAL_IP/24 dev v-main
ip link set v-main up
ip netns exec peer ip addr add $PEER_IP/24 dev v-peer
ip netns exec peer ip link set v-peer up
ip netns exec peer ip link set lo up

for i in 0 1 2; do
    ip netns exec peer ip link add adv\$i type dummy
    ip netns exec peer ip addr add 10.55.\$i.1/24 dev adv\$i
    ip netns exec peer ip link set adv\$i up
done

# -N gives the peer its own config and socket paths, so it cannot
# collide with anything running in the default namespace.
mkdir -p /etc/frr/peer /var/run/frr/peer
cat > /etc/frr/peer/zebra.conf <<EOF
hostname bgp-peer
EOF
cat > /etc/frr/peer/bgpd.conf <<EOF
hostname bgp-peer
router bgp 65002
  bgp router-id 10.55.0.1
  no bgp ebgp-requires-policy
  neighbor $LOCAL_IP remote-as 65001
  address-family ipv4 unicast
    neighbor $LOCAL_IP activate
    redistribute connected
  exit-address-family
EOF
chown -R frr:frr /etc/frr /var/run/frr
ip netns exec peer /usr/lib/frr/zebra -N peer -A 127.0.0.1 -f /etc/frr/peer/zebra.conf -d
sleep 2
ip netns exec peer /usr/lib/frr/bgpd -N peer -A 127.0.0.1 -f /etc/frr/peer/bgpd.conf -d
"

# ── The zebra-rs side ───────────────────────────────────────────────
cat > "$SOCKDIR/zebra.conf" <<EOF
set system fpm enabled true
set router bgp global as 65001
set router bgp global router-id 10.99.0.1
set router bgp neighbor $PEER_IP remote-as 65002
set router bgp neighbor $PEER_IP enabled true
set router bgp neighbor $PEER_IP afi-safi ipv4 enabled true
EOF
docker cp "$SOCKDIR/zebra.conf" "$CONTAINER:/tmp/zebra.conf" >/dev/null

echo "bgp-tee: starting fpmsyncd"
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2

echo "bgp-tee: starting zebra-rs"
docker exec -d "$CONTAINER" bash -c \
    'RUST_LOG=info,zebra_rs::fib::fpm=debug zebra-rs --yang-path /usr/share/zebra-rs/yang \
        -c /tmp/zebra.conf > /tmp/zebra-rs.log 2>&1'

echo "bgp-tee: waiting for the session to come up and routes to converge"
for _ in $(seq 40); do
    n=$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
        --scan --pattern '_ROUTE_TABLE:10.55.*' 2>/dev/null | wc -l)
    [[ "$n" -ge 3 ]] && break
    sleep 1
done

echo
echo "bgp-tee: peer's view of the session"
docker exec "$CONTAINER" bash -c 'ip netns exec peer vtysh -N peer -c "show bgp summary" 2>&1 | tail -6' || true

echo
echo "bgp-tee: routes zebra-rs installed in the kernel"
docker exec "$CONTAINER" ip route show proto bgp 2>&1 | head -5 || true

echo
echo "bgp-tee: APPL_DB — BGP routes teed by zebra-rs"
found=0
for p in 10.55.0.0/24 10.55.1.0/24 10.55.2.0/24; do
    key="_ROUTE_TABLE:$p"
    if [ "$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 EXISTS "$key")" = "1" ]; then
        echo "== $p"
        docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 HGETALL "$key" | paste - - | sort
        found=$((found + 1))
    else
        echo "== $p  <MISSING>"
    fi
done

# BGP's protocol byte is 186, which libnl's rt_protos names, so APPL_DB
# should say `bgp` here rather than the raw `0xc4` static routes get.
protos=$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
    HGET "_ROUTE_TABLE:10.55.0.0/24" protocol 2>/dev/null || true)

echo
if [[ "$found" -eq 3 && "$protos" == "bgp" ]]; then
    echo "PASS — zebra-rs learned 3 prefixes over eBGP and teed them to"
    echo "       APPL_DB with protocol=$protos"
    exit 0
fi
echo "FAIL — $found/3 BGP prefixes in APPL_DB, protocol='$protos' (expected 'bgp')"
docker exec "$CONTAINER" bash -c 'echo "--- zebra-rs ---"; tail -25 /tmp/zebra-rs.log' || true
docker exec "$CONTAINER" bash -c 'ip netns exec peer vtysh -N peer -c "show bgp ipv4 unicast" 2>&1 | tail -10' || true
exit 1
