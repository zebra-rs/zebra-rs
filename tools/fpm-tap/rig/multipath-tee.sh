#!/usr/bin/env bash
#
# BGP multipath, end to end: two eBGP peers advertise the SAME prefix
# with equal attributes, and zebra-rs must install BOTH next-hops and tee
# both to APPL_DB.
#
# The unit tests cover the selection ladder. They cannot show that the
# chosen set survives the RIB, the netlink encoder and fpmsyncd — which
# is the part that decides whether a leaf actually load-shares across its
# uplinks. Before this feature existed zebra-rs installed one path and
# forwarded everything over a single link, with nothing erroring, so
# "looks fine" is not evidence here.
#
#   FRR peer A (AS 65002) ─┐
#                          ├─eBGP─> zebra-rs (AS 65001) ─FPM─> fpmsyncd ─> APPL_DB
#   FRR peer B (AS 65002) ─┘
#
# Both peers are in the SAME AS deliberately: that is what the default
# (strict) multipath rule requires — equal AS-path length AND the same
# neighbouring AS. Using two different ASes would only pass with
# `multipath-relax`, so this exercises the stricter path.
#
# Requires docker-fpm-frr:latest and docker-database:latest, plus a built
# zebra-rs (PROFILE=release by default here).

set -euo pipefail

FRR_IMAGE=${FRR_IMAGE:-docker-fpm-frr:latest}
DB_IMAGE=${DB_IMAGE:-docker-database:latest}
CONTAINER=${CONTAINER:-fpm-tap-multipath}
DB_CONTAINER="${CONTAINER}-db"
KEEP="no"
PROFILE=${PROFILE:-release}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
SOCKDIR=$(mktemp -d /tmp/fpm-tap-mp.XXXXXX)

[[ "${1:-}" == "--keep" ]] && KEEP="yes"

ZEBRA_BIN="$repo/target/$PROFILE/zebra-rs"
[[ -x "$ZEBRA_BIN" ]] || { echo "missing $ZEBRA_BIN — cargo build --release -p zebra-rs" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "multipath-tee: leaving containers running (--keep)"
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

# --privileged: `ip netns add` needs to make /run/netns a shared mount,
# which Docker forbids even with CAP_SYS_ADMIN.
docker run -d --name "$CONTAINER" --init \
    --network "container:$DB_CONTAINER" \
    --privileged \
    -v "$SOCKDIR:/var/run/redis" \
    --entrypoint /bin/sleep "$FRR_IMAGE" infinity >/dev/null

# Two point-to-point links, one per peer, so each path has a distinct
# next-hop — the whole point of the test.
A_LOCAL=10.99.1.1; A_PEER=10.99.1.2
B_LOCAL=10.99.2.1; B_PEER=10.99.2.2
SHARED=10.66.0.0/24

echo "multipath-tee: two AS 65002 peers ($A_PEER, $B_PEER) both advertising $SHARED"

docker cp "$ZEBRA_BIN" "$CONTAINER:/usr/bin/zebra-rs" >/dev/null
docker exec "$CONTAINER" mkdir -p /usr/share/zebra-rs/yang
docker cp "$repo/zebra-rs/yang/." "$CONTAINER:/usr/share/zebra-rs/yang/" >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock ping >/dev/null 2>&1 && break
    sleep 0.5
done

# ── two FRR peers, one netns each ───────────────────────────────────
for spec in "a:$A_LOCAL:$A_PEER:10.66.0.1" "b:$B_LOCAL:$B_PEER:10.66.0.2"; do
    IFS=':' read -r name local peer rid <<<"$spec"
    docker exec "$CONTAINER" bash -euo pipefail -c "
ip netns add peer$name
ip link add v-$name type veth peer name vp-$name
ip link set vp-$name netns peer$name
ip addr add $local/24 dev v-$name
ip link set v-$name up
ip netns exec peer$name ip addr add $peer/24 dev vp-$name
ip netns exec peer$name ip link set vp-$name up
ip netns exec peer$name ip link set lo up

# The shared prefix on a dummy, advertised by BOTH peers through
# redistribute connected, so the two announcements are identical apart
# from their next-hop.
#
# A static route would be the obvious way to originate it, and does not
# work: FRR 9+ routes static config through mgmtd/staticd rather than
# zebra.conf, so the line is silently ignored and there is nothing to
# advertise. The dummy is what bgp-tee.sh uses, for the same reason.
#
# NOTE: no backticks anywhere in this block. It lives inside a
# double-quoted docker exec string, so a backtick is command
# substitution on the HOST -- which is how an earlier revision ended up
# running the host ip route and pasting 172.17.0.0/16 into the config.
ip netns exec peer$name ip link add shared type dummy
ip netns exec peer$name ip addr add $rid/24 dev shared
ip netns exec peer$name ip link set shared up

mkdir -p /etc/frr/peer$name /var/run/frr/peer$name
cat > /etc/frr/peer$name/zebra.conf <<EOF
hostname peer$name
EOF
cat > /etc/frr/peer$name/bgpd.conf <<EOF
hostname peer$name
router bgp 65002
  bgp router-id $rid
  no bgp ebgp-requires-policy
  neighbor $local remote-as 65001
  address-family ipv4 unicast
    neighbor $local activate
    redistribute connected
  exit-address-family
EOF
chown -R frr:frr /etc/frr /var/run/frr
ip netns exec peer$name /usr/lib/frr/zebra -N peer$name -A 127.0.0.1 -f /etc/frr/peer$name/zebra.conf -d
sleep 1
ip netns exec peer$name /usr/lib/frr/bgpd -N peer$name -A 127.0.0.1 -f /etc/frr/peer$name/bgpd.conf -d
"
done

# ── zebra-rs, with multipath on ─────────────────────────────────────
cat > "$SOCKDIR/zebra.conf" <<EOF
set system fpm enabled true
set router bgp global as 65001
set router bgp global router-id 10.99.1.1
set router bgp afi-safi ipv4 maximum-paths 64
set router bgp neighbor $A_PEER remote-as 65002
set router bgp neighbor $A_PEER enabled true
set router bgp neighbor $A_PEER afi-safi ipv4 enabled true
set router bgp neighbor $B_PEER remote-as 65002
set router bgp neighbor $B_PEER enabled true
set router bgp neighbor $B_PEER afi-safi ipv4 enabled true
EOF
docker cp "$SOCKDIR/zebra.conf" "$CONTAINER:/tmp/zebra.conf" >/dev/null

echo "multipath-tee: starting fpmsyncd"
docker exec -d "$CONTAINER" bash -c 'fpmsyncd > /tmp/fpmsyncd.log 2>&1'
sleep 2

echo "multipath-tee: starting zebra-rs"
docker exec -d "$CONTAINER" bash -c \
    'RUST_LOG=info zebra-rs --yang-path /usr/share/zebra-rs/yang \
        -c /tmp/zebra.conf > /tmp/zebra-rs.log 2>&1'

echo "multipath-tee: waiting for both sessions and the shared prefix"
for _ in $(seq 45); do
    if docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
        EXISTS "_ROUTE_TABLE:$SHARED" 2>/dev/null | grep -q 1; then
        break
    fi
    sleep 1
done
sleep 3   # let the second path settle in after the first

echo
echo "multipath-tee: kernel route"
docker exec "$CONTAINER" ip route show "$SHARED" 2>&1 || true

echo
echo "multipath-tee: APPL_DB"
docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
    HGETALL "_ROUTE_TABLE:$SHARED" | paste - - | sort || true

nexthop=$(docker exec "$CONTAINER" redis-cli -s /var/run/redis/redis.sock -n 0 \
    HGET "_ROUTE_TABLE:$SHARED" nexthop 2>/dev/null || true)
legs=$(awk -F, '{print NF}' <<<"$nexthop")

echo
echo "multipath-tee: APPL_DB nexthop = '$nexthop' ($legs leg(s))"
if [[ "$legs" -ge 2 && "$nexthop" == *"$A_PEER"* && "$nexthop" == *"$B_PEER"* ]]; then
    echo "PASS — both eBGP next-hops installed and teed as one ECMP route"
    exit 0
fi
echo "FAIL — expected 2 legs ($A_PEER and $B_PEER)"
docker exec "$CONTAINER" bash -c 'echo "--- zebra-rs ---"; tail -30 /tmp/zebra-rs.log' || true
docker exec "$CONTAINER" bash -c 'ip netns exec peera vtysh -N peera -c "show bgp summary" 2>&1 | tail -5' || true
exit 1
