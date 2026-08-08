#!/usr/bin/env bash
#
# Capture a golden FPM trace from SONiC's FRR.
#
# Runs the real `docker-fpm-frr` image from a sonic-buildimage tree, with
# zebra started on exactly the command line SONiC's supervisord uses, and
# `fpm-tap` standing in for `fpmsyncd` on TCP 2620. A scenario script
# then drives routes in through `vtysh`, and the resulting capture is
# copied back out.
#
# The point is fidelity: the bytes recorded here are the specification
# the zebra-rs FPM encoder has to reproduce. Nothing in this rig
# normalizes or reformats them.
#
# Usage:
#   ./capture.sh --scenario scenarios/basic.sh --out ../golden/basic.fpm
#   ./capture.sh --scenario scenarios/basic.sh --out ../golden/basic-nhg.fpm --nhg
#
# Requires: docker, and `docker-fpm-frr:latest` loaded, e.g.
#   docker load < <sonic-buildimage>/target/docker-fpm-frr.gz

set -euo pipefail

IMAGE=${IMAGE:-docker-fpm-frr:latest}
CONTAINER=${CONTAINER:-fpm-tap-rig}
SCENARIO=""
OUT=""
NHG="no"
KEEP="no"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
    sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --out)      OUT="$2";      shift 2 ;;
        # Capture the RTM_NEWNEXTHOP / RTA_NH_ID encoding instead of
        # inline RTA_MULTIPATH. SONiC's docker_init.sh disables next-hop
        # groups by default, so the non-NHG trace is the primary one —
        # but both encodings must be supported, so both get captured.
        --nhg)      NHG="yes";     shift ;;
        # Leave the container running afterwards for poking at by hand.
        --keep)     KEEP="yes";    shift ;;
        -h|--help)  usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[[ -n "$SCENARIO" ]] || { echo "--scenario is required" >&2; usage; }
[[ -n "$OUT" ]]      || { echo "--out is required" >&2; usage; }
[[ -f "$SCENARIO" ]] || { echo "no such scenario: $SCENARIO" >&2; exit 1; }

# Prefer a release build; fall back to debug so the rig works mid-edit.
TAP_BIN=""
for cand in "$here/../../../target/release/fpm-tap" "$here/../../../target/debug/fpm-tap"; do
    [[ -x "$cand" ]] && { TAP_BIN="$cand"; break; }
done
[[ -n "$TAP_BIN" ]] || { echo "build fpm-tap first: cargo build --release -p fpm-tap" >&2; exit 1; }

cleanup() {
    if [[ "$KEEP" == "yes" ]]; then
        echo "rig: leaving container '$CONTAINER' running (--keep)"
    else
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# --init gives us a real PID 1 that reaps children; without it every
# daemon we stop turns into a zombie holding its pidfile, and the next
# run of the rig silently fails to start zebra.
docker run -d --name "$CONTAINER" --init \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --entrypoint /bin/sleep "$IMAGE" infinity >/dev/null

docker cp "$TAP_BIN" "$CONTAINER:/usr/bin/fpm-tap" >/dev/null
docker cp "$SCENARIO" "$CONTAINER:/tmp/scenario.sh" >/dev/null

echo "rig: image=$IMAGE nhg=$NHG scenario=$(basename "$SCENARIO")"

docker exec "$CONTAINER" bash -euo pipefail -c "
# Three dummy links carrying v4 and v6 addresses: enough to produce
# connected routes and to hang single-path, ECMP and v6 nexthops off,
# without needing a routing peer.
for i in 0 1 2; do
    ip link add dum\$i type dummy
    ip addr add 10.0.\$i.1/24 dev dum\$i
    ip -6 addr add 2001:db8:\$i::1/64 dev dum\$i
    ip link set dum\$i up
done
mkdir -p /var/run/frr /var/log/frr
chown -R frr:frr /var/run/frr /var/log/frr /etc/frr

# SONiC's 'separated' config mode removes the integrated frr.conf so each
# daemon reads its own file. Without this, FRR loads /etc/frr/frr.conf
# instead and our fpm settings are silently ignored.
rm -f /etc/frr/frr.conf
echo 'no service integrated-vtysh-config' > /etc/frr/vtysh.conf

cat > /etc/frr/zebra.conf <<EOF
hostname fpm-tap-rig
log stdout
!
$( [[ "$NHG" == "yes" ]] && echo 'fpm use-next-hop-groups' || echo 'no fpm use-next-hop-groups' )
fpm address 127.0.0.1
!
EOF
chown -R frr:frr /etc/frr
"

# Start the tap before zebra so the very first message — zebra's initial
# full-table push — is captured. FPM uses replace semantics and expects a
# complete table dump on every (re)connect, so that first burst is part
# of the contract, not noise.
docker exec -d "$CONTAINER" \
    bash -c 'fpm-tap record --listen 127.0.0.1:2620 --out /tmp/capture.fpm > /tmp/tap.log 2>&1'
sleep 1

# Daemon set and command lines from
# dockers/docker-fpm-frr/frr/supervisord/supervisord.conf.common.j2,
# in the same order supervisord starts them.
#
# mgmtd is not optional: since FRR 9 it owns staticd's YANG config, so
# `ip route ...` from vtysh is delivered to mgmtd, not to staticd — and
# staticd has no -f flag at all any more.
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

# Let the last dataplane events drain before tearing the socket down.
sleep 2
# -x matches the process name exactly. A -f pattern would also match the
# `bash -c` shell running the pkill (its command line contains the
# pattern), so the shell kills itself, returns 137, and set -e aborts the
# rig before the capture is copied out.
docker exec "$CONTAINER" bash -c 'pkill -x zebra || true; sleep 1'
sleep 1

mkdir -p "$(dirname "$OUT")"
docker cp "$CONTAINER:/tmp/capture.fpm" "$OUT" >/dev/null
echo "rig: wrote $OUT"
echo
"$TAP_BIN" stats "$OUT"
