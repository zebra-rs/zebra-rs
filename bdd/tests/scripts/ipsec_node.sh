#!/bin/bash
# One IPsec node for the ipsec_s2s BDD feature: charon-systemd plus
# zebra-rs, together inside a PRIVATE MOUNT NAMESPACE with tmpfs over
# /run and /etc/swanctl.
#
# Why the mount namespace: network namespaces do not isolate the
# filesystem, and the strongSwan paths are effectively fixed —
# swanctl's enforced AppArmor profile allows config reads only under
# /etc/swanctl/** and the vici socket only at /run/charon.vici — so
# two nodes on one host would collide on the very same files. Inside
# `unshare -m` every instance sees the stock paths on its own tmpfs,
# which keeps zebra-rs, swanctl AND the AppArmor profiles entirely
# stock. (/var/run resolves through the /run symlink, so zebra-rs's
# default vici path lands on the private tmpfs too.)
#
# Requires charon-systemd and strongswan-swanctl installed on the
# host — see the Makefile target comment.
set -e

NS="$1" # scoped namespace name, e.g. ipsec_s2s_z1

if [ -z "$IPSEC_NODE_INNER" ]; then
    command -v charon-systemd >/dev/null || {
        echo "ipsec_node: charon-systemd not installed on this host" >&2
        exit 1
    }
    export IPSEC_NODE_INNER=1
    exec unshare -m "$0" "$@"
fi

mount -t tmpfs tmpfs /run
mkdir -p /run/lock
mount -t tmpfs tmpfs /etc/swanctl

charon-systemd >"logs/$NS.charon.log" 2>&1 &
echo $! >"/tmp/$NS.charon.pid"
for _ in $(seq 1 50); do
    [ -S /run/charon.vici ] && break
    sleep 0.1
done

# The harness starts zebra-rs itself everywhere else; here the daemon
# must live in this mount namespace, so the wrapper replicates the
# harness argv conventions (pid file, log path, /dev/null config) and
# its stage resolution: PATH already leads with <stage>/bin, and the
# staged YANG tree sits next to it. `--daemon` forks inside the
# namespace, so the daemonized child keeps the private mounts.
ZEBRA="$(command -v zebra-rs)"
YANG="$(cd "$(dirname "$ZEBRA")/../share/zebra-rs/yang" && pwd)"
exec "$ZEBRA" --feature iso --daemon \
    --log-output=file --log-file="logs/$NS.log" \
    --pid-file="/tmp/$NS.pid" -c /dev/null --yang-path "$YANG"
