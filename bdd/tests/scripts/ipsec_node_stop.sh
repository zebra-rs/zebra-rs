#!/bin/bash
# Stop the charon started by ipsec_node.sh. zebra-rs is stopped by
# the regular "I stop zebra-rs" step; pids are host-global even
# though the daemons live in private namespaces. Always exits 0 — the
# "I execute" step treats a non-zero exit as a scenario failure, and
# an already-gone charon is fine at teardown.
NS="$1"
if [ -f "/tmp/$NS.charon.pid" ]; then
    kill "$(cat "/tmp/$NS.charon.pid")" 2>/dev/null
    rm -f "/tmp/$NS.charon.pid"
fi
exit 0
