#!/bin/bash
# Tear down the mup-lab topology and processes.
set -x
pkill -x free-ran-ue || true
[ -f /tmp/mupupf_zebra.pid ] && kill "$(cat /tmp/mupupf_zebra.pid)" 2>/dev/null
[ -f /tmp/mupupf_cradle.pid ] && kill "$(cat /tmp/mupupf_cradle.pid)" 2>/dev/null
sleep 1
ip netns del mupran 2>/dev/null
ip netns del mupupf 2>/dev/null
ip netns del mupdn 2>/dev/null
ip link del mrHost 2>/dev/null
ip link del muHost 2>/dev/null
echo "topology down"
