#!/bin/sh
# One echo request to an address of either family, and whatever came
# back for it.
#
#   ping_once.sh ADDRESS [SOURCE]
#
# For a feature that reads the answer rather than whether there was one:
# `Destination Host Unreachable`, `Destination unreachable: No route`,
# `Time exceeded`, or nothing at all. It succeeds either way.
ping -n -c 1 -W 2 ${2:+-I "$2"} "$1" 2>&1 || true
