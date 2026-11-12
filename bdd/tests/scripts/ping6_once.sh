#!/bin/sh
# One echo request to an IPv6 address, and whatever came back for it.
#
#   ping6_once.sh ADDRESS [SOURCE]
#
# For a feature that reads the answer rather than whether there was one:
# `Time exceeded` from a routing loop, `Destination unreachable`, or
# nothing at all. It succeeds either way.
ping -6 -n -c 1 -W 2 ${2:+-I "$2"} "$1" 2>&1 || true
