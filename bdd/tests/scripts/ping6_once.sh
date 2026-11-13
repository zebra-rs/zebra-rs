#!/bin/sh
# One echo request to an IPv6 address, and whatever came back for it.
#
#   ping6_once.sh ADDRESS [SOURCE]
#
# The name the IPv6 features know ping_once.sh by: that script takes an
# address of either family.
exec "$(dirname "$0")/ping_once.sh" "$@"
