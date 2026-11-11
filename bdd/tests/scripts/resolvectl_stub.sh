#!/bin/sh
# Stands in for `resolvectl` under the BDD suite: the harness names it to
# every zebra-rs it starts (ZEBRA_RESOLVECTL), so that what a daemon would
# tell systemd-resolved is kept here, where a feature can read it, and
# never reaches the host's resolver.
#
# It must not: the suite's daemons run in network namespaces, and
# `resolvectl` sends the system bus an interface index. From a namespace
# that is the index of some other interface on the host.
#
#   resolvectl_stub.sh [--] dns LINK [SERVER…]       as resolvectl
#   resolvectl_stub.sh [--] domain LINK [DOMAIN…]    as resolvectl
#   resolvectl_stub.sh [--] revert LINK              as resolvectl
#   resolvectl_stub.sh status   what is held: `LINK dns …`, `LINK domain …`
#   resolvectl_stub.sh reset    hold nothing, and work
#   resolvectl_stub.sh break    fail every dns, domain and revert
#   resolvectl_stub.sh mend     work again
#
# What is held is kept per network namespace, the one this runs in, so a
# feature's daemon and its steps find the same state without being told
# where it is.
set -eu
ns=$(ip netns identify $$)
if [ -z "$ns" ]; then
    echo "resolvectl_stub: not in a named network namespace" >&2
    exit 1
fi
dir=/tmp/zebra-bdd-resolvectl/$ns

if [ "${1:-}" = "--" ]; then
    shift
fi
verb=${1:-}
[ $# -gt 0 ] && shift

case $verb in
dns | domain | revert)
    if [ -e "$dir/broken" ]; then
        echo "Failed to $verb: the resolver is away" >&2
        exit 1
    fi
    link=$1
    shift
    mkdir -p "$dir"
    case $verb in
    revert)
        rm -f "$dir/$link.dns" "$dir/$link.domain"
        ;;
    *)
        # One empty argument clears the list.
        if [ -z "$*" ]; then
            rm -f "$dir/$link.$verb"
        else
            echo "$*" >"$dir/$link.$verb"
        fi
        ;;
    esac
    ;;
status)
    for file in "$dir"/*.dns "$dir"/*.domain; do
        [ -e "$file" ] || continue
        name=${file##*/}
        echo "${name%.*} ${name##*.} $(cat "$file")"
    done
    echo "status: end"
    ;;
reset)
    rm -rf "$dir"
    ;;
break)
    mkdir -p "$dir"
    : >"$dir/broken"
    ;;
mend)
    rm -f "$dir/broken"
    ;;
*)
    echo "usage: $0 [--] dns LINK [SERVER…] | domain LINK [DOMAIN…] | revert LINK | status | reset | break | mend" >&2
    exit 2
    ;;
esac
