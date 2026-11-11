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
#   resolvectl_stub.sh history  every dns, domain and revert it was asked
#                               for since the last reset, one a line
#   resolvectl_stub.sh reset    hold nothing, and work
#   resolvectl_stub.sh break [SECONDS]
#                               fail every dns, domain and revert, after
#                               that long if a time is given
#   resolvectl_stub.sh stall    do what dns, domain and revert ask, and
#                               then give no answer
#   resolvectl_stub.sh spoil    fail every dns and domain after dropping
#                               the list it was to replace
#   resolvectl_stub.sh mend     work again
#
# What is held is kept per network namespace, the one this runs in, so a
# feature's daemon and its steps find the same state without being told
# where it is.
#
# As resolved does, it holds an interface's settings and not a name's:
# they are given to the interface the name is then, and `status` shows
# them only while the name is still that interface. One deleted and made
# again under the same name holds nothing.
#
# `spoil` is what resolved does when it cannot add an entry of a new list
# (SetLinkDNS and SetLinkDomains in systemd 255): the list being replaced
# is dropped whole, and then the error is reported. An error is no word
# that nothing changed.
set -eu
ns=$(ip netns identify $$)
if [ -z "$ns" ]; then
    echo "resolvectl_stub: not in a named network namespace" >&2
    exit 1
fi
# Under /run, where only root makes entries: this runs as root at a name
# anybody can predict, and in /tmp another user could have put a link
# there first (the hostname stand-in is kept there for the same reason,
# `hostname_stub_dir` in bdd/src/netns.rs).
dir=/run/zebra-rs-bdd/resolvectl/$ns

# The index of the interface of that name, or nothing.
index_of() {
    cat "/sys/class/net/$1/ifindex" 2>/dev/null || true
}

if [ "${1:-}" = "--" ]; then
    shift
fi
verb=${1:-}
[ $# -gt 0 ] && shift

case $verb in
dns | domain | revert)
    if [ -e "$dir/broken" ]; then
        # A refusal, slow in coming if `break` was given a time. One
        # that has begun is not undone by `mend`.
        wait=$(cat "$dir/broken")
        [ -z "$wait" ] || sleep "$wait"
        echo "Failed to $verb: the resolver is away" >&2
        exit 1
    fi
    link=$1
    shift
    mkdir -p "$dir"
    echo "$verb $link $*" >>"$dir/history"
    index=$(index_of "$link")
    if [ -n "$index" ]; then
        mkdir -p "$dir"
        # What the name's previous interface held went with it.
        if [ "$(cat "$dir/$link.ifindex" 2>/dev/null || true)" != "$index" ]; then
            rm -f "$dir/$link.dns" "$dir/$link.domain" "$dir/$link.ifindex"
        fi
        if [ -e "$dir/spoiled" ] && [ "$verb" != revert ]; then
            rm -f "$dir/$link.$verb"
            echo "Failed to $verb: no room for it" >&2
            exit 1
        fi
        case $verb in
        revert)
            rm -f "$dir/$link.dns" "$dir/$link.domain" "$dir/$link.ifindex"
            ;;
        *)
            echo "$index" >"$dir/$link.ifindex"
            # One empty argument clears the list.
            if [ -z "$*" ]; then
                rm -f "$dir/$link.$verb"
            else
                echo "$*" >"$dir/$link.$verb"
            fi
            ;;
        esac
    fi
    if [ -e "$dir/stalled" ]; then
        # No answer, whatever was or was not done. `exec`, so that what
        # the caller kills at its time limit is the sleep.
        exec sleep 60
    fi
    if [ -z "$index" ]; then
        echo "Failed to resolve interface \"$link\": No such device" >&2
        exit 1
    fi
    ;;
history)
    cat "$dir/history" 2>/dev/null || true
    echo "history: end"
    ;;
status)
    for file in "$dir"/*.dns "$dir"/*.domain; do
        [ -e "$file" ] || continue
        name=${file##*/}
        link=${name%.*}
        [ "$(index_of "$link")" = "$(cat "$dir/$link.ifindex" 2>/dev/null || true)" ] || continue
        echo "$link ${name##*.} $(cat "$file")"
    done
    echo "status: end"
    ;;
reset)
    rm -rf "$dir"
    ;;
break)
    mkdir -p "$dir"
    echo "${1:-}" >"$dir/broken"
    ;;
stall)
    mkdir -p "$dir"
    : >"$dir/stalled"
    ;;
spoil)
    mkdir -p "$dir"
    : >"$dir/spoiled"
    ;;
mend)
    rm -f "$dir/broken" "$dir/stalled" "$dir/spoiled"
    ;;
*)
    echo "usage: $0 [--] dns LINK [SERVER…] | domain LINK [DOMAIN…] | revert LINK | status | history | reset | break [SECONDS] | stall | spoil | mend" >&2
    exit 2
    ;;
esac
