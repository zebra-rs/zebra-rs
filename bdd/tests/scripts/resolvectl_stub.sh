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
#   resolvectl_stub.sh [--] dns INDEX [SERVER…]      as resolvectl
#   resolvectl_stub.sh [--] domain INDEX [DOMAIN…]   as resolvectl
#   resolvectl_stub.sh [--] revert INDEX             as resolvectl
#   resolvectl_stub.sh status   what is held: `NAME dns …`, `NAME domain …`
#   resolvectl_stub.sh history  every dns, domain and revert it was asked
#                               for since the last reset, one a line, with
#                               the name the interface had then
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
# The interface is said by its index, as zebra-rs says it to
# `resolvectl`, which takes a number in place of a name and uses it as it
# is. A name is refused here, where `resolvectl` would look it up: a
# daemon that said one would pass for right on every interface that kept
# its name, and the suite is to notice.
#
# As resolved does, it holds an interface's settings by that index and
# not by a name. `status` and `history` show the name the index has at
# that moment, so a renamed interface is shown with what it holds under
# its new name, and one deleted and made again under the same name holds
# nothing. An index that is no interface's is shown as `#INDEX` in the
# history, and its command fails as resolved's does for a link it does
# not know.
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

# The name of the interface of that index, or nothing.
name_of() {
    for file in /sys/class/net/*/ifindex; do
        [ -e "$file" ] || continue
        if [ "$(cat "$file" 2>/dev/null || true)" = "$1" ]; then
            file=${file%/ifindex}
            echo "${file##*/}"
            return
        fi
    done
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
    index=$1
    shift
    case $index in
    '' | *[!0-9]*)
        echo "resolvectl_stub: \"$index\" is not an interface index" >&2
        exit 1
        ;;
    esac
    mkdir -p "$dir"
    name=$(name_of "$index")
    echo "$verb ${name:-#$index} $*" >>"$dir/history"
    if [ -n "$name" ]; then
        if [ -e "$dir/spoiled" ] && [ "$verb" != revert ]; then
            rm -f "$dir/$index.$verb"
            echo "Failed to $verb: no room for it" >&2
            exit 1
        fi
        case $verb in
        revert)
            rm -f "$dir/$index.dns" "$dir/$index.domain"
            ;;
        *)
            # One empty argument clears the list.
            if [ -z "$*" ]; then
                rm -f "$dir/$index.$verb"
            else
                echo "$*" >"$dir/$index.$verb"
            fi
            ;;
        esac
    fi
    if [ -e "$dir/stalled" ]; then
        # No answer, whatever was or was not done. `exec`, so that what
        # the caller kills at its time limit is the sleep.
        exec sleep 60
    fi
    if [ -z "$name" ]; then
        echo "Failed to $verb: Link $index not known" >&2
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
        held=${file##*/}
        # Only what an interface that is there holds.
        name=$(name_of "${held%.*}")
        [ -n "$name" ] || continue
        echo "$name ${held##*.} $(cat "$file")"
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
    echo "usage: $0 [--] dns INDEX [SERVER…] | domain INDEX [DOMAIN…] | revert INDEX | status | history | reset | break [SECONDS] | stall | spoil | mend" >&2
    exit 2
    ;;
esac
