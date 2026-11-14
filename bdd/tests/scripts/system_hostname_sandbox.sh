#!/bin/sh
# The REAL system host name under `system hostname` with --feature insomnia:
# sethostname(2) and /etc/hostname, not the stand-in the rest of the BDD
# uses (ZEBRA_HOSTNAME_STUB_DIR, docs/design/system-hostname.md §10).
#
# A network namespace shares the host's UTS namespace and its /etc, so the
# real thing must not run in a BDD namespace as it is. This script builds a
# sandbox first, and nothing in it can reach the machine it runs on:
#
#   - a private UTS namespace: sethostname(2) names the sandbox;
#   - a private mount namespace with an overlay on /etc and a tmpfs on
#     /var/lib: /etc/hostname and the saved-name record land in a scratch
#     directory.
#
# Modes:
#
#   apply   Also a private PID and network namespace, as a container has:
#           PID 1 is the sandbox's own, so zebra-rs IS in "the default
#           network namespace" and must change the name: set, change,
#           delete (the name found comes back), and a restart with the
#           line gone (it comes back again).
#   refuse  The host's PID namespace and a network namespace that is not
#           PID 1's, as every `ip netns exec` daemon has: zebra-rs must
#           leave the name, /etc/hostname and /var/lib alone, and say why.
#
# Run as root (the harness's `I execute` does), with zebra-rs and vtyctl on
# PATH. Exits non-zero, with the reason on stderr, on the first failed check.

set -u

MODE="${1:-}"
VTY="unix:hostname-sandbox/vty"
START="sandbox-host"

fail() {
    echo "system_hostname_sandbox $MODE: $*" >&2
    if [ -n "${SCR:-}" ] && [ -f "$SCR/zebra-rs.log" ]; then
        echo "--- zebra-rs log" >&2
        tail -n 20 "$SCR/zebra-rs.log" >&2
    fi
    exit 1
}

# ── Outside the sandbox ──────────────────────────────────────────────────
case "$MODE" in
apply | refuse)
    SCR=$(mktemp -d /tmp/zebra-hostname-sandbox.XXXXXX) || exit 1
    mkdir -p "$SCR/upper" "$SCR/work"
    before_kernel=$(hostname)
    before_static=$(cat /etc/hostname 2>/dev/null)
    if [ "$MODE" = apply ]; then
        unshare --uts --mount --net --pid --fork --mount-proc "$0" "inner-$MODE" "$SCR"
    else
        unshare --uts --mount --net "$0" "inner-$MODE" "$SCR"
    fi
    rc=$?
    rm -rf "$SCR"
    # Whatever happened inside, this machine keeps its name.
    [ "$(hostname)" = "$before_kernel" ] ||
        fail "the HOST's kernel name changed: $before_kernel -> $(hostname)"
    [ "$(cat /etc/hostname 2>/dev/null)" = "$before_static" ] ||
        fail "the HOST's /etc/hostname changed"
    exit $rc
    ;;
inner-apply | inner-refuse)
    MODE="${MODE#inner-}"
    SCR="$2"
    ;;
*)
    echo "usage: $0 apply|refuse" >&2
    exit 2
    ;;
esac

# ── Inside the sandbox ───────────────────────────────────────────────────
mount -t overlay overlay \
    -o "lowerdir=/etc,upperdir=$SCR/upper,workdir=$SCR/work" /etc ||
    fail "cannot mount an overlay on /etc"
mount -t tmpfs tmpfs /var/lib || fail "cannot mount a tmpfs on /var/lib"
ip link set lo up

# A name of the sandbox's own to start from, so that no check depends on
# what the machine is called.
hostname "$START" || fail "cannot name the sandbox"
echo "$START" >/etc/hostname

# The stand-in must not be what is tested here.
unset ZEBRA_HOSTNAME_STUB_DIR

RECORD=/var/lib/zebra-rs/system/hostname.json
YANG="$(dirname "$(dirname "$(command -v zebra-rs)")")/share/zebra-rs/yang"

# The daemon must not outlive this script, whichever check ends it. In
# `refuse` mode it shares the host's PID namespace, so nothing else would
# stop it: a leaked root daemon, and one holding the caller's output pipe
# open, which keeps the harness's `I execute` step waiting for ever.
ZPID=
trap '[ -n "$ZPID" ] && kill -KILL "$ZPID" 2>/dev/null' EXIT

start_daemon() {
    # daemonize(3)'s umask, which a plain create would turn into an
    # /etc/hostname only root can read.
    umask 027
    if [ -d "$YANG" ]; then
        zebra-rs --feature insomnia --vty-socket "$VTY" -c /dev/null \
            --yang-path "$YANG" \
            --log-output file --log-file "$SCR/zebra-rs.log" \
            </dev/null >/dev/null 2>&1 &
    else
        zebra-rs --feature insomnia --vty-socket "$VTY" -c /dev/null \
            --log-output file --log-file "$SCR/zebra-rs.log" \
            </dev/null >/dev/null 2>&1 &
    fi
    ZPID=$!
    umask 022
    i=0
    until vtyctl --vty-socket "$VTY" show "show version" >/dev/null 2>&1; do
        i=$((i + 1))
        [ $i -ge 40 ] && fail "zebra-rs did not come up"
        sleep 0.5
    done
}

stop_daemon() {
    kill -INT "$ZPID" 2>/dev/null
    wait "$ZPID" 2>/dev/null
    ZPID=
}

apply() {
    out=$(vtyctl --vty-socket "$VTY" apply -c "$1" 2>&1) || fail "vtyctl apply '$1': $out"
    case "$out" in
    *error*) fail "'$1' was refused: $out" ;;
    esac
}

show_hostname() {
    vtyctl --vty-socket "$VTY" show "show hostname" 2>&1
}

# expect <what> <kernel name> <static name | ABSENT> <record: yes | no>
expect() {
    i=0
    while :; do
        kernel=$(hostname)
        static=$(cat /etc/hostname 2>/dev/null || echo ABSENT)
        record=no
        [ -f "$RECORD" ] && record=yes
        [ "$kernel" = "$2" ] && [ "$static" = "$3" ] && [ "$record" = "$4" ] && return 0
        i=$((i + 1))
        [ $i -ge 20 ] &&
            fail "$1: kernel=$kernel static=$static record=$record, expected $2 $3 $4"
        sleep 0.5
    done
}

if [ "$MODE" = apply ]; then
    [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ] ||
        fail "the sandbox is not its own default network namespace"

    start_daemon
    # Nothing configured: nothing to apply, nothing to give back.
    sleep 1
    expect "started unconfigured" "$START" "$START" no

    apply "set system hostname sandbox-r1"
    expect "set sandbox-r1" sandbox-r1 sandbox-r1 yes
    [ "$(uname -n)" = sandbox-r1 ] || fail "uname -n is $(uname -n)"
    [ "$(stat -c %a /etc/hostname)" = 644 ] ||
        fail "/etc/hostname has mode $(stat -c %a /etc/hostname), not 644"
    grep -q "\"static\":\"$START\"" "$RECORD" || fail "the record is $(cat "$RECORD")"
    case "$(show_hostname)" in
    *"not applied"*) fail "show hostname: $(show_hostname)" ;;
    esac

    apply "set system hostname sandbox-r2"
    expect "set sandbox-r2" sandbox-r2 sandbox-r2 yes
    # Still the name found, not the one zebra-rs set first.
    grep -q "\"static\":\"$START\"" "$RECORD" || fail "the record is $(cat "$RECORD")"

    apply "delete system hostname sandbox-r2"
    expect "deleted" "$START" "$START" no

    apply "set system hostname sandbox-r3"
    expect "set sandbox-r3" sandbox-r3 sandbox-r3 yes
    stop_daemon
    expect "stopped" sandbox-r3 sandbox-r3 yes
    # An empty config again: the line went away while zebra-rs was down.
    start_daemon
    expect "restarted without the line" "$START" "$START" no
    stop_daemon

    [ -z "$(find /etc -maxdepth 1 -name '.hostname*')" ] ||
        fail "a temporary file is left in /etc"
else
    [ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] ||
        fail "the sandbox shares PID 1's network namespace"

    start_daemon
    apply "set system hostname sandbox-r1"
    # The commit is in: the daemon names itself.
    i=0
    until show_hostname | grep -q sandbox-r1; do
        i=$((i + 1))
        [ $i -ge 20 ] && fail "the commit did not arrive: $(show_hostname)"
        sleep 0.5
    done
    sleep 2
    expect "set outside the default namespace" "$START" "$START" no
    [ ! -e /var/lib/zebra-rs ] || fail "something was written under /var/lib/zebra-rs"
    [ -z "$(find "$SCR/upper" -type f ! -name hostname)" ] ||
        fail "something was written under /etc: $(find "$SCR/upper" -type f)"
    show_hostname | grep -q "not applied to the system: zebra-rs is not in the default network namespace" ||
        fail "show hostname does not say why: $(show_hostname)"
    # `show hostname` is where the reason is given. The log keeps it at
    # debug, so a daemon run without root every day does not repeat it.
    ! grep -q "system hostname is not applied to the system" "$SCR/zebra-rs.log" ||
        fail "the log repeats why at the default level"
    stop_daemon
fi

echo "system_hostname_sandbox $MODE: ok"
