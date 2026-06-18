#!/usr/bin/env bash
#
# compare-peer-task.sh — A/B convergence benchmark for the two BGP egress
# models, with N=4 incoming RIB shards on both sides.
#
#   peer-task OFF  (default)  →  update-group flush  (FRR coalesce-once-
#                                replicate; one encode fanned to all members)
#   peer-task ON   (gate-on)  →  per-peer egress task (GoBGP per-goroutine;
#                                each peer re-encodes its own egress in parallel)
#
# Scenario (what the user asked for): a large incoming route set blasted by
# several senders is re-advertised ("reflected") to MANY receiver peers — i.e.
# the egress fan-out is the bottleneck under test. Both runs use
# ZEBRA_BGP_SHARDS=4 so the ingress side is identical and only the egress model
# differs.
#
# This is a thin orchestrator over the existing `bgp-bench` load generator
# (tools/bgp-bench): it spins the daemon up in a rootless user+net namespace
# (the README recipe), runs one measurement per config, captures the JSON
# convergence number, and prints a side-by-side verdict. `bgp-bench` itself
# validates correctness — a receiver that never sees the full prefix set makes
# the run exit non-zero ("DID NOT CONVERGE"), so a broken egress model can't
# masquerade as a fast one.
#
# Usage:
#   tools/bgp-bench/compare-peer-task.sh [flags]
#
# Common flags (see --help for the full list):
#   --senders N        injecting eBGP sessions          (default 4)
#   --receivers R      fan-out eBGP sessions ("peers")   (default 16, max 55)
#   --prefixes M       unique /32s per sender            (default 100000)
#   --shards S         incoming RIB shards, both configs (default 4)
#   --reps K           repetitions per config            (default 3)
#   --no-build         use the binaries already in target/release
#
set -euo pipefail

# Absolute path to this script — re-exec'd inside the namespace as `__inner`.
SELF="$(readlink -f "$0")"

# ──────────────────────────────────────────────────────────────────────────
# Inner mode: runs INSIDE the per-run user+net namespace created by `unshare`.
# Everything it needs arrives via BB_* environment variables (unshare keeps the
# parent environment). It starts the daemon, runs one bgp-bench measurement,
# prints the bench's single-line JSON to stdout, and tears the daemon down.
# ──────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "__inner" ]; then
    set +e # capture the bench's exit code rather than aborting on non-zero
    # Only in netns mode do we own (and need to raise) loopback. On the host
    # lo is already up and we lack CAP_NET_ADMIN to touch it.
    [ "${BB_NETNS:-0}" = 1 ] && ip link set lo up

    ZEBRA_BGP_SHARDS="$BB_SHARDS" ZEBRA_BGP_PEER_TASK="$BB_PEER_TASK" \
        "$BB_ZEBRA" --yang-path "$BB_DIR/yang" \
        --vty-socket "unix:$BB_DIR/vty" \
        >"$BB_DIR/daemon.log" 2>&1 &
    dpid=$!

    # The daemon needs a moment to commit the config and open its listener;
    # bgp-bench's establish_retry (20×500ms) absorbs any remaining lag.
    sleep "$BB_WARMUP"

    "$BB_BENCH" run \
        --target "127.0.0.1:$BB_PORT" \
        --senders "$BB_SENDERS" \
        --receivers "$BB_RECEIVERS" \
        --prefixes "$BB_PREFIXES" \
        --attr-buckets "$BB_ATTR_BUCKETS" \
        --quiet-ms "$BB_QUIET_MS" \
        --timeout-secs "$BB_TIMEOUT" \
        --json
    rc=$?

    # Teardown: SIGTERM, brief grace, then SIGKILL so a slow/large daemon
    # shutdown can never wedge the run between configs.
    kill "$dpid" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$dpid" 2>/dev/null || break
        sleep 0.5
    done
    kill -9 "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null
    exit "$rc"
fi

# ──────────────────────────────────────────────────────────────────────────
# Outer mode
# ──────────────────────────────────────────────────────────────────────────

REPO="$(cd "$(dirname "$SELF")/../.." && pwd)"

# Defaults.
SENDERS=4
RECEIVERS=16
PREFIXES=100000
SHARDS=4
ATTR_BUCKETS=16
QUIET_MS=3000
TIMEOUT=600
PORT=1179
REPS=3
WARMUP=3
OUT_POLICY=shared
BUILD=1
BUILD_JOBS=""

usage() {
    cat <<EOF
compare-peer-task.sh — A/B convergence benchmark: BGP peer-task OFF vs ON,
with N=$SHARDS incoming RIB shards on both sides.

Flags:
  --senders N        injecting eBGP sessions (RIB-FIB ratio = N)   [default $SENDERS]
  --receivers R      fan-out eBGP sessions, the "all peers" set     [default $RECEIVERS, max 55]
  --prefixes M       unique /32s each sender advertises            [default $PREFIXES, max 2^24]
  --shards S         ZEBRA_BGP_SHARDS for BOTH configs             [default $SHARDS]
  --attr-buckets B   distinct attribute sets per sender            [default $ATTR_BUCKETS]
  --quiet-ms Q       receiver convergence quiet window             [default $QUIET_MS]
  --timeout-secs T   hard cap per measurement                      [default $TIMEOUT]
  --port P           daemon BGP listen port                        [default $PORT]
  --reps K           repetitions per config (interleaved)          [default $REPS]
  --warmup W         seconds to wait after daemon start            [default $WARMUP]
  --out-policy MODE  egress out-policy on receivers: none|shared|distinct
                       shared   = all receivers in ONE update-group (coalesce)
                       distinct = one update-group per receiver (diverse)
                                                                    [default $OUT_POLICY]
  --build-jobs J     cargo -j J for the release build              [default: cargo default]
  --no-build         skip the build; use target/release as-is
  -h, --help         this message

Output is a side-by-side table (min/median/mean convergence per config) and a
verdict naming the faster egress model. Per-run daemon logs are kept under a
temp results dir whose path is printed at the end.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
    --senders) SENDERS="$2"; shift 2 ;;
    --receivers) RECEIVERS="$2"; shift 2 ;;
    --prefixes) PREFIXES="$2"; shift 2 ;;
    --shards) SHARDS="$2"; shift 2 ;;
    --attr-buckets) ATTR_BUCKETS="$2"; shift 2 ;;
    --quiet-ms) QUIET_MS="$2"; shift 2 ;;
    --timeout-secs) TIMEOUT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --reps) REPS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --out-policy) OUT_POLICY="$2"; shift 2 ;;
    --build-jobs) BUILD_JOBS="$2"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage >&2; exit 1 ;;
    esac
done

ZEBRA="$REPO/target/release/zebra-rs"
BENCH="$REPO/target/release/bgp-bench"

# Preflight.
if [ "$RECEIVERS" -gt 55 ]; then
    echo "error: --receivers must be <= 55 (the 127.0.0.200+ address plan)" >&2
    exit 1
fi
case "$OUT_POLICY" in
none | shared | distinct) ;;
*) echo "error: --out-policy must be none|shared|distinct (got '$OUT_POLICY')" >&2; exit 1 ;;
esac

# Isolation mode. A rootless user+net namespace (the README recipe) is tidiest,
# but it needs unprivileged userns, which many hosts disable. We don't actually
# require it: emit-config sets `no-fib-install`, so the daemon never writes the
# kernel FIB, and every 127.0.0.0/8 source the bench binds is local anyway. So
# probe once and fall back to running the daemon straight on the host loopback.
NETNS=0
if command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; then
    NETNS=1
fi

if [ "$BUILD" = 1 ]; then
    echo ">> building release binaries (zebra-rs + bgp-bench)…" >&2
    if [ -n "$BUILD_JOBS" ]; then
        cargo build --release -p bgp-bench -p zebra-rs -j "$BUILD_JOBS"
    else
        cargo build --release -p bgp-bench -p zebra-rs
    fi
fi
[ -x "$ZEBRA" ] || { echo "error: $ZEBRA missing (drop --no-build, or build it)" >&2; exit 1; }
[ -x "$BENCH" ] || { echo "error: $BENCH missing (drop --no-build, or build it)" >&2; exit 1; }

RESULTS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bgp-bench-compare-XXXXXX")"

# run_one <peer_task 0|1> <run-tag> → echoes the bench JSON; returns bench rc.
run_one() {
    local peer_task="$1" tag="$2"
    local dir="$RESULTS_DIR/$tag"
    mkdir -p "$dir"
    ln -sfn "$REPO/zebra-rs/yang" "$dir/yang"
    "$BENCH" emit-config \
        --senders "$SENDERS" --receivers "$RECEIVERS" --port "$PORT" \
        --out-policy "$OUT_POLICY" \
        >"$dir/zebra-rs.conf"

    local json rc
    # In netns mode re-exec under unshare; on the host run __inner directly.
    local runner=("$SELF" __inner)
    [ "$NETNS" = 1 ] && runner=(unshare -rn "$SELF" __inner)
    if json=$(
        BB_SHARDS="$SHARDS" BB_PEER_TASK="$peer_task" BB_NETNS="$NETNS" \
            BB_ZEBRA="$ZEBRA" BB_BENCH="$BENCH" BB_DIR="$dir" BB_PORT="$PORT" \
            BB_SENDERS="$SENDERS" BB_RECEIVERS="$RECEIVERS" \
            BB_PREFIXES="$PREFIXES" BB_ATTR_BUCKETS="$ATTR_BUCKETS" \
            BB_QUIET_MS="$QUIET_MS" BB_TIMEOUT="$TIMEOUT" BB_WARMUP="$WARMUP" \
            "${runner[@]}"
    ); then
        rc=0
    else
        rc=$?
    fi
    printf '%s\n' "$json" >"$dir/result.json"
    printf '%s' "$json"
    # Host mode reuses port $PORT across runs; let the listener fully close
    # before the next daemon binds it.
    [ "$NETNS" = 1 ] || sleep 1
    return "$rc"
}

# field <json> <key> → numeric value, or empty.
field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9.]*\).*/\1/p"
}
flag() {
    printf '%s' "$1" | sed -n "s/.*\"$2\":\(true\|false\).*/\1/p"
}

echo ">> topology: $SENDERS senders × $PREFIXES prefixes → $RECEIVERS receivers (fan-out), N=$SHARDS shards, $REPS reps" >&2
echo ">> out-policy: $OUT_POLICY (set MED + AS-path-prepend on each receiver)" >&2
echo ">> isolation: $([ "$NETNS" = 1 ] && echo 'rootless user+net namespace' || echo 'host loopback (no userns; no-fib-install daemon)')" >&2
echo ">> results dir: $RESULTS_DIR" >&2

declare -a CONV_OFF=() CONV_ON=() RATE_OFF=() RATE_ON=()
OK_OFF=0 OK_ON=0

for rep in $(seq 1 "$REPS"); do
    for variant in off on; do
        if [ "$variant" = off ]; then pt=0; label="peer-task OFF"; else pt=1; label="peer-task ON "; fi
        echo ">> [rep $rep] $label …" >&2
        json="$(run_one "$pt" "${variant}.rep${rep}")" && rc=0 || rc=$?

        converged="$(flag "$json" converged)"
        conv="$(field "$json" convergence_secs)"
        rate="$(field "$json" unique_prefixes_per_sec)"

        if [ "$rc" = 0 ] && [ "$converged" = true ] && [ -n "$conv" ]; then
            echo "   converged in ${conv}s (${rate} pfx/s)" >&2
            if [ "$variant" = off ]; then
                CONV_OFF+=("$conv"); RATE_OFF+=("$rate"); OK_OFF=$((OK_OFF + 1))
            else
                CONV_ON+=("$conv"); RATE_ON+=("$rate"); OK_ON=$((OK_ON + 1))
            fi
        else
            echo "   DID NOT CONVERGE (rc=$rc) — see $RESULTS_DIR/${variant}.rep${rep}/daemon.log" >&2
        fi
    done
done

# stats <samples…> → "min median mean" (3 decimals), or "- - -" if none.
stats() {
    [ $# -eq 0 ] && { echo "- - -"; return; }
    printf '%s\n' "$@" | sort -g | awk '
        {a[NR]=$1}
        END{
            n=NR; min=a[1];
            med=(n%2)?a[(n+1)/2]:(a[n/2]+a[n/2+1])/2;
            s=0; for(i=1;i<=n;i++)s+=a[i];
            printf "%.3f %.3f %.3f", min, med, s/n;
        }'
}
median() {
    [ $# -eq 0 ] && { echo ""; return; }
    printf '%s\n' "$@" | sort -g | awk '{a[NR]=$1} END{n=NR; print (n%2)?a[(n+1)/2]:(a[n/2]+a[n/2+1])/2}'
}

read -r OFF_MIN OFF_MED OFF_MEAN <<<"$(stats "${CONV_OFF[@]}")"
read -r ON_MIN ON_MED ON_MEAN <<<"$(stats "${CONV_ON[@]}")"
OFF_RATE_MED="$(median "${RATE_OFF[@]}")"
ON_RATE_MED="$(median "${RATE_ON[@]}")"

printf '\n'
printf '════════════════════════════════════════════════════════════════════════\n'
printf ' BGP peer-task A/B benchmark   (N=%s incoming shards, out-policy=%s)\n' "$SHARDS" "$OUT_POLICY"
printf ' topology: %s senders × %s prefixes → %s receivers (fan-out), %s reps\n' \
    "$SENDERS" "$PREFIXES" "$RECEIVERS" "$REPS"
printf '════════════════════════════════════════════════════════════════════════\n'
printf ' %-26s %-10s %-26s %-12s\n' "config" "converged" "conv secs min/med/mean" "pfx/s med"
printf ' %-26s %-10s %-26s %-12s\n' \
    "peer-task OFF (upd-group)" "$OK_OFF/$REPS" "$OFF_MIN / $OFF_MED / $OFF_MEAN" "${OFF_RATE_MED:-–}"
printf ' %-26s %-10s %-26s %-12s\n' \
    "peer-task ON  (per-peer)" "$OK_ON/$REPS" "$ON_MIN / $ON_MED / $ON_MEAN" "${ON_RATE_MED:-–}"
printf '════════════════════════════════════════════════════════════════════════\n'

# Verdict by median convergence (lower = faster).
if [ "$OK_OFF" -gt 0 ] && [ "$OK_ON" -gt 0 ]; then
    awk -v off="$OFF_MED" -v on="$ON_MED" 'BEGIN{
        if (off < on)      { d=(on-off)/on*100;  printf " verdict: peer-task OFF (update-group) is faster — median %.3fs vs %.3fs (%.1f%% quicker)\n", off, on, d }
        else if (on < off) { d=(off-on)/off*100; printf " verdict: peer-task ON  (per-peer)    is faster — median %.3fs vs %.3fs (%.1f%% quicker)\n", on, off, d }
        else               { printf " verdict: tie — median %.3fs both\n", off }
    }'
else
    printf ' verdict: inconclusive — a config failed to converge (see logs)\n'
fi
printf '════════════════════════════════════════════════════════════════════════\n'
printf ' logs: %s\n' "$RESULTS_DIR"
