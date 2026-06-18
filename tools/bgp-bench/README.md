# bgp-bench

Synthetic BGP load generator for zebra-rs convergence benchmarks —
Phase 0 of `docs/design/bgp-rib-sharding-plan.md`. N sender sessions
blast a shared prefix set at the daemon (so the RIB-FIB ratio equals
the sender count), R receiver sessions count the re-advertised routes,
and the headline number is blast-start → last UPDATE at the slowest
receiver.

Wire encoding reuses the daemon's own `bgp_packet` crate
(`UpdatePacket::pop_ipv4`), so the generated traffic is byte-identical
to what zebra-rs itself emits.

## Run

```sh
cargo build --release -p bgp-bench -p zebra-rs

# 1. Stage a bench instance dir: the daemon loads
#    `<yang-dir>/../zebra-rs.conf`, so pair a yang symlink with the
#    generated config (4 senders, 2 receivers, port 1179, MRAI 1s):
mkdir -p /tmp/bench && ln -sfn "$PWD/zebra-rs/yang" /tmp/bench/yang
target/release/bgp-bench emit-config --senders 4 --receivers 2 > /tmp/bench/zebra-rs.conf

# 2. Start the daemon + bench. Root is not required for the BGP-only
#    measurement, but the RIB needs netlink — without CAP_NET_ADMIN,
#    run both inside a user+net namespace:
unshare -rn sh -c '
  ip link set lo up
  target/release/zebra-rs --yang-path /tmp/bench/yang \
      --vty-socket unix:bgp-bench-vty >/tmp/bench/daemon.log 2>&1 &
  sleep 3
  target/release/bgp-bench run --target 127.0.0.1:1179 \
      --senders 4 --receivers 2 --prefixes 100000
'
```

(With root or an already-running daemon, skip the `unshare` wrapper
and just point `--target` at it.)

## Knobs

| Flag | Meaning |
|---|---|
| `--senders N` | parallel eBGP sessions advertising the same prefix set (RIB-FIB ratio = N) |
| `--receivers R` | eBGP sessions counting re-advertisements (fan-out load) |
| `--prefixes M` | unique /32s carved from 10/8 (max 2^24) |
| `--attr-buckets B` | distinct attribute sets per sender (MED varies); controls UPDATE packing |
| `--quiet-ms Q` | receiver declares convergence after the expected count arrived and the line stayed quiet this long |
| `--json` | machine-readable single-line result |

The reported `convergence` excludes the quiet window (it is the time
of the **last announce**, not the time the window expired). Receivers
may legitimately count more announces than `--prefixes`: a best-path
flip between two senders' paths mid-ingest re-advertises the prefix.

## Daemon-side notes

- `emit-config` sets `router bgp timer adv-interval {ibgp,ebgp}: 1`
  so MRAI debounce quantization (defaults 5s/30s) stays out of the
  measurement. (A separate ~1s flush/settle floor remains on the
  update-group path, so keep the prefix count large enough that real
  work dominates it — see the comparison below.)
- `emit-config` marks every neighbor `transport passive-mode true`: the
  daemon then only **accepts**, and the bench is always the dialer.
  Without this the daemon *also* dials each neighbor on port 179, and
  that outbound attempt collides with the bench's inbound session (BGP
  §6.8 collision resolution), resetting sessions once more than a
  handful of receivers are configured.
- Senders drain and discard everything the daemon re-advertises to
  them, so daemon-side writers never stall on a full TCP window.

## Egress out-policy (`--out-policy`)

`emit-config --out-policy {none|shared|distinct}` attaches an outbound
policy (permit-all, `set med` + `as-path-prepend`) to every **receiver**,
so the egress out-policy *build* — the per-peer attribute work the egress
models differ on — is on the measured path (default `none`).

- `shared` — one policy on all receivers ⇒ they fall in **one**
  update-group. Coalescing-favorable (the route-reflector shape).
- `distinct` — a distinct policy per receiver ⇒ **one update-group each**.
  Neither model can coalesce, so per-peer parallel build is free to win.

## peer-task vs update-group comparison

`compare-peer-task.sh` is an A/B harness over this tool. It runs one
measurement per egress model — both with `ZEBRA_BGP_SHARDS=4` so only the
egress side differs — and prints a side-by-side verdict:

| | gate | egress model |
|---|---|---|
| peer-task **OFF** (default) | `ZEBRA_BGP_PEER_TASK` unset | update-group flush — FRR coalesce-once-replicate |
| peer-task **ON** | `ZEBRA_BGP_PEER_TASK=1` | per-peer egress task — GoBGP per-goroutine, parallel re-encode |

```sh
# Large incoming table (4 senders × 200k prefixes) reflected to 16
# receiver peers, N=4 incoming shards, shared out-policy, 3 reps:
tools/bgp-bench/compare-peer-task.sh \
    --senders 4 --receivers 16 --prefixes 200000 --shards 4 \
    --out-policy shared --reps 3

# The diversity case (each receiver its own update-group):
tools/bgp-bench/compare-peer-task.sh ... --out-policy distinct
```

It spins the daemon up in a rootless user+net namespace when
unprivileged userns is available, else straight on the host loopback
(the `no-fib-install` daemon needs no `CAP_NET_ADMIN`). `bgp-bench`
itself validates correctness: a receiver that never sees the full prefix
set makes the run report "DID NOT CONVERGE", so a broken egress model
cannot masquerade as a fast one. Per-run daemon logs and `result.json`
are kept under the printed results dir.

Run it large: at small prefix counts the update-group path's ~1s flush
floor dominates and the comparison is meaningless. Keep the work-time
well above ~1s (≥ ~100k prefixes) so the numbers reflect real egress
work, not the timer.

Measured results and analysis live in
`docs/design/bgp-peer-task-bench.md`.

## Flamegraph recipe

```sh
# Build with symbols (release profile already keeps them via
# `debug = true`; if not, set CARGO_PROFILE_RELEASE_DEBUG=true).
perf record -F 997 -g -p "$(pgrep -x zebra-rs)" -- sleep 30 &
target/release/bgp-bench run ... # the measurement window
perf script | inferno-collapse-perf | inferno-flamegraph > bgp-flame.svg
```

`perf` needs `kernel.perf_event_paranoid <= 2` for same-user
processes (or root). Record results in
`docs/design/bgp-rib-sharding-plan.md` §9 with the machine specs.
