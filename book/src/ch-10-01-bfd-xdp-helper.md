# The XDP/eBPF Data-Plane Helper (`xdp-bfd-echo`)

Two BFD features run partly *outside* the daemon, in the kernel data
plane: the [Echo function](ch-10-00-bfd.md#echo-function) and
[expiration-detection offload](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload)
(`detect-offload`). Both are backed by one helper program,
**`xdp-bfd-echo`** — an XDP/eBPF program with a small userspace loader
that zebra-rs spawns and supervises automatically, one process per
interface that needs it.

This chapter is the operational view: what runs where, what the helper
needs from the system, how its lifecycle works, and what to check when
it doesn't come up. The protocol-facing configuration lives in the
per-protocol BFD chapters; the deeper design rationale (including the
S-BFD / STAMP roadmap the same scaffolding is meant to carry) is in
`docs/design/bfd-sbfd-stamp-xdp-offload-notes.md` in the repository.

## Division of labor

The split follows one rule: **anything that must react to a received
packet at line rate lives in XDP; anything that must originate packets
or run protocol logic lives in userspace.** XDP programs cannot send
packets on their own — they only react — so every transmit path stays
in software, while every receive-side deadline moves into the kernel.

| Function | Where | How |
|---|---|---|
| Echo reflect (peer's Echo, UDP/3785) | XDP | Rewrite in place (MAC swap, TTL/Hop-Limit decrement, IPv6 src/dst swap for FRR-style peers), `XDP_TX` back out the same interface |
| Echo originate (our Echo) | helper userspace | `AF_PACKET` raw socket, self-addressed frames on a jittered timer |
| Echo detection (our returns stop) | XDP + `bpf_timer` | Each return re-arms a per-session kernel timer; expiry fires in softirq |
| Control-packet expiration (`detect-offload`, UDP/3784) | XDP + `bpf_timer` | Each control packet for an Up session re-arms the timer; the frame is **always passed** to the daemon |
| BFD state machine, Poll/Final, negotiation, control TX | zebra-rs | Unchanged — the helper never makes protocol decisions |

The daemon and the helper talk over a one-line-per-message stdin/stdout
protocol: `echo-add <discr> <local> <peer> <tx-us> <mult>` / `echo-del`
and `detect-add <discr> <detect-us>` / `detect-del` go down;
`echo-down <discr>` / `detect-down <discr>` come back when a kernel
timer fires. You never drive this by hand in production, but the verbs
appear in traces and are handy to know when debugging.

## What the helper needs

- **Kernel**: XDP support, and `bpf_timer` (Linux ≥ 5.15) for the two
  detection offloads. The reflect-only path works without `bpf_timer`.
- **Capabilities**: `cap_net_admin,cap_bpf` to load and attach the XDP
  program, plus `cap_net_raw` only if Echo *origination* is used (the
  `AF_PACKET` socket). The packaged `.deb` install grants all three via
  postinstall; a hand-installed binary needs
  `setcap cap_net_admin,cap_bpf,cap_net_raw+ep` (or root).
- **Binary**: resolved in this order —
  `$ZEBRA_XDP_BFD_ECHO_BIN` → `~/.zebra/bin/xdp-bfd-echo` →
  `/usr/sbin/xdp-bfd-echo` (the packaged location).
- **Attach mode**: `$ZEBRA_XDP_BFD_ECHO_MODE` = `auto` (default) |
  `native` | `skb`. `auto` tries native/driver XDP and falls back to
  generic (SKB) mode.

> **Virtual NICs and veth need SKB mode.** On veth pairs and most
> virtual NICs, native XDP *attaches successfully* but frames never
> reach the program — a classic silent failure. Set
> `ZEBRA_XDP_BFD_ECHO_MODE=skb` in labs and VMs. Physical NICs with
> real driver support (mlx5, i40e/ice, ixgbe, …) should use native mode
> for the lowest reflect jitter.

The helper tree lives in `offload/xdp-bfd-echo/` and is **excluded from
the main cargo workspace** — building it needs the nightly toolchain,
`bpf-linker`, and LLVM (see its `README.md`). The packaged build does
this for you; `cargo build` of zebra-rs alone never touches it.

## Lifecycle

The helper is **reference-counted per interface**. The first session on
an interface that needs it — any Echo role, or `detect-offload` —
spawns one process attached to that interface; further sessions share
it; the last one to go away stops it (SIGTERM, which detaches the XDP
program cleanly). A node where neither feature is configured runs no
helper at all.

Everything the helper does is gated on it being **confirmed running**
("honesty gates"):

- A non-zero `Required Min Echo RX Interval` — the promise to loop a
  peer's Echo — is only advertised once the child is up.
- The `detect-offload` watchdog is only armed once the child is up;
  until then (and on any helper death) detection runs in userspace as
  usual, and the stretched backstop timer is restored to normal
  immediately.

So a missing binary, missing capabilities, or an unsupported kernel
never breaks BFD — the affected sessions simply behave as if the
feature were not configured, and the daemon logs why.

## Verifying and troubleshooting

`show bfd peers` tells you per session what the helper is doing:

```
    Detection timeout: 900ms
    Detection runs in: kernel/XDP (900ms)     ← detect-offload armed
    Echo receive interval: 50ms               ← we advertise + reflect
    Echo transmission interval: 50ms          ← we originate
```

`Detection runs in: userspace` with `detect-offload true` configured,
or an Echo interval stuck at `disabled`, means the helper is not up for
that interface. Check in order:

1. **Is the process running?** `pgrep -a xdp-bfd-echo` — one per
   expected interface, with `-i <ifname>` in the arguments.
2. **Binary present and executable** at one of the resolution paths
   above, with the capabilities set (`getcap /usr/sbin/xdp-bfd-echo`).
3. **Attach mode**: on veth/VM NICs, force `skb` (see above). The
   helper's own log line says which mode actually attached.
4. **Kernel support**: `bpf_timer` needs ≥ 5.15; the verifier rejects
   the program on older kernels.
5. **Traces**: `set bfd tracing true` makes the daemon log helper
   spawn/stop, the IPC verbs, and session state changes; the helper
   itself logs to stderr (`RUST_LOG=info`).

The helper can also be run standalone for testing (`xdp-bfd-echo -i
<iface> -m skb`), and the repository ships two self-contained veth
tests that exercise the data plane end to end as root:
`offload/xdp-bfd-echo/scripts/veth-test.sh` (Echo reflect) and
`scripts/veth-detect-test.sh` (the expiration watchdog: streams control
packets, asserts the kernel timer re-arms, then fires after the stream
stops).

## Scope and limits

- **Single-hop sessions only.** The helper attaches per interface;
  multihop ingress is not bound to one (and multihop's TTL floor is
  below the GTSM 255 the watchdog requires). Multihop sessions simply
  keep full userspace behavior.
- **BGP neighbours** are covered via the connected-interface keying
  described in [BGP BFD](ch-02-08-bgp-bfd.md#offloading-expiration-detection):
  the session is keyed by the interface whose subnet covers the
  neighbour, learned from the RIB's interface addresses.
- **IPv4 and IPv6** are both handled by the same program, including
  FRR's peer-addressed IPv6 Echo dialect.
- **No authentication.** If BFD authentication is added in the future,
  authenticated sessions must not be offloaded — XDP cannot verify
  MD5/SHA digests. Today zebra-rs has no BFD auth, so this is moot.
- The same process/scaffolding is designed to grow the **S-BFD**
  (UDP 7784/7785) and **STAMP** (UDP 862) reflectors later; see the
  design notes for that roadmap.
