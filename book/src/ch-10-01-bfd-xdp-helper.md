# BFD Offload in the eBPF Data Plane

Two BFD features run partly *outside* the daemon, in the kernel data
plane: the [Echo function](ch-10-00-bfd.md#echo-function) and
[expiration-detection offload](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload)
(`detect-offload`). Both are hosted by the
[eBPF data plane](ch-16-00-ebpf.md) — the `cradle` engine — which
zebra-rs launches and supervises, and drives over gRPC.

This chapter is the operational view: what runs where, what the offload
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
| Echo reflect (peer's Echo, UDP/3785) | engine XDP (`cradle_xdp`) | Rewrite in place (MAC swap, TTL/Hop-Limit decrement, IPv6 src/dst swap for FRR-style peers), `XDP_TX` back out the same interface |
| Echo originate (our Echo) | engine userspace | `AF_PACKET` raw socket, self-addressed frames on a jittered timer |
| Echo detection (our returns stop) | engine XDP + `bpf_timer` | Each return re-arms a per-session kernel timer; expiry fires in softirq |
| Control-packet expiration (`detect-offload`, UDP/3784) | engine XDP + `bpf_timer` | Each control packet for an Up session re-arms the timer; the frame is **always passed** to the daemon |
| BFD state machine, Poll/Final, negotiation, control TX | zebra-rs | Unchanged — the data plane never makes protocol decisions |

The daemon and the engine talk over cradle's gRPC control plane, keyed
by our local BFD discriminator: `ArmBfdEcho` / `DisarmBfdEcho` for the
Echo originator and return detector, `ArmBfdDetect` / `DisarmBfdDetect`
for the control watchdog, and a `WatchBfd` server stream that carries
`echo-down` / `detect-down` back when a kernel timer fires. You never
drive this by hand in production, but the verbs appear in traces and
are handy to know when debugging.

## What the offload needs

- **The engine enabled**: `system ebpf enabled true`. The datapath that
  reflects and originates Echo *is* the eBPF data plane, so BFD offload
  is coupled to it. Interfaces do **not** need an explicit
  `interface <name> ebpf enabled` line — a single-hop `echo-mode` /
  `detect-offload` session
  [auto-attaches its egress interface](ch-16-00-ebpf.md#automatic-port-attach-for-bfd)
  as a data-plane port and releases it when the last such session goes.
- **Kernel**: XDP support, and `bpf_timer` (Linux ≥ 5.15) for the two
  detection offloads. The reflect-only path works without `bpf_timer`.
- **Capabilities**: the engine needs `cap_net_admin,cap_bpf` (plus
  `cap_perfmon`) to load and attach the XDP program, and `cap_net_raw`
  for the Echo originator's `AF_PACKET` socket. The `cradle-rs` package
  grants all of these on `/usr/bin/cradle` via its postinstall.
- **Binary**: `/usr/bin/cradle`, shipped by the `cradle-rs` Debian
  package (a `recommends` of the zebra-rs package). No separate BFD
  helper is installed — the reflector, originator, and watchdogs all
  live inside the engine.
- **Control endpoint**: the driver dials `$ZEBRA_CRADLE_BFD_ENDPOINT`,
  defaulting to `unix:cradle/grpc` — the same per-netns abstract socket
  the rest of zebra-rs uses to reach the engine.

> **Virtual NICs and veth need generic (SKB) mode.** In native/driver
> mode, an `XDP_TX` reflection is only delivered to a peer that also has
> XDP attached, so reflecting off a veth whose far end is a bridge port
> is silently dropped — the session flaps `Up`↔`Down` with
> `Echo Function Failed`. Set `CRADLE_XDP_MODE=skb` (equivalently
> `generic`) in the engine's environment for labs and VMs; the engine
> then re-injects through the stack and reflects regardless of the
> peer. Physical NICs with real driver support (mlx5, i40e/ice, ixgbe,
> …) should stay in native mode for the lowest reflect jitter.

All of the eBPF/XDP code lives in the separate
[cradle-rs](https://github.com/zebra-rs/cradle-rs) repository, which
needs the nightly toolchain, `bpf-linker`, and LLVM to build. `cargo
build` of zebra-rs never touches it, and the packaged builds are
independent.

## Lifecycle

zebra-rs keeps a **per-interface refcount** of sessions that need the
offload — any Echo role, or `detect-offload`. The first one on an
interface asks the engine to attach that port; the last one to go away
releases it (unless an `interface … ebpf enabled` leaf keeps it). The
datapath itself is keyed by discriminator, not by interface; the
refcount only governs *where* the XDP program is attached. A node where
neither feature is configured attaches no BFD port at all.

Everything the offload does is gated on the engine being **confirmed
reachable** ("honesty gates"):

- A non-zero `Required Min Echo RX Interval` — the promise to loop a
  peer's Echo (RFC 5880 §6.8.1) — is only advertised once the driver's
  `WatchBfd` stream is connected.
- The `detect-offload` watchdog is only armed once the engine is up;
  until then detection runs in userspace as usual.

Reachability is **soft**. If the engine restarts or the stream drops,
every offloaded session reverts to userspace detection and its
stretched backstop timer is restored immediately; when the driver
reconnects (2 s backoff), readiness is refreshed and the Echo/detect
reconciles re-run for all active sessions. So a missing engine, missing
capabilities, or an unsupported kernel never breaks BFD — the affected
sessions simply behave as if the feature were not configured, and the
daemon logs why.

## Verifying and troubleshooting

`show bfd peers` tells you per session what the offload is doing:

```
    Detection timeout: 900ms
    Detection runs in: kernel/XDP (900ms)     ← detect-offload armed
    Echo receive interval: 50ms               ← we advertise + reflect
    Echo transmission interval: 50ms          ← we originate
```

`Detection runs in: userspace` with `detect-offload true` configured,
or an Echo interval stuck at `disabled`, means the offload is not up
for that session. Check in order:

1. **Is the engine running?** `show ebpf` — `System ebpf: enabled` and
   `Engine: managed (pid …)`. Without `system ebpf enabled true` there
   is no BFD datapath.
2. **Is the interface a port?** The same `show ebpf` port table should
   list it, labelled `bfd` (auto-attached) or `config,bfd`:

   ```
     Ports:           1 wanted (0 config, 1 bfd), 1 attached
       enp0s7           ifindex 4      vrf 0     bfd         attached
   ```
3. **Binary present with capabilities**: `/usr/bin/cradle`, and
   `getcap /usr/bin/cradle` showing
   `cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw`.
4. **Attach mode**: on veth/VM NICs, force `CRADLE_XDP_MODE=skb` (see
   above). The engine logs which mode actually attached.
5. **Kernel support**: `bpf_timer` needs ≥ 5.15; the verifier rejects
   the program on older kernels.
6. **Traces**: `set bfd tracing true` makes the daemon log the arm /
   disarm RPCs, engine reachability transitions, and session state
   changes; the engine's own output is merged into the zebra-rs log.

## Scope and limits

- **Single-hop sessions only.** The XDP program runs on attached ports;
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
- The same engine and scaffolding are designed to grow the **S-BFD**
  (UDP 7784/7785) and **STAMP** (UDP 862) reflectors later; see the
  design notes for that roadmap.
