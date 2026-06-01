# BFD Echo Function — Design & Phasing Plan

Tracks the BFD **Echo function** (RFC 5880 §6.4 / §6.8.5 / §6.8.8 /
§6.8.9 / §6.8.13; RFC 5881 §4 / §6) for zebra-rs.

> ## As-built (supersedes the plan below)
>
> Echo is **implemented**, both halves, offloaded to a per-interface
> XDP/eBPF helper named **`xdp-bfd-echo`** (`offload/xdp-bfd-echo/`,
> built out of the CI workspace; supervised by
> `zebra-rs/src/bfd/reflector.rs`, ref-counted per ifindex):
>
> - **Responder** — the XDP program loops a peer's Echo in the data
>   plane (TTL−−/checksum/MAC-swap/`XDP_TX`); advertised only once the
>   helper is confirmed up.
> - **Originator** — the helper TXes self-addressed Echo from an
>   `AF_PACKET` socket (XDP can't originate); detection is offloaded to a
>   per-session **`bpf_timer`** the XDP program arms on each looped
>   return, firing `Down` + `EchoFunctionFailed` if returns stop. A
>   userspace bootstrap timeout covers the window before the first
>   return arms the timer.
> - **Core model** — `bfd::session::EchoMode {Off,Transmit,Receive,Both}`
>   (advertise ⟺ `Receive|Both`, originate ⟺ `Transmit|Both`, spawn
>   helper ⟺ `≠ Off`). The IPC is a stdin/stdout line protocol
>   (`echo-add`/`echo-del` → helper, `echo-down` → zebra-rs).
> - **Config (OSPF v2+v3 and IS-IS, done)** — `echo-mode
>   {transmit|receive|both}` with FRR-style `echo-transmit-interval` /
>   `echo-receive-interval`, settable at the instance level
>   (`router ospf|isis { bfd {} }`) as a default and overridden per
>   interface *per leaf* (`{Ospf,}LinkBfdConfig::resolve`); instance
>   `enable true` blanket-enables all interfaces, a per-interface
>   `enable false` opts out. There is **no global top-level `bfd {}`**
>   container — BFD spawns eagerly with its first consumer. BGP echo
>   config is the remaining gap (single-hop eBGP only).
>
> Open lab item: verify `bpf_timer`-from-XDP loads on the target kernel.
>
> The original plan (options + open questions, mostly now resolved)
> follows for historical context.

Read this first if you're touching the BFD module (`zebra-rs/src/bfd/`)
with Echo in mind.

## Status (2026-06-01)

**Not implemented, and currently RFC-conformant without it.** Every
session advertises `Required Min Echo RX Interval = 0`
(`session.rs build_packet()` hard-codes it), which tells peers "I will
not loop Echo packets back." Echo is **optional** (§6.1), so this is a
valid, safe state. This doc exists to scope the work *before* committing
to it, because Echo is materially more invasive than the rest of the BFD
work landed this cycle (#1130–#1140).

The rest of RFC 5880 §6.8 is now implemented: async Control, slow-TX
(§6.8.3), Poll Sequences both directions (§6.8.7), GTSM (§6.8.6 + 5881
§5), diagnostics. **Echo is the last §6.8 gap.**

## What the Echo function is

A **second packet stream**, independent of Control packets. The local
system emits Echo packets to **UDP 3785** (RFC 5881 §4), crafted so the
**remote's forwarding plane loops them straight back** — the remote's
BFD logic never sees them. The **sender alone** times the round trip; if
enough Echoes fail to return within `echo-interval × detect-mult`, the
sender sets `SessionState = Down`, `LocalDiag = 2` (Echo Function
Failed) (§6.8.5).

Why it's useful:
- It tests the **actual data-forwarding path** end-to-end, not just the
  peer's control-plane liveness.
- Detection is done entirely by the **sender** — no dependence on the
  peer's BFD scheduling or CPU.
- When Echo is active, the sender SHOULD **raise its Required Min RX
  Interval** so the peer slows its Control stream (§6.4 / §6.8.3) — fast
  detection via Echo, low Control-plane load.

Key properties from the RFC:
- **Single-hop only.** The looped packet must come straight back;
  RFC 5883 (multihop) defines no Echo. So Echo would apply to OSPF /
  IS-IS adjacencies and directly-connected eBGP — **not** the iBGP
  multihop case that drove this cycle's BFD work.
- **Independent per direction** (§6.4). A system may loop back Echoes
  without ever sending its own, and vice-versa. The two halves below are
  fully decoupled.
- **Only sent while Up** (§6.8.9): Echo MUST NOT be transmitted unless
  the session is Up *and* the last Control packet from the peer carried
  a non-zero `Required Min Echo RX Interval`.
- **Packet payload is a local matter** (§5): only the sender ever parses
  a returned Echo, so the contents just need enough to demux back to the
  session. RFC recommends some authentication (Echoes can be spoofed).

## The feasibility problem (why this is hard for us)

Our BFD module today is **pure async UDP sockets** — `bfd_socket_ipv4` /
`bfd_socket_ipv6` build `socket2` UDP sockets, and `network.rs` uses
`recvmsg` / `sendmsg`. Echo does not fit that model:

1. **The loopback (responder) half is a forwarding-plane action, not a
   socket read.** RFC 5881 §4 requires the Echo packet's **destination
   address be chosen so the remote forwards it back**, the **source
   chosen to avoid ICMP/ND Redirects** (SHOULD NOT be on the egress
   subnet, SHOULD NOT be a link-local), and explicitly notes "the above
   requirements may require the bypassing of some common IP-layer
   functionality, particularly in host implementations." A host doesn't
   *route* a packet addressed to itself back out a wire by default. To
   loop arriving Echoes back to their source on UDP 3785 you need a
   dedicated **raw / `AF_PACKET` socket** (or an `iptables`/`tc`/eBPF
   hook) that intercepts, swaps L2/L3 as needed, and re-injects — none of
   which exists in the module.

2. **The sender half needs the same low-level send** plus an independent
   detect timer keyed on returned Echoes, plus the §6.8.5 Down/diag-2
   transition wired into the existing FSM/notify path.

3. **BCP38 / ingress filtering caveat** (RFC 5881 §2): hosts doing
   uRPF / ingress filtering will drop Echoes; the implementation MUST
   ensure ingress filtering is disabled on the Echo interface or
   excepted for Echo. That's an operational + datapath concern.

So Echo is **not** an incremental change to `send_control` / `on_recv`.
It's a new datapath surface (raw socket or BPF reflection) with its own
timers, its own demux, and real interop/operational risk.

## How FRR does it (reference)

FRR's `bfdd` runs Echo over a dedicated socket and crafts the loopback
so the kernel returns the packet. It defaults to **advertising** echo
capability (`Echo receive interval: 50ms` in `show bfd peers`) but keeps
**echo transmission disabled** until `echo-mode` is configured per
peer/profile — exactly what we saw on the wire during this cycle
(`Echo receive interval: 50ms` / `Echo transmission interval: disabled`).
Note: advertising a non-zero echo-rx is a *promise to loop packets
back* — FRR can make that promise because it implements the responder.
**We cannot advertise non-zero until the responder exists**, or we'd be
lying to the peer.

## Architecture options for the loopback responder

The crux is "reflect a UDP/3785 packet back to its source." Options, in
rough order of portability vs. invasiveness:

- **(A) Raw `AF_PACKET` reflect.** A raw socket bound to the BFD
  interface(s) filters UDP/3785, swaps src/dst MAC + IP, and re-injects.
  Most control, most code, must handle v4 + v6 + per-interface.
- **(B) `tc` / eBPF reflect in the kernel.** A small clsact/eBPF program
  on the interface mirrors+swaps 3785 packets. Fast, but adds an eBPF
  toolchain dependency and a southbound to install it — we have `tc`
  southbound nowhere in BFD today.
- **(C) `iptables`/`nftables` REDIRECT-style hairpin.** Fragile, distro-
  dependent, hard to scope per-session; not recommended.
- **(D) Lean on the existing FIB.** zebra-rs already sets
  `net.ipv4.ip_forward=1` / `ipv6 forwarding=1` (`fib/netlink/sysctl.rs`).
  In principle a correctly-addressed Echo (dst = a remote address that
  routes back to us) is forwarded by the kernel without any reflection
  code on *our* side — i.e. we'd be the **sender** relying on the *peer's*
  kernel to loop, and as a responder we'd rely on *our* kernel forwarding.
  This is the least-code path but depends on addressing tricks (§5881 §4)
  and on forwarding being on for the relevant path; needs a real-datapath
  spike to confirm it works against FRR before trusting it.

A spike on **(D)** is the cheapest way to learn whether we need (A)/(B)
at all. If the kernel forwarding path can be made to loop a
properly-addressed Echo, the responder might reduce to "advertise
echo-rx + ensure forwarding/ingress-filtering is right," and the sender
to "craft the addressed Echo + detect returns" — far smaller than a raw
reflector.

## Config surface (when/if built)

Mirror FRR. Since standalone `bfd { … }` config was removed this cycle,
Echo config would live **per-protocol** alongside `bfd { enable; }`:

```
# illustrative — not implemented
router ospf { area 0 { interface eth0 {
  bfd { enable true; echo-mode true; echo-interval 50; }
}}}
```

- `echo-mode` (bool, default false) — enable Echo transmission on this
  attachment. Advertising echo-rx (the responder promise) could be
  gated by a global/per-interface capability flag, defaulting **off**
  until the responder is proven.
- `echo-interval` (ms) — desired Echo tx rate; also the value advertised
  as `Required Min Echo RX Interval`.

## Phasing (if we proceed)

- **Phase 0 — datapath spike (throwaway).** Hand-craft an Echo against a
  FRR peer using option (D); confirm whether the kernel loops it. Decide
  (A)/(B) vs (D). *Gates everything; no production code.*
- **Phase 1 — packet + state vars.** `bfd-packet` already carries
  `required_min_echo_rx_interval` on the wire struct, but the session
  does **not** cache the peer's value today (`Session::handle_packet`
  ignores it — verified: `session.rs` has no `remote_min_echo_rx`
  field). Add `remote_min_echo_rx_us` to `Session`, our own
  `bfd.RequiredMinEchoRxInterval` state var, and the Echo *payload* type
  (a local demux blob, §5). No behaviour change yet.
- **Phase 2 — responder (loopback).** Whichever of (A)/(D) the spike
  picks; advertise non-zero echo-rx **only once this lands** so the
  promise is honest. Single-hop sockets only (3785, GTSM 255).
- **Phase 3 — sender.** Transmit Echoes while Up + peer-echo-rx≠0
  (§6.8.9, with 75–100% jitter), an Echo detect timer, and the §6.8.5
  Down + `EchoFunctionFailed` transition into the existing notify path.
- **Phase 4 — Control-rate backoff.** When Echo is active, raise our
  `Required Min RX Interval` (§6.4) so the peer slows Control; reflect in
  `tx_interval_us` / detection-time math.
- **Phase 5 — show + interop.** `show bfd peers` Echo rows (we already
  print `Echo receive interval`/`Echo transmission interval` as
  `disabled`); validate against FRR `echo-mode` both directions; honor
  the BCP38 caveat (doc + maybe an ingress-filter check/log).

## Open questions

1. Does kernel forwarding (option D) actually loop a correctly-addressed
   Echo against a FRR peer, or do we need a raw/eBPF reflector (A/B)?
   **This decides whether the feature is small or large.**
2. Is Echo even wanted, given it's **single-hop only** and the recent
   work centered on **multihop** BGP? Likely value is OSPF/IS-IS LAN
   adjacencies and directly-connected eBGP.
3. Authentication of Echo payloads (§5 SHOULD) — in scope, or accept the
   spoofing risk initially (GTSM 255 already bounds it to on-link)?
4. Per-protocol config plumbing: which attachments expose `echo-mode`
   first (OSPF? IS-IS?), and do we gate the *responder* advertisement
   separately from the *sender*?

## Recommendation

**Don't build full Echo speculatively.** Start with the **Phase 0
datapath spike** if there's appetite — it's a few hours and decides the
entire cost/shape. If the spike shows option (D) works, a minimal
responder+sender may be tractable; if it needs a raw/eBPF reflector,
weigh that against the single-hop-only value. Until then, the current
`Required Min Echo = 0` state is correct and safe.
