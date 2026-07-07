# BGP Fast External Failover — Design

IOS-XR-parity `fast-external-failover` for zebra-rs: when the interface
carrying a **directly connected eBGP** session goes operationally down,
reset the session **immediately** instead of waiting for the hold timer
(typically 90–180 s) to expire. On by default, disable-able globally —
exactly IOS-XR's `bgp fast-external-fallover disable` (XR spells it
"fallover"; FRR and this design spell it `fast-external-failover`).

## Status (2026-07-02)

**PR 1 (knob + failover core, unit tests, book chapter) merged
(#1713); PR 2 (BDD feature, validated live: both the admin-down and
the carrier-down side reset and recover) implemented on branch
`fast-external-failover-bdd`.** Only the listed follow-ups remain
open. Original recon, kept for context:
before PR 1, no `fast-external`/`fast_external` symbol existed
anywhere in the tree, and BGP **silently discarded link events** —
`process_rib_msg` has no arm for `RibRx::LinkUp/LinkDown/LinkDel`; they
fall through the `_ => {}` catch-all at `zebra-rs/src/bgp/inst.rs:3388`.
An eBGP link cut is therefore detected only by hold-timer expiry (or an
eventual TCP error). Every other piece of plumbing already exists; this
feature is essentially "stop dropping `LinkDown` on the floor."

## Prior art

### IOS-XR

```
router bgp 65000
 bgp fast-external-fallover disable
```

Default **enabled**: "the BGP session of neighbors that are directly
connected through an interface is immediately reset if the link goes
down." The knob is global-only (no per-neighbor form in XR; classic IOS
has a per-interface `ip bgp fast-external-fallover permit|deny`, out of
scope here).

### FRR (`bgpd/bgp_zebra.c:bgp_ifp_down`, flag `BGP_FLAG_NO_FAST_EXT_FAILOVER`)

```c
/* Fast external-failover */
if (!CHECK_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER)) {
        for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
                /* Take down directly connected peers. */
                if ((peer->ttl != BGP_DEFAULT_TTL)
                    && (peer->gtsm_hops != BGP_GTSM_HOPS_CONNECTED))
                        continue;
                if (ifp == peer->nexthop.ifp) {
                        BGP_EVENT_ADD(peer->connection, BGP_Stop);
                        peer_set_last_reset(peer, PEER_DOWN_IF_DOWN);
                }
        }
}
```

Facts to carry over:

- **Eligibility is TTL-based**: single-hop peers (TTL 1) plus GTSM
  connected (`gtsm_hops == 1`). iBGP is skipped implicitly (its TTL is
  255). `ebgp-multihop` opts a peer out.
- **Match by session interface** (`peer->nexthop.ifp`, resolved when the
  session came up), not by re-deriving reachability.
- **Reset = `BGP_Stop`, no NOTIFICATION** (the link is down; nothing
  would be delivered anyway). Reset reason recorded as
  `PEER_DOWN_IF_DOWN` ("Interface down").
- Address-delete does **not** reset sessions — only interface-down does.
- CLI: `bgp fast-external-failover` / `no bgp fast-external-failover`,
  default enabled.

## What zebra-rs already has (recon, file:line)

- **RIB → protocol link events.** `RibRx::LinkDown(u32)` /
  `LinkUp(u32)` / `LinkDel(u32)` exist (`zebra-rs/src/rib/api.rs:94`),
  are emitted VRF-filtered to every subscriber
  (`api_link_down`, `rib/api.rs:318`) from the netlink flap detector
  (`rib/link.rs:518-548`) via `rib/route.rs:252 link_down()`. BGP's
  event loop already drains the channel
  (`bgp/inst.rs:4394 process_rib_msg`) — it just has no `LinkDown` arm.
- **Ordering guarantee that makes matching easy:** on a flap the RIB
  emits `RibRx::LinkDown` *first*, then withdraws connected routes; it
  does **not** emit `AddrDel` (addresses are usually retained on down —
  `keep_addr_on_down`, `rib/link.rs:565`). So when BGP processes
  `LinkDown`, its `ConnectedSubnets` table still maps the peer address
  to the downed ifindex. This is also why keying the feature off
  `AddrDel`/`refresh_connected` would *miss* link-down entirely.
- **Peer ↔ interface resolution.**
  - Unnumbered/interface peers: `PeerOrigin::Interface { ifindex }`
    (`bgp/peer_key.rs:33`), addressable via
    `PeerKey::Interface(ifindex)`.
  - v6 link-local numbered peers: `Peer.scope_id: Option<u32>`
    (`bgp/peer.rs:758`).
  - Ordinary address peers: `ConnectedSubnets::ifindex_for(ip)`
    (`bgp/connected.rs:92`), maintained from `AddrAdd/AddrDel`.
- **Single-hop classification.** `Peer::session_ttl()`
  (`bgp/peer.rs:1200`): iBGP/GTSM ⇒ 255, else
  `ebgp_multihop.unwrap_or(1)`. zebra-rs GTSM (`ttl-security`,
  `zebra-bgp-transport.yang:112`) is **connected-only by design** (no
  `hops <N>`), i.e. exactly FRR's `BGP_GTSM_HOPS_CONNECTED` case — so
  "eBGP && no ebgp-multihop" is the complete FRR-parity eligibility
  test. Do **not** reuse `connected_check_applies()`
  (`bgp/peer.rs:1218`) here: it also excludes `disable-connected-check`
  and link-local peers, which FRR *does* fail over.
- **The teardown primitive.** `Message::Event(ident, Event::Stop)` on
  `bgp.tx` → `fsm_stop` (`bgp/peer.rs:1779`, returns `Idle`, **no
  NOTIFICATION**) → the Established→Idle transition in `fsm()`
  (`bgp/peer.rs:1629`) runs `route_clean`, withdraws update-group /
  egress-task membership, and `timer::update_timers`
  (`bgp/timer.rs:206`) tears the socket down and re-arms the idle-hold
  timer (which fires `Event::Start` → auto-reconnect with backoff).
  This is precisely what BFD-down already does
  (`bgp/inst.rs:5229 process_bfd_event`, RFC 5882 §5) and what
  `clear bgp … hard` does (`bgp/peer.rs:3214`). Fast external failover
  is "BFD-down, triggered by `RibRx::LinkDown` instead."
- **Post-reset behavior needs nothing new.** After Stop→Idle the
  idle-hold timer re-dials; if the link is still down the dial fails
  fast (ENETUNREACH → retry) or, if addresses were also removed,
  `fsm_start`'s connected-check gate holds the peer in `Active` until
  `refresh_connected()` (`bgp/inst.rs:2920`) re-kicks it on `AddrAdd`.

## Design

### Semantics (IOS-XR / FRR parity)

- **Scope:** per-BGP-instance, global knob. Applies to sessions whose
  transport rides the downed interface *and* whose peer is
  **single-hop eBGP**: `is_ebgp() && ebgp_multihop.is_none()`. This
  includes `ttl-security` (GTSM ⇒ directly connected in zebra-rs) and
  `disable-connected-check` peers, unnumbered interface peers, and
  dynamic peers; it excludes iBGP and `ebgp-multihop` peers.
- **Default: enabled.** Disabling requires explicit config, like XR.
- **Trigger:** `RibRx::LinkDown` (operational down) and `RibRx::LinkDel`
  (interface removed). **Not** `AddrDel` (FRR parity; address events
  keep their existing `refresh_connected` role of gating *new* dials).
- **Action:** post `Event::Stop` — full hard reset (route_clean, TCP
  close, Idle, idle-hold auto-reconnect). **No NOTIFICATION** is sent:
  `fsm_stop` emits none, matching FRR's interface-down path, and the
  link is down so a Cease couldn't be delivered anyway.
- **Config flips do not bounce sessions.** The knob only changes how a
  *future* link-down is handled (unlike `disable-connected-check`,
  which bounces on change). Nothing to reconcile at commit time.
- **Bonus (small, recommended):** on `RibRx::LinkUp`, kick matching
  non-Established eligible peers with `Event::Start` so reconvergence
  after the flap doesn't wait out the connect-retry backstop (up to
  120 s). FRR gets this for free via NHT; we get it in three lines.

### YANG schema

Mirror the existing global boolean `no-fib-install` — a plain leaf in
the ietf-bgp `container global`
(`zebra-rs/yang/ietf-bgp@2023-07-05.yang:293`, add next to
`no-fib-install` at :329). No new module, no `config.yang` import, and
the config path comes out as `/router/bgp/global/fast-external-failover`.

> **Update (post-landing):** `fast-external-failover`, `hostname` and
> `no-fib-install` were later hoisted out of the `global` container to be
> direct children of `bgp`, so the CLI is now `router bgp
> fast-external-failover ...` and the config path is
> `/router/bgp/fast-external-failover` (likewise
> `/router/bgp/{hostname,no-fib-install}`). `as` and `router-id` stay
> under `global`. The handlers are otherwise unchanged; the `global {`
> CLI/YAML examples and the callback path below reflect the original
> layout.

```yang
leaf fast-external-failover {
  type boolean;
  default "true";
  description
    "When true (the default), immediately reset the session of any
     directly connected (single-hop) eBGP neighbor whose interface
     goes operationally down, instead of waiting for the hold timer
     to expire. Single-hop means the session TTL is 1 or the
     neighbor uses ttl-security (GTSM, directly connected by
     definition); neighbors configured with ebgp-multihop and all
     iBGP neighbors are unaffected. Setting this to false restores
     hold-timer-only failure detection, equivalent to IOS-XR
     'bgp fast-external-fallover disable' and FRR
     'no bgp fast-external-failover'.";
}
```

*Alternative considered:* a dedicated `zebra-bgp-fast-external-failover.yang`
augment module (the `zebra-bgp-transport.yang` pattern). Rejected for
v1 — that pattern earns its keep for multi-leaf feature groups and
per-neighbor knobs; a single global boolean sits naturally beside
`no-fib-install`, and one file beats four (module + 2 augments +
import).

### CLI sample config

```
router bgp {
  global {
    as 65001;
    router-id 10.255.0.1;
    fast-external-failover false;   # disable; absent/true = enabled (default)
  }
  neighbor 10.107.0.2 {
    remote-as 65002;
    afi-safi ipv4 {
      enabled true;
    }
  }
}
```

BDD / `vtyctl apply` YAML form:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
      fast-external-failover: false
```

Book doc table row (`book/src/` BGP chapter, mirror the
`no-fib-install` row):

```
| /router/bgp/global/fast-external-failover | true | Reset directly connected eBGP sessions immediately on interface down |
```

### CLI handler

State: one field on `Bgp` (`zebra-rs/src/bgp/inst.rs:641`), initialized
`true` (`inst.rs:1159` block):

```rust
/// IOS-XR `bgp fast-external-fallover` (default on): reset directly
/// connected eBGP sessions immediately on RibRx::LinkDown instead of
/// waiting for hold-timer expiry.
pub fast_external_failover: bool,
```

Handler in `zebra-rs/src/bgp/config.rs`, next to
`config_global_no_fib_install` (:71). One asymmetry vs `no-fib-install`:
this knob defaults **true**, so `Delete` must restore `true`, not
`false`, and a missing value token on delete must not early-return into
stale state:

```rust
fn config_global_fast_external_failover(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    // Default-on knob: `set … false` disables; delete restores the default.
    let flag = args.boolean().unwrap_or(true);
    bgp.fast_external_failover = !op.is_set() || flag;
    Some(())
}
```

Registration in `callback_build` (`config.rs:3899` block):

```rust
self.callback_add(
    "/router/bgp/global/fast-external-failover",
    config_global_fast_external_failover,
);
```

Plus the two standing guards every new knob gets:

- schema-path parse-settability test in
  `zebra-rs/src/config/manager.rs` (:2712-2917 block, mirror the
  `ip-transparent` case);
- a `#[tokio::test]` in `config.rs` asserting set-false/delete/set-true
  transitions of `bgp.fast_external_failover` (mirror
  `disable_connected_check_toggles_field_and_bounces_live_session`
  minus the bounce — assert the knob does *not* bounce sessions).

### Apply logic

**1. Stop discarding link events.** In `process_rib_msg`
(`bgp/inst.rs:3124`), ahead of the `_ => {}` catch-all:

```rust
RibRx::LinkDown(ifindex) | RibRx::LinkDel(ifindex) => {
    self.link_down_failover(ifindex);
}
RibRx::LinkUp(ifindex) => {
    self.link_up_kick(ifindex);
}
```

**2. Peer-side predicates** (in `bgp/peer.rs`, next to
`connected_check_applies` at :1218):

```rust
/// Whether fast-external-failover governs this peer: single-hop eBGP.
/// FRR parity (`bgp_ifp_down`): default TTL-1 eBGP and GTSM
/// (`ttl-security` — connected-only in zebra-rs) participate;
/// `ebgp-multihop` opts out; iBGP (TTL 255) never participates.
/// Deliberately NOT `connected_check_applies()`: that also exempts
/// `disable-connected-check` and link-local peers, which FRR does
/// fail over.
pub fn fast_failover_applies(&self) -> bool {
    self.is_ebgp() && self.config.transport.ebgp_multihop.is_none()
}

/// The interface this peer's session rides, as far as it can be
/// determined at link-down time (FRR caches `peer->nexthop.ifp` at
/// establish; we resolve live — see "edge cases" in the design doc).
pub fn session_ifindex(&self, subnets: &ConnectedSubnets) -> Option<u32> {
    match self.origin {
        PeerOrigin::Interface { ifindex } => Some(ifindex),
        _ => self
            .scope_id // v6 link-local numbered peer
            .or_else(|| subnets.ifindex_for(self.address)),
    }
}
```

**3. The failover sweep** (in `bgp/inst.rs`, next to
`refresh_connected` at :2920; shape copied from `process_bfd_event` at
:5229):

```rust
/// RibRx::LinkDown/LinkDel handler — RFC-agnostic fast external
/// failover (IOS-XR `bgp fast-external-fallover`, on by default).
/// Hard-resets every non-Idle single-hop eBGP peer whose session
/// rides the downed interface. No NOTIFICATION (fsm_stop sends
/// none; the link is down). The idle-hold timer re-dials.
fn link_down_failover(&mut self, ifindex: u32) {
    if !self.fast_external_failover {
        return;
    }
    let victims: Vec<_> = self
        .peers
        .iter_all() // NOT iter(): that skips interface peers
        .filter(|(_, p)| p.state != State::Idle)
        .filter(|(_, p)| p.fast_failover_applies())
        .filter(|(_, p)| p.session_ifindex(&self.connected_subnets) == Some(ifindex))
        .map(|(_, p)| (p.ident, p.address))
        .collect();
    for (ident, addr) in victims {
        tracing::warn!(
            "fast-external-failover: interface {ifindex} down — resetting eBGP peer {addr}"
        );
        let _ = self.tx.try_send(Message::Event(ident, Event::Stop));
    }
}

/// RibRx::LinkUp — re-kick eligible peers parked by an earlier
/// failover so reconvergence doesn't wait out connect-retry.
fn link_up_kick(&mut self, ifindex: u32) {
    let kicks: Vec<_> = self
        .peers
        .iter_all()
        .filter(|(_, p)| matches!(p.state, State::Idle | State::Active))
        .filter(|(_, p)| p.session_ifindex(&self.connected_subnets) == Some(ifindex))
        .map(|(_, p)| p.ident)
        .collect();
    for ident in kicks {
        let _ = self.tx.try_send(Message::Event(ident, Event::Start));
    }
}
```

Notes on the sweep:

- **Skip `Idle`.** Stop on an Idle peer is a no-op (`fsm()`
  early-returns on `prev == new`), so filtering is just noise
  avoidance. Every other state (Connect/Active/OpenSent/OpenConfirm/
  Established) transitions cleanly to Idle with full teardown.
- **`iter_all()`, not `iter()`** — `PeerMap::iter()` skips
  interface-keyed peers, which are exactly the peers most obviously
  governed by an interface-down.
- **VRF instances work for free**: the RIB fans `LinkDown` out
  VRF-filtered (`client_registry.iter_vrf`), so each per-VRF BGP
  instance only ever sees its own interfaces.
- **Dynamic peers** are address-keyed and matched via `ifindex_for`
  like static ones; their teardown path is the normal FSM one.

### Edge cases & deliberate simplifications

1. **Live ifindex resolution vs FRR's cached `nexthop.ifp`.**
   *Closed by the follow-up:* `Peer.session_ifindex` is snapshotted on
   the transition into Established (from
   `Peer::resolve_session_ifindex`, which prefers the session's
   **local** socket address — a v6 scope-id directly, else the
   connected subnet the local address sits on) and cleared when the
   session ends; the link-down sweep consults it before live
   resolution. An established session now survives `AddrDel`
   reordering. Live resolution remains the fallback for
   never-established peers.
2. **Peer address covered by two connected subnets on different
   interfaces** (parallel links): *closed by the same follow-up* for
   established sessions — the local socket address is unambiguous per
   link. Non-established peers still fall back to first-match
   `ifindex_for` on the peer address.
3. **GTSM iBGP.** FRR technically fails over a directly connected GTSM
   *iBGP* peer; we scope to eBGP only — the feature is named
   *external*, XR documents "directly adjacent **external** peers",
   and zebra-rs GTSM on iBGP is uncommon. Noted, not a bug.
4. **`LinkDel` is treated as `LinkDown`.** Permanent removal implies
   operational down; the peer parks in Active/Idle-hold and, for
   interface peers, existing `LinkAdd` rematerialization brings it back
   if the interface reappears.
5. **No reset-reason bookkeeping yet.** `Peer` has no `last_reset`
   field today, so "Interface down" as a `show bgp neighbors`-visible
   reset reason (FRR's `PEER_DOWN_IF_DOWN`) is out of scope; the
   `tracing::warn!` line is the v1 observability. A general
   last-reset-reason field is a worthwhile standalone follow-up (it
   would also serve BFD-down, hold-timer, collision, …).

### Testing

**Unit (config.rs / inst.rs, `cargo test -p zebra-rs`):**

- knob transitions: default `true`; `set false` → `false`; `delete` →
  `true`; no session bounce on flip.
- sweep selection: build an instance with (a) single-hop eBGP peer on
  ifindex 3, (b) `ebgp-multihop 2` eBGP peer on ifindex 3, (c) iBGP
  peer on ifindex 3, (d) single-hop eBGP peer on ifindex 4 — feed
  `RibRx::LinkDown(3)`, assert exactly (a) got `Event::Stop`; repeat
  with the knob off, assert nobody did.
- `session_ifindex`: interface-origin peer, scope_id peer,
  connected-subnet peer, unresolvable peer.
- manager.rs parse-settability guard for the new path.

**BDD (`bdd/tests/features/bgp_fast_external_failover.feature`):**

Two namespaces (z1, z2), one veth pair (feature-unique names), direct
eBGP 10.107.0.1/24 ↔ 10.107.0.2/24, AS 65001/65002, default timers
(hold 90). Note downing *either* veth end drops carrier on both — fine
for both scenarios.

- *Scenario: failover enabled (default)* — establish (settle ~10 s per
  the session-timing house rule), `ip link set <veth> down` in z1,
  assert z1's neighbor leaves `Established` within ~5 s (≪ hold time).
- *Scenario: failover disabled* — apply `fast-external-failover: false`
  on both, re-establish, link down, wait 10 s, assert **still**
  `Established` on both (hold timer hasn't expired; TCP retransmits
  silently — this is the discriminating assertion that the knob works).
- *Scenario: recovery* — link back up (enabled case), assert
  re-`Established` well under connect-retry (exercises `link_up_kick`).
- *Scenario: Teardown topology* — stop zebra-rs in each namespace,
  delete namespaces, assert clean environment (house rule; mirror
  `bgp_allowas_in.feature`).

BDD doc page `bdd/docs/bgp_fast_external_failover.md` mirroring
`bgp_disable_connected_check.md`.

## Phasing

Smallest-first; each lands green on its own.

- **PR 1 — knob + failover core.** YANG leaf, `Bgp` field, config
  handler + registration, `LinkDown/LinkDel` arm + `link_down_failover`
  + peer predicates, `LinkUp` kick, unit tests, manager.rs guard, book
  table row. This is the whole IOS-XR-parity feature.
- **PR 2 — BDD.** Feature file + configs + doc page as above.
- **Follow-ups (separate, optional):**
  - cached `session_ifindex` at Established — **done** (closes edge
    cases 1–2; snapshot in the `became_established` block of
    `process_msg`, keyed off `PeerParam::local_addr`);
  - `Peer.last_reset` reason plumbed into `show bgp neighbor` —
    **done**: initiators park a `PeerDownReason` on the peer
    (failover → `InterfaceDown`, BFD → `BfdDown`, hard clear →
    `AdminReset`) and the FSM stamps `last_reset` on leaving
    Established, deriving the cause from the event when nothing is
    parked (hold-timer, NOTIFICATION, TCP fail, update error;
    unattributed `Stop` = config bounce). Shown as
    `Last reset <elapsed>, due to <reason>` (text + JSON);
  - per-neighbor override via `InheritableKnobs` (classic-IOS-style
    granularity; XR itself has none — only add on real demand).

## Open questions

1. Should `LinkUp` also re-kick peers that were *not* reset by us
   (e.g. parked by the connected-check gate)? The sketch above kicks
   any Idle/Active peer on that interface — harmless (`fsm_start`
   re-runs its own gates) and simpler than tracking "who we downed".
   Recommend yes as sketched.
2. Is `warn!` the right log level for a triggered failover? It's an
   expected, correct reaction to a link event — `info!` may fit the
   house style better. Cosmetic; decide in review.
