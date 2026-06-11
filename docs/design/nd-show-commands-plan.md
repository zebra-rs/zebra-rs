# IPv6 ND Show Commands — Blueprint and Plan

Goal: expose the internal state of the IPv6 Neighbor Discovery subsystem —
especially Neighbor Advertisement (NA) and Neighbor Solicitation (NS)
packet counts, sent and received, broken down by interface and by source
link-local address — and tie that visibility into the BGP
`interface-neighbor` (unnumbered) story.

## 1. Current state

What exists today (branch `nd-show-commands`, 2026-06-10):

| Aspect | Status | Anchor |
|---|---|---|
| ND module | RS (133) / RA (134) only | `zebra-rs/src/nd/` |
| NS (135) / NA (136) | blocked at the kernel ICMP6 filter, no codec | `nd/socket.rs:90`, `crates/nd-packet/src/typ.rs` |
| Counters | none anywhere in the ND module | — |
| Learned neighbors | not stored; `NdEvent::NeighborDiscovered` is fire-and-forget to BGP | `nd/engine.rs:122-137` |
| Show infrastructure | none (no ShowChannel, no `show nd` grammar, `show_proto` falls back to `"rib"`) | `config/manager.rs:1112` |
| BGP interface peer | stores `ifname`, learned link-local in `address`, `scope_id` | `bgp/interface_neighbor.rs:88` (`materialize_peer`) |
| `show bgp neighbors` for interface peers | prints `BGP neighbor on <ifname>: <link-local>` only — nothing about ND | `bgp/show.rs:2036-2041` |

Key physical constraints that shape the design:

1. **The daemon never sends NS/NA.** The host kernel owns the NDP cache
   (deliberate — see the `nd-packet` crate comment). A raw ICMPv6 socket
   only delivers *received* packets, so "NS/NA sent" can never be counted
   from the socket. The kernel's per-interface counters at
   `/proc/net/dev_snmp6/<ifname>` (`Icmp6InNeighborSolicits`,
   `Icmp6OutNeighborAdvertisements`, and the six siblings covering
   RS/RA/NS/NA × in/out) are the authoritative source for kernel-side
   totals — but they have no per-source breakdown.
2. **The daemon CAN passively observe received NS/NA.** Widening the
   ICMP6 filter to pass 135/136 delivers *copies* to the raw socket; the
   kernel still processes NDP itself. This is how we get the per-source
   link-local breakdown the operator asked for.
3. **Multicast loopback is OFF** (`nd/socket.rs:83`), so our own RA
   transmissions are not seen on the receive path. TX counting must
   happen at the emission point in `NdEngine::tick`, not on the socket.
4. The hop-limit-255 check at `network.rs:75` applies equally to NS/NA
   (RFC 4861 requires 255 for all four message types) — no change needed.

So the design exposes **two complementary counter sets**:

* **Daemon-observed** (per interface AND per source address): rx RS/RA/NS/NA,
  tx RA (split unsolicited/solicited), plus drop counters.
* **Kernel totals** (per interface only, read from `dev_snmp6` at show
  time, no state kept): sent+received for all four types — this is the
  only place "NS/NA sent" can come from.

## 2. Blueprint

### 2.1 nd-packet codec: NS/NA types

`crates/nd-packet`:

* `Icmp6Type`: add `NeighborSolicit = 135`, `NeighborAdvert = 136`.
* New structs mirroring `RouterSolicit`/`RouterAdvert`:
  * `NeighborSolicit { target: Ipv6Addr, options: Vec<NdOption> }`
  * `NeighborAdvert { flags: NaFlags /* R|S|O */, target: Ipv6Addr, options: Vec<NdOption> }`
* `parse()` + `emit_without_checksum()` + round-trip unit tests (emit is
  only used by tests today; the engine never originates NS/NA).
* Reuse the existing `NdOption` parser (SLLA/TLLA options appear in both).

### 2.2 Engine state: counters + neighbor table (pure, unit-testable)

All state lives in `NdEngine` (pure logic, no I/O) so it is testable the
same way the existing engine tests are.

```rust
// nd/engine.rs
#[derive(Default)]
pub struct NdIfCounters {
    pub tx_ra_unsolicited: u64,
    pub tx_ra_solicited: u64,
    pub rx_ra: u64,
    pub rx_rs: u64,
    pub rx_ns: u64,
    pub rx_na: u64,
    pub rx_drop_hop_limit: u64,
    pub rx_drop_malformed: u64,
    pub untracked_sources: u64,   // neighbor-table cap overflow
}

pub struct NdNeighbor {
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub rx_ra: u64,
    pub rx_rs: u64,
    pub rx_ns: u64,
    pub rx_na: u64,
    pub last_ra: Option<LastRa>,  // lifetime, cur_hop_limit, M/O flags
}

// added to NdEngine:
counters:  BTreeMap<u32, NdIfCounters>,                 // keyed by ifindex
neighbors: BTreeMap<u32, BTreeMap<Ipv6Addr, NdNeighbor>>,
```

Notes:

* `counters`/`neighbors` are independent of `senders` — NS/NA arrive on
  interfaces that have no RA sender configured, and we still want to
  count and attribute them.
* The neighbor table is capped per interface (proposal: 256 sources;
  beyond that increment `untracked_sources` instead of inserting) so a
  large or hostile segment can't grow memory unboundedly.
* DAD probes arrive with source `::` — they get a table entry like any
  other source and render with a `(duplicate address detection)` note.
* TX counting happens inside `NdEngine::tick` where `RaEvent::SendUnsolicited`
  vs `SendSolicited` is still distinguishable.

**Keeping drop counters pure:** hop-limit and parse drops currently
happen silently inside the read task (`network.rs:75-96`), outside the
engine. Rather than sprinkling atomics into the I/O task, extend the
channel message so the engine counts everything:

```rust
// nd/mod.rs
pub enum NdRecv {
    RouterAdvert  { ifindex: u32, src: Ipv6Addr, ra: RouterAdvert },
    RouterSolicit { ifindex: u32, src: Ipv6Addr, rs: RouterSolicit },
    NeighborSolicit { ifindex: u32, src: Ipv6Addr, ns: NeighborSolicit },
    NeighborAdvert  { ifindex: u32, src: Ipv6Addr, na: NeighborAdvert },
    Dropped { ifindex: u32, reason: DropReason },   // HopLimit | Malformed
}
```

`read_packet` gains arms for types 135/136 and sends `Dropped` where it
silently `return Ok(())` today; `NdEngine::on_recv` becomes the single
place where every counter increments. Existing behavior (RA → notify
BGP, RS → schedule reply) is unchanged; NS/NA are count-and-record only.

`socket.rs:90` becomes `Icmp6Filter::pass_only(&[133, 134, 135, 136])`.

`RaSender` gains read accessors for show: `cfg()`, `initial_remaining()`,
`next_unsolicited_at()`, `pending_solicited_at()`, `last_multicast_at()`.

### 2.3 Show command: `show ipv6 nd [interface [IFNAME]]`

Grammar (`zebra-rs/yang/exec.yang`, inside the existing `container ipv6`
at line ~697):

```yang
container nd {
  ext:help "IPv6 neighbor discovery";
  presence "Show IPv6 ND status";
  list interface {
    ext:help "ND status per interface";
    ext:presence "Show all interfaces";
    key if-name;
    leaf if-name {
      ext:dynamic "rib:interface";
      type string;
    }
  }
}
```

* `show ipv6 nd` → `/show/ipv6/nd`, summary: one line per interface
  (RA enabled?, neighbor count, rx/tx totals).
* `show ipv6 nd interface` → `/show/ipv6/nd/interface`, args `[]`: full
  detail for all interfaces.
* `show ipv6 nd interface eth0` → same path, args `["eth0"]`.

Plumbing (mirror the BFD pattern exactly — it is the nearest
conditionally-spawned protocol):

1. `config/manager.rs`: add `is_nd()` (any path segment `"nd"`) to
   `show_proto()` and to the fallback protocol-name chain, so an
   un-spawned ND answers `"ND is not configured or running"` via the
   existing Layer-1 fallback. (In practice ND spawns eagerly with
   `router bgp` — manager.rs:547 — so BGP-unnumbered users always have
   it running.)
2. `nd/inst.rs`: add `show: ShowChannel`, `show_cb: HashMap<String, ShowCallback>`,
   `show_build()`, `process_show_msg()`, and the
   `Some(msg) = self.show.rx.recv()` select arm.
3. `config/nd.rs` (`spawn_nd`): `config.subscribe_show("nd", nd.show.tx.clone())`.
4. New `nd/show.rs`: renderers, text + JSON (`json: bool` flag per the
   house convention — serde structs for JSON, `write!` for text).
5. Kernel counters: a small helper reads
   `/proc/net/dev_snmp6/<ifname>` at show time and extracts the eight
   `Icmp6{In,Out}{Router,Neighbor}{Solicits,Advertisements}` lines.
   Stateless, namespace-correct, and tolerant of the file being absent
   (interface gone): render `-`.

Text output sketch:

```
Interface enp0s5 (ifindex 2)
  Router advertisement: enabled
    interval 200-600s, lifetime 1800s, hop-limit 64, managed=0 other=0
    initial advertisements remaining 0, next unsolicited in 134s
    solicited reply pending: no, last multicast 27s ago
  Counters (daemon-observed)        Sent  Received
    Router solicitations               -         2
    Router advertisements             14        13
    Neighbor solicitations             -         5
    Neighbor advertisements            -         5
    dropped: hop-limit 0, malformed 0, untracked sources 0
  Counters (kernel)                 Sent  Received
    Router solicitations               0         2
    Router advertisements             14        13
    Neighbor solicitations             9         5
    Neighbor advertisements            5         9
  Neighbors (4):
    fe80::a8aa:aaff:feaa:1   RA 13  RS 0  NS 3  NA 5   first 05:31 ago, last 27s ago
      last RA: lifetime 1800s hop-limit 64 M=0 O=0
    ::                       NS 2 (duplicate address detection)
```

Grammar pinning: parse() tests in `config/parse.rs` (using
`exec_entry()`) for the three spellings above; `yang_load_tests` guards
the schema edit automatically.

### 2.4 BGP integration: ND visibility on interface peers

`bgp/peer.rs` — new fields on `Peer`:

```rust
pub nd_discovered_at: Option<Instant>,   // first NeighborDiscovered
pub nd_refreshed_at: Option<Instant>,    // most recent one
pub nd_event_count: u64,
```

Set/updated in `materialize_peer()` (`bgp/interface_neighbor.rs:88`) for
both the create and the refresh path.

`bgp/show.rs` — for interface-keyed peers, `show bgp neighbors` (and the
single-neighbor form) gains a block right under the identity line, text
and JSON:

```
BGP neighbor on enp0s5: fe80::a8aa:aaff:feaa:1, remote AS 65001, ...
  Interface peer: link-local learned via IPv6 ND router advertisement
  Discovered 05:31 ago, refreshed 13 times (last 27s ago)
```

Registered through the existing show `Builder` chain — no new paths, only
renderer changes.

### 2.5 BDD

New `bdd/features/nd_show.feature` (tag must not be a prefix of any
existing tag — verify with a grep before naming; `@nd_show` proposed):

* Two namespaces, veth pair, `ipv6 router-advertisements` +
  `interface-neighbor` both sides (reuse the `@bgp_unnumbered_neighbor`
  topology; keep its two-phase apply to dodge the link-learn race).
* Assert `show ipv6 nd interface <if>` contains the peer's link-local
  and a non-zero received-RA count (allow the documented up-to-16 s
  initial-RA delay before asserting).
* Assert `show bgp neighbors` contains the `Discovered ... ago` line.
* End with the mandatory `Scenario: Teardown topology`.

Known step traps (from prior sessions): the `show command "<cmd>"` step
needs the literal `show` inside the quotes; stack given/when/then on
utility steps; rebuild + reinstall `/usr/bin/zebra-rs` and verify the
binary is yours immediately before the run.

## 3. Step-by-step plan (PR slices)

Each PR: `cargo fmt`, workspace-wide clippy, full test suite before push.

1. **PR 1 — nd-packet: NS/NA codec.** `Icmp6Type` 135/136,
   `NeighborSolicit`/`NeighborAdvert` structs, parse/emit, round-trip
   tests. Pure codec, zero behavior change. (small)
2. **PR 2 — ND core: observe + count + remember.** Widen the ICMP6
   filter; `NdRecv` gains `NeighborSolicit`/`NeighborAdvert`/`Dropped`
   variants; `NdIfCounters` + `NdNeighbor` table (capped) in `NdEngine`;
   TX counting in `tick`; `RaSender` accessors. Engine unit tests for
   every counter and the cap/DAD edge cases. (medium)
3. **PR 3 — `show ipv6 nd`.** exec.yang grammar, `is_nd` routing,
   ShowChannel on `Nd`, `nd/show.rs` text+JSON renderers, `dev_snmp6`
   reader, parse() grammar tests. (medium)
4. **PR 4 — BGP neighbor ND block.** `Peer` discovery-tracking fields,
   `materialize_peer` updates, `show bgp neighbors` text+JSON rendering
   for interface peers. (small)
5. **PR 5 — BDD.** `@nd_show` feature as in §2.5, with teardown. (small)

PR 1 and the grammar half of PR 3 are independent of PR 2; the rest is
sequential. PR 1 in particular is a self-contained warm-up.

## 4. Deferred (explicitly out of scope)

* `clear ipv6 nd counters`.
* Actively transmitting RS when an `interface-neighbor` is configured
  (would speed up peer discovery; the RS send path is already plumbed
  but unused in the engine).
* Unicast solicited RA replies (engine comment at `engine.rs:173`).
* Neighbor expiry / `NeighborLost` event on RA lifetime timeout → BGP
  peer teardown (today a vanished peer only dies via hold-time).
* Socket-level send-failure counters in the write task.
* Exposing the kernel NDP cache itself (`ip -6 neigh` equivalent) —
  different data source (netlink dump), separate command if wanted.

## 5. Decision points (recommendations baked into the plan)

1. **Command spelling** — `show ipv6 nd …` (recommended; short, matches
   the module name) vs `show ipv6 neighbor-discovery …`.
2. **Kernel counters in the output** — recommended yes; it is the only
   source for "NS/NA sent" and costs no state. Could be dropped to a
   later PR if the dual table feels noisy.
3. **Neighbor-table cap** — 256 sources/interface proposed.
