# BGP neighbor ip-transparent — recap & follow-ups

Snapshot as of `main` ≈ commit `756426bb` (PR #1388 merged,
2026-06-12). The per-neighbor `ip-transparent` knob (FRR 10.4 parity,
FRRouting/frr PR #18789) is shipped end-to-end: YANG → config →
sockets → neighbor-group inheritance → show → BDD → book
(`book/src/ch-02-28-bgp-ip-transparent.md`). This memo records the
design decisions a future session would otherwise re-derive, and the
deliberately deferred slices.

## What shipped (PR #1388)

- **YANG**: `container ip-transparent { presence … }` in
  `zebra-bgp-transport.yang` — checked against the silent
  augment-name-collision trap with the vendored ietf-bgp tree (none);
  settable-path parse test pins both the `neighbor` and
  `neighbor-group` spellings
  (`bgp_neighbor_ip_transparent_is_settable` in
  `zebra-rs/src/config/manager.rs`). The group surface came free via
  the existing `uses zbt:bgp-neighbor-transport-extension` in
  `zebra-bgp-neighbor-group.yang`.
- **Sockopt** (`zebra-rs/src/bgp/transparent.rs`):
  `set_ip_transparent(fd, is_ipv4, on)` — `IP_TRANSPARENT` (SOL_IP)
  for v4, `IPV6_TRANSPARENT` (SOL_IPV6) for v6. Note FRR sets only the
  v4 option regardless of AF; the split is deliberate here (Linux v6
  sockets want the v6 spelling). Reuses `ttl::setsockopt_int`
  (promoted to `pub(super)`). Unit tests are privilege-aware: as root
  they assert set/clear readback, unprivileged they assert a clean
  EPERM — so they pass in both dev and root (BDD-host) runs.
- **Active connect** (`peer_connect`): option applied **before
  `bind()`**, gated on `update-source` being configured — the same
  both-flags gate as FRR's `bgp_connect()`. Unlike the best-effort
  TTL/MSS options, a setsockopt failure here **fails the dial** (the
  bind would fail `EADDRNOTAVAIL` anyway; EPERM names the real cause,
  missing CAP_NET_ADMIN).
- **Listeners**: `apply_ip_transparent_refresh_all` installs the
  per-AF **union** of (a) every peer's resolved knob and (b) any
  neighbor-group opinion (`knobs.ip_transparent == Some(true)` counts
  toward BOTH AFs — a dynamic listen-range member must find the flag
  on the listener before its SYN arrives, i.e. before any member peer
  exists). Refresh sites: the two knob callbacks,
  `sweep_members_inherit` (covers group delete), whole-neighbor
  delete in `config_peer`, and `listen()` after bind. Binding changes
  alone never alter the union (group opinions count regardless of
  membership), so `InheritOutcome` needed no new flag. FRR does not
  touch its listener at all; this side is what makes the documented
  passive scenarios (TPROXY-steered, VRRP pre-bind) work without an
  AnyIP route.
- **Semantics**: change on a live session bounces it
  (FRR `peer_change_reset`) via the standard
  `apply_<knob>` ritual (diff-gate, `start()`, bounce-if-not-Idle);
  inheritable through neighbor-group with explicit-wins; rendered in
  `show bgp neighbor` ("IP transparent enabled …") and the group
  detail/JSON views.
- **BDD `@bgp_ip_transparent`** mirrors FRR's
  `tests/topotests/bgp_tcp_ip_transparent`: z2 dials z1 sourcing from
  a phantom `10.255.0.99`; scenario 1 proves the session stays DOWN
  without the knob (kernel refuses the non-local bind), scenario 2
  proves it establishes with it. The new reusable harness step
  `I enable transparent return-path routing in namespace "X"`
  (bdd/tests/cucumber.rs) installs the fwmark recipe:
  `iptables -t mangle PREROUTING -p tcp -j MARK 0x100` +
  `ip rule fwmark 0x100 lookup 100` +
  `ip route add local default dev lo table 100`.
  **Do not** "simplify" the test to AnyIP
  (`ip route add local … dev lo` in the MAIN local table): that makes
  the address genuinely local and the whole feature passes vacuously.
  Direction is pinned by z1's connected-check hold (z1 cannot dial the
  phantom address), so z2 owns the connect.

## Deferred / scope boundaries

None of these block anything; each is parity-consistent with the
sibling transport knobs (`disable-connected-check`, `ttl-security`,
`tcp-mss`, …). Listed so a future surface-sweep has a known list.

1. **VRF BGP instances** — the per-neighbor callback is registered
   only on the default instance (`/router/bgp/neighbor/ip-transparent`).
   No transport knob is registered for per-VRF neighbors today; if
   that surface ever grows them, `ip-transparent` must join the sweep
   (callback registration + per-VRF listener refresh — note each VRF
   task has its own listener fds).
2. **interface-neighbor (unnumbered) peers** — the knob is not
   exposed on `interface-neighbor` (YANG attaches to `neighbor`
   only), same as the other transport extensions. Low value there:
   unnumbered sessions source from link-locals the host owns by
   construction.
3. **update-source gating is connect-time, not config-time** — FRR's
   vty refuses `ip-transparent` without `update-source`
   ("% Missing update-source"); zebra-rs accepts the config and gates
   at connect instead. Deliberate: per-leaf callbacks fire in
   tree-iteration order within one commit, so a cross-leaf rejection
   would spuriously refuse the natural single-commit config
   (`update-source` + `ip-transparent` together). Documented in the
   YANG description and the book chapter. If a commit-level
   cross-leaf validation pass ever exists, this pair is a candidate.
4. **No FRR-interop / topotest cross-validation run** — the BDD
   mirrors FRR's topotest topology zebra-rs↔zebra-rs; an actual
   zebra-rs↔FRR 10.4 run (one transparent end each way) has not been
   done.
5. **`bgp_getsockname` nexthop tolerance** — FRR's PR also tolerates
   `nexthop_set` failure when ip-transparent + update-source are set
   (the local address has no interface). zebra-rs has no equivalent
   failure site today (nexthop derivation does not hard-fail on an
   unknown local address), so nothing was ported; re-check if a
   sockname→nexthop validation is ever added.

## Code anchors

- `zebra-rs/src/bgp/transparent.rs` — sockopt + privilege-aware tests
- `zebra-rs/src/bgp/peer.rs` — `TransportConfig.ip_transparent`,
  `peer_start_connection` capture, `peer_connect` pre-bind site
- `zebra-rs/src/bgp/config.rs` — `config_ip_transparent`,
  `apply_ip_transparent`, `apply_ip_transparent_refresh_all`,
  FSM/inheritance unit tests
- `zebra-rs/src/bgp/neighbor_group.rs` —
  `InheritableKnobs.ip_transparent`,
  `config_neighbor_group_ip_transparent`, `apply_inherited` lockstep
- `bdd/tests/features/bgp_ip_transparent.feature` + configs +
  the return-path harness step in `bdd/tests/cucumber.rs`
