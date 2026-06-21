# BGP-PIC / Mirror SID node-protection — deferred items

Follow-ups after PR #1565 (`neighbor X pic-retention` + NHT-track-SID +
single-seg-re-lookup), which landed the end-to-end node-down SRv6 L3VPN
**service** failover validated by `@mirror_sid_node_vpn`. Companion to
`isis-mirror-sid-egress-protection-plan.md` (progress log) and the
`zebra-rs-bgp-pic-mirror-sid-node` memory note. None of these block the
shipped feature; they are scope deliberately left out.

## Dataplane / kernel

- **SR-MPLS node protection** — blocked on stock Linux (Risk #2 in the
  plan: no per-context label table). The protector cannot pop the context
  label and re-resolve the inner VPN label in a per-protected-egress
  context without an eBPF/VPP dataplane. SRv6 works because End.DT6 in a
  mirror-context vrftable is a kernel primitive; the MPLS equivalent is
  not. Needs the `tc-evpn-replicate`-style eBPF datapath (or VPP).
- **Single-seg re-lookup is a kernel-behavior assumption.** The ingress
  installs `encap seg6 [PEA-SID]` and relies on Linux **re-routing the
  encapped packet by its new outer DA** so the retained locator route adds
  the second `[Mirror SID]` H.Encaps. This is the same re-lookup the
  egress-link redirect already depends on, but it is an implicit contract,
  not an explicit two-segment program. If a future dataplane (VPP, a
  different kernel path) does *not* re-route seg6-encapped packets, the
  redirect silently breaks — there is no test that asserts the re-lookup
  happens, only the end-to-end ping. A two-segment SRH is **not** an
  alternative: it leaves `segleft=1` at the protector, where End.DT6
  expects `segleft=0`.

## Config surface

- **`pic-retention` safety hold-down is a fixed `PIC_RETENTION_HOLDDOWN`
  (600 s) constant** (`route.rs`). NHT is the primary withdrawal trigger,
  so this only caps a next-hop that never goes unreachable — but it is not
  operator-tunable. A per-neighbor or global `pic-retention hold-down
  <seconds>` knob would let deployments match it to their IGP
  egress-protection `hold-down`.
- **Two hold-downs interact and neither is surfaced.** The BGP route
  lifetime after a node death is `min(IGP-retention hold-down via NHT,
  600 s safety cap)`. If the IGP `egress-protection hold-down` is unset
  (float-forever), the BGP route is still withdrawn at 600 s; if it is set
  shorter, NHT drives the withdrawal first. Document/validate this
  interplay (today only the float-forever path is BDD-covered) and consider
  surfacing the remaining retention time in `show`.
- **No neighbor-group inheritance.** `pic-retention` is a plain per-neighbor
  knob (like `soft-reconfig-in`), not wired through `InheritableKnobs` /
  `resolve_knob`. A peer-group/template deployment must set it on every
  member. Add inheritance if group-level egress-protection config is wanted.

## AFI/SAFI coverage

- **Retention covers VPNv4 / VPNv6 only.** The `route_clean` stale path is
  added for the two MPLS-VPN AFI/SAFIs; plain unicast still withdraws
  immediately (correct — no SRv6 service SID), but **EVPN Type-5 IP-Prefix
  over SRv6** is *not* covered. EVPN-over-SRv6 node protection would want
  the same stale + NHT-track-SID treatment (the EVPN import path already
  exists in `nht_reeval`/`nht_reinstall_transport`). Out of scope until an
  EVPN-SRv6 node-protection use case lands.
- **`nht_target` resolves the SID for SRv6 L3VPN (`srv6_l3_sid()`) only.**
  EVPN Type-5 carries its SID via the same Prefix-SID attribute but through
  a different code path; if EVPN node protection is built, `nht_target`
  (or its EVPN analogue) must track the EVPN service SID the same way, and
  the shard's `candidate_nexthops_*` survivor set must stay consistent
  (the bug that made the v6vpn route show valid with an empty FIB).

## Validation

- **`@mirror_sid_node_vpn` validates the happy path only.** It does not
  exercise: the 600 s safety-cap withdrawal (would need a multi-minute
  wait), NHT-driven withdrawal when the IGP retention `hold-down` fires
  (the BGP route should disappear when the locator is withdrawn), recovery
  (pea's node returns → route un-stales → forwards natively again), or the
  multi-prefix / ECMP transport case. Add these as the feature hardens.
- **No FRR/commercial interop.** The retention + redirect is zebra-rs↔
  zebra-rs only; `draft-ietf-rtgwg-bgp-pic` interop with another vendor's
  ingress is untested.
