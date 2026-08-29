# EVPN multihoming interop lab: zebra-rs + cradle-rs against FRR

*Lab plan, drafted 2026-08-28. Companion to
`bgp-evpn-multihoming-dataplane.md` (the analysis of the ENOG91 FRR EVPN-MH
talk) and `bgp-evpn-ethernet-segment.md` (what zebra-rs implements).
Status: **plan — not yet executed.** The result goes into
`bgp-evpn-mh-frr-interop-report.md`.*

---

## 1. The question

zebra-rs v26.8.5 with cradle-rs v1.1.0 implements EVPN multihoming end to
end (DF election with carving / HRW / preference / AC-DF, non-DF and
split-horizon filters, aliasing and mass withdraw, LAG ports, single-active
with a backup path). Every proof so far is zebra-rs against zebra-rs. The
one thing a same-vendor lab cannot show is whether the *wire* is right —
that a PE running FRR reads our Type-1/2/3/4 routes the way RFC 7432 and
RFC 8584 intend, and that we read FRR's.

The lab answers three questions, in order of importance:

1. **Control-plane agreement.** On a segment shared by one zebra-rs PE and
   one FRR PE, do both elect the *same* Designated Forwarder for every
   EVI, and do both build the *same* aliasing set for a remote observer?
   Disagreement here is a duplicate-or-blackhole bug, whichever side is
   wrong.
2. **Route-format compatibility.** Does each side accept the other's
   routes intact — the ESI in the Type-2 NLRI, the ES-Import RT and DF
   Election EC on the Type-4, the ESI-label EC on the per-ES A-D, FRR's
   MAC-IP *sync* routes with the proxy bit — without dropping or
   misinterpreting them?
3. **Behaviour under the known FRR gaps.** FRR computes the non-DF and
   split-horizon filters but the Linux bridge cannot enforce them (the
   talk's thesis, FRR issue #15400), it has no RFC 7432 modulus election
   and no single-active mode. Which of those show up as duplicates or loops
   on a mixed segment, and is any of them something zebra-rs should
   compensate for?

Out of scope: FRR's own eBPF workaround from the talk (it patches FRR;
the lab runs stock FRR), MPLS-EVPN (FRR has none), EVPN-VPWS (FRR has
none), and performance.

## 2. What we know going in

| Function | FRR (10.x) | zebra-rs + cradle-rs (26.8.5 / 1.1.0) | Expected on a mixed segment |
|---|---|---|---|
| Ethernet Segment, Type-4, ES-Import RT | yes — Type-3 ESI (`es-sys-mac` + `es-id`), auto RT | yes — Type-0 manual 10-byte ESI, auto RT from bytes 1–6 | zebra-rs configured with FRR's derived Type-3 value; RTs identical by construction |
| DF election, default (Alg 0, RFC 7432 modulus) | **no** | yes | mixed Alg 0 / Alg 2 → RFC 8584 says fall back to Alg 0, which FRR lacks — **disagreement risk, measure** |
| DF election, preference (Alg 2) | yes, `evpn mh es-df-pref` | yes, `df-election preference` | both Alg 2 → agree; the supported way to share a segment |
| DF election, HRW (Alg 1) | no | yes | zebra-rs falls back to carving; FRR unknown — measure |
| AC-DF capability bit | unknown | advertised + honoured when unanimous | observe FRR's bitmap; expect *not in effect* |
| non-DF BUM filter | control plane only | enforced (cradle) | FRR non-DF: CE gets duplicates (**expected FRR gap**); zebra-rs non-DF: exactly one copy |
| split horizon / local bias | control plane only | enforced (cradle `VTEP_ES`) | BUM DF→FRR non-DF re-floods to the CE (**expected FRR gap**); FRR DF→zebra-rs: dropped, `l2_drop_sph` |
| aliasing + mass withdraw | yes — kernel FDB `nhid` groups | yes — ES nexthop groups | both directions should converge; measure the withdraw-to-reroute time |
| single-active | **no** | yes, incl. backup path | do not mix; test only that an SA ESI-label EC does not break FRR |
| LAG segment port (MC-LAG) | bond required for the ES interface | bond optional (`PORT_MASTER`) | LACP needs the same actor system MAC on both PEs' bonds |
| MAC-IP sync / proxy Type-2 | yes (ES peers sync MACs/neighbours) | not originated; must be accepted | zebra-rs must tolerate the proxy bit and the sync semantics |

## 3. Inventory

* **Host**: the dev box — Ubuntu 24.04, kernel 6.8, `bonding` loaded,
  Docker available. Everything runs in Linux network namespaces exactly as
  the BDD suites do, so a scenario can later be scripted as a feature.
* **zebra-rs** v26.8.5 (`/usr/bin/zebra-rs`, `vtyctl`), **cradle-rs**
  v1.1.0 (`cradle`, `ctl`, gRPC over an abstract unix socket).
* **FRR**: the local build under `/usr/local` (`bgpd`, `zebra`, `vtysh`)
  or the Ubuntu 24.04 package candidate 10.7.0. Run per namespace with a
  pathspace: `ip netns exec <ns> /usr/local/sbin/zebra -N <ns> -d`, same
  for `bgpd`; `vtysh -N <ns>`. Record the exact version in the report.
* **Instruments**: `tc filter … matchall` byte/packet counters on the CE
  legs (copy-count proof), cradle stats over gRPC (`l2_drop_nondf`,
  `l2_drop_sph`, `l2_es_nhg`, `l2_drop_sa`), `tcpdump -ni <underlay>
  udp port 4789`, FRR `show evpn es detail` / `show evpn es-evi` / `show
  evpn mac vni` / `show bgp l2vpn evpn route`, kernel `bridge fdb show`
  and `ip nexthop show`, zebra-rs `show bgp evpn` / `show bgp evpn
  ethernet-segment` / `show evpn mac`, `ping -i 0.1 -c 300` for gap
  counting.

## 4. Topology

```
      c1 ── PE-A ══════════╗
   10.0.0.1  zebra-rs+cradle ║                 ┌─── eth0 ─── PE-A  ┐
   (behind   VTEP 192.0.2.1  ║   br0 (underlay ║                   │  CE  bond0
    PE-C)                    ╠══ 192.0.2.0/24) ║   10.0.0.2  bond0 ┤  active-backup,
             PE-B ══════════╣                 └─── eth1 ─── PE-B  ┘  later 802.3ad
             FRR + kernel    ║
             bridge/vxlan    ║      ES-1 = PE-A + PE-B, EVI/VNI 100
             VTEP 192.0.2.2  ║      ESI 03:00:00:00:00:01:00:00:00:01
                             ║      (FRR: es-sys-mac 00:00:00:00:01:00, es-id 1)
      c2 ── PE-C ══════════╝
   10.0.0.3  role swaps by phase:
             zebra-rs (P0–P2) or FRR (P3)
```

* One flat underlay (`br0`, `192.0.2.0/24`) as in the BDD suites; iBGP AS
  65001 full mesh, EVPN address family, all three PEs peering directly (no
  RR — one fewer variable; add an FRR RR as a P4 extra if time allows).
* **PE-A** — zebra-rs with the cradle tee: `vtep-source 192.0.2.1`,
  `ethernet-segment es1 { esi …; interface pe-a-ce; df-election {
  preference 100 } }`, ports `pe-a-ce` (vlan 100) and the uplink (`l3`),
  `vxlan100` enslaved to `br100` for the kernel-side L2 EVI membership.
* **PE-B** — FRR: vlan-aware `br100` with `vxlan100` (traditional per-VNI
  device, `dstport 4789 local 192.0.2.2 nolearning`) and `bond0` (mode
  802.3ad or active-backup, **`miimon 100`**, member `pe-b-ce`) as the ES
  port; `interface bond0 { evpn mh es-id 1; evpn mh es-sys-mac
  00:00:00:00:01:00; evpn mh es-df-pref 50 }`, `evpn mh startup-delay 0`
  for the lab, `router bgp 65001 { address-family l2vpn evpn {
  advertise-all-vni } }`.
* **CE** — a kernel bond: `active-backup miimon 100 all_slaves_active 1`
  first (P0–P4); `802.3ad lacp_rate fast` with both PEs' bonds set to
  `ad_actor_system 00:00:00:00:01:00` for P5.
* **PE-C** — the remote observer: zebra-rs+cradle in P0–P2 (we watch our
  aliasing group and stats), FRR in P3 (we watch its `nhid` group).
* **ESI**: FRR derives the Type-3 ESI `03:<es-sys-mac>:<es-id, 3 bytes>` =
  `03:00:00:00:00:01:00:00:00:01`; zebra-rs is configured with that literal.
  *Verify first* that zebra-rs's `esi` leaf accepts a leading `03` (it is
  a free 10-byte string today; the ES-Import RT derivation reads bytes
  1–6 regardless of type, which is what FRR does).

## 5. Phases

The phases are ordered by dependency: each one's pass is a precondition
for the next being interpretable.

### P0 — zebra-rs as a pure remote of an all-FRR segment

Setup: PE-B and PE-C both FRR, sharing ES-1 (two FRR bonds toward the CE);
PE-A zebra-rs, single-homed to c1.

Checks:
* `show bgp evpn` on PE-A lists FRR's Type-4 with `es-import:00:00:00:00:01:00`
  and `df-election:alg2:pref…`, the per-ES A-D `[1]:[ESI]:[MAX-ET]` with an
  `esi-label:all-active` EC, per-EVI A-D `[1]:[ESI]:[0]` under both RDs, and
  the CE's Type-2 carrying the ESI. Nothing is logged as malformed.
* FRR's MAC-IP sync Type-2 (advertised by the non-learning ES peer with the
  proxy flag in the EVPN ARP-ND / MAC Mobility EC) is accepted; note how
  zebra-rs treats the duplicate-advertiser case for the MAC entry.
* `show bgp evpn ethernet-segment` on PE-A ends with
  `… bd 100: all-active 192.0.2.2 192.0.2.3`; after a `ping c1 → CE` the
  cradle stat `l2_es_nhg` on PE-A is non-zero (known unicast is hashed
  across both FRR PEs).
* Mass withdraw: `ip link set pe-b-ce down` on PE-B (bond loses carrier)
  → FRR withdraws its Type-4 and per-ES A-D → PE-A's group becomes
  `all-active 192.0.2.3` and a running `ping -i 0.1` loses ≤ a handful of
  packets. Record the withdraw-to-reroute gap.

Pass: all routes parsed, group correct in both states, ping continuity.

### P1 — mixed segment: DF election agreement

Setup: PE-A (zebra-rs) and PE-B (FRR) share ES-1; PE-C zebra-rs remote.
Both sides on **preference** (Alg 2): PE-A `preference 100`, PE-B
`es-df-pref 50`.

Checks:
* PE-A `show bgp evpn ethernet-segment`: `DF algorithm: preference-based`,
  `Designated Forwarder (tag 0): 192.0.2.1 (this node)`; PE-B `show evpn
  es detail`: DF = 192.0.2.1 for VNI 100 (`show evpn es-evi`). Both agree.
* Swap the preferences (PE-B 200): both move the DF to PE-B without any
  session flap; PE-A's tee sends `SetEsRole{df:false}` (cradle
  `l2_drop_nondf` starts counting on BUM toward the CE).
* Tie (equal preference): both pick the lower VTEP (192.0.2.1).
* Startup delay: restart PE-B's bgpd with `evpn mh startup-delay 30` — PE-A
  must keep the DF role until FRR's Type-4 appears, then re-elect; and the
  mirror image with zebra-rs `startup-delay 30`.
* AC-DF: enable `ac-df` on PE-A and read FRR's DF EC bitmap in PE-A's
  `show bgp evpn`; expect `AC-DF: advertised, not in effect (1 of 2 PEs
  advertise it)` unless FRR sets the bit — record either way.

Pass: DF identical on both PEs in every state; no flap.

### P2 — mixed segment: BUM (non-DF filter and split horizon)

Setup as P1. Instrument the CE's two legs with `tc matchall` counters
after convergence (enslaving emits a frame; install the counters late).

Checks, each with an ARP burst from c1 (`ip neigh flush` then `ping -c 3`):
1. **zebra-rs non-DF** (PE-B DF): CE receives exactly one copy per ARP on
   the PE-B leg; PE-A's `l2_drop_nondf` increments; PE-A leg counter
   stays flat. *This is the case the whole arc was built for.*
2. **FRR non-DF** (PE-A DF): expect **two copies** at the CE — one per leg
   — because FRR's non-DF filter is not enforced by the bridge (talk,
   slides 20–41; FRR #15400). Count them. This is the pre-registered FRR
   gap, not a zebra-rs failure.
3. **Split horizon, CE → PE-A (DF) → PE-B**: BUM from the CE enters at
   PE-A and is flooded to PE-B and PE-C; PE-B must not forward it back
   to the CE. Expect FRR to re-flood it onto the CE's PE-B leg (the SPH
   filter is control-plane only): the CE sees its own broadcast echoed.
   Count.
4. **Split horizon, CE → PE-B (DF) → PE-A**: the frame arrives at PE-A
   from VTEP 192.0.2.2, which is in PE-A's `VTEP_ES` set for ES-1; cradle
   drops it toward the CE and `l2_drop_sph` increments; the CE's PE-A leg
   stays flat.
5. Known unicast is unaffected in all four: c1 ↔ CE ping succeeds with no
   duplicates (`ping` reports no `DUP!`).

Pass: cases 1, 4 and 5 clean; cases 2 and 3 documented with counts (they
are FRR's gap; if either is *clean*, FRR has changed and the analysis doc
needs updating).

### P3 — aliasing and mass withdraw with an FRR remote

Setup: PE-C becomes FRR; ES-1 = PE-A (zebra-rs) + PE-B (FRR).

Checks:
* On PE-C: `show evpn es` lists ES-1 with both VTEPs, `ip nexthop show`
  has a group with two VXLAN nexthops, and `bridge fdb show` maps the CE's
  MAC to that `nhid`. That is FRR consuming zebra-rs's per-ES + per-EVI
  A-D routes.
* c2 → CE flows hash over both PEs (tcpdump on PE-C's underlay: VXLAN to
  both 192.0.2.1 and 192.0.2.2 across several flows).
* Mass withdraw from the zebra-rs side: `ip link set pe-a-ce down` on PE-A
  — zebra-rs withholds Type-4 and A-D at once (the access link-state path)
  — PE-C's nexthop group drops 192.0.2.1 and the `ping -i 0.1` gap is
  measured; then link up → PE-A rejoins the group.
* The reverse (PE-B's bond down) for symmetry.

Pass: FRR builds and shrinks the group from zebra-rs's routes; gap ≤ P0's.

### P4 — divergences, pre-registered

Each of these is expected to *not* interoperate; the lab records exactly
how, so the docs and the book can say it precisely.

* **Algorithm mismatch**: PE-A `df-election algorithm hrw` (Alg 1) against
  PE-B's Alg 2. zebra-rs falls back to carving (Alg 0). What does FRR do
  with an Alg 1 bid — fall back, ignore, or keep preference? If the two
  PEs disagree on the DF, both forward BUM (duplicates) or neither
  (blackhole). Record which. Same test with PE-A on plain default (Alg 0).
* **Single-active**: PE-A `redundancy-mode single-active`. Its per-ES A-D
  carries the single-active ESI-label EC; FRR (no SA support) presumably
  keeps treating the segment as all-active — its non-DF still forwards
  to the CE and its remote still aliases. Confirm; confirm nothing on the
  FRR side crashes or logs the route as bad.
* **AC-DF** (if FRR sets the bit in P1): take a VLAN sub-interface AC down
  on PE-B and see whether FRR withdraws only the per-EVI A-D.
* **RR in the middle** (optional): an FRR route reflector between the
  PEs, to check the ES-Import RT filtering and the Type-4 reaching only ES
  members.

Recommendation expected to come out of this phase: *on a mixed segment,
configure preference-based election on both sides; never mix
single-active with FRR.*

### P5 — LACP MC-LAG (optional, last)

CE bond `802.3ad lacp_rate fast`; PE-A's port becomes a bond with
`ad_actor_system 00:00:00:00:01:00` (matching FRR's `es-sys-mac`, which FRR
also applies to its own bond); both legs must reach LACP *distributing*.
Re-run P2 cases 1 and 4 and P3 with the CE hashing flows over both legs.
Pass criterion is P2/P3 unchanged plus LACP up on both legs.

## 6. Method

* One scenario at a time, from a clean set of namespaces (`ip netns list`
  must be empty of lab names before setup). Keep each PE's configuration
  in the report verbatim.
* Every count is a difference of two readings around a known stimulus
  (N ARPs from c1, N pings), never an absolute.
* Failover gaps: `ping -i 0.1 -c 300` running through the event; report
  lost packets ×100 ms, and the BGP timestamps of the withdraw
  (`show bgp l2vpn evpn route` / zebra-rs trace) for the control-plane
  half of the gap.
* Capture the underlay on the remote PE for every BUM case; the pcap is
  the evidence of copy counts when the tc counters are in doubt.
* Anything unexpected on the zebra-rs side becomes an issue with the
  scenario reproduced as a BDD feature (`bdd/tests/features/`, the
  `cradle_evpn_mh_*_zebra` features are the template; FRR can be driven
  in a namespace the same way).

## 7. Exit criteria and deliverables

* **Report** `docs/design/bgp-evpn-mh-frr-interop-report.md`: FRR version,
  per-phase results with counts and gaps, the divergence table filled in,
  and the recommendation for mixed segments.
* **Docs updated**: `bgp-evpn-multihoming-dataplane.md` §1.2 (the FRR
  matrix) corrected with measured facts; the book's multihoming text gains
  an "interoperating with FRR" note (preference-based on mixed segments;
  what FRR's non-DF/SPH gap means for a CE dual-homed to FRR).
* **Bugs**: anything where zebra-rs misreads an FRR route, or the two
  disagree on a DF while both are on Alg 2, is a zebra-rs bug until
  proven otherwise; FRR-side findings are filed upstream with the pcap.
* **Optional**: P1 + P2 case 1 scripted as a BDD feature with FRR in a
  namespace, so the interop stays proven.

Effort: about three lab days — P0–P1 (day 1), P2–P3 (day 2), P4–P5 and
the report (day 3).

## 8. Risks and gotchas (from the same-vendor labs)

* FRR only accepts `evpn mh es-id` on a bond; the CE-facing port on the
  FRR PE must be enslaved, and a bond needs `miimon` (or ARP monitoring)
  to notice member carrier loss — with the kernel default it never does.
* A veth must be `down` before `master bond0` ("Device can not be
  enslaved while up").
* zebra-rs's Type-4 Originating IP must be the VTEP: set `vtep-source`, or
  the split-horizon peer list will not match FRR's outer source.
* IPv6 on the PE namespaces pollutes CE-leg counters (MLD/DAD/RS): disable
  it in the PEs before creating links; install the tc counters after
  convergence.
* FRR's auto-derived route target is `AS:VNI`, the same as zebra-rs's — but
  if FRR is given `advertise-all-vni` with a manual RD/RT, match zebra-rs's
  `evi` import accordingly.
* Both stacks re-originate MAC routes on segment changes; a MAC seen from
  two advertisers is normal during a transition, not a finding, unless
  it persists.
