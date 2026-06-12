# Fast Failover: TI-LFA + BFD (NexthopProtect)

When a primary nexthop fails, waiting for the IGP to re-run SPF and
rewrite every affected route is the slowest possible repair: detection
plus convergence plus one netlink operation *per prefix*. zebra-rs
instead pre-computes a TI-LFA repair for each protected destination and
installs primary and backup together as a single RIB object — the
**`Nexthop::Protect`** primary/backup pair. [BFD](ch-10-00-bfd.md)
supplies sub-second detection, and the switchover onto the repair is
**one atomic kernel operation per failed adjacency**, independent of
how many prefixes were using it (PIC-style). SPF still runs — but it
cleans up after traffic has already been restored, instead of being in
the restoration path.

## The two failure classes

The design splits on what the kernel can see for itself:

| Failure | Detected by | Repaired by | Cost |
|---|---|---|---|
| Local link down | kernel netdev event | **kernel, autonomously** — it flushes the nexthop objects on the dead device and the routes referencing them; the pre-installed `metric+1` repair route takes over | ~instant, no daemon involvement |
| Remote failure with the link still up (neighbour crash, unidirectional loss) | **BFD** | **`ProtectSwitch` fast path** — one atomic group replace per failed adjacency, *before* SPF | detection-bounded (BFD interval × 3) plus microseconds |

The second row is what NexthopProtect exists for. The link is up, so
the kernel sees nothing wrong; the primary route still points at a dead
gateway. Without the fast path, the pre-computed TI-LFA repair would
sit unused in exactly the failure class TI-LFA was invented for, while
the daemon ground through SPF and per-prefix FIB churn.

## What each layer contributes

- **TI-LFA** (RFC 9490, in IS-IS, OSPFv2 and OSPFv3) computes the
  post-convergence repair path for each destination and expresses it as
  a segment-routing encapsulation — an SR-MPLS label stack or an SRv6
  segment list — so the repair is loop-free *during* convergence, not
  just after it.
- **[BFD](ch-10-00-bfd.md)** detects the dead forwarding path in
  sub-second time and reports it to the owning IGP.
- **The RIB** carries both paths in one route as `Nexthop::Protect
  { primary, backup }`, instead of leaving the repair implicit in a
  second route object.
- **The FIB layer** installs the protected primary behind a kernel
  *nexthop indirection group*, giving the switchover a single handle to
  swap.

## Configuration

Three ingredients: segment routing (the repair needs SIDs to ride on),
`fast-reroute ti-lfa`, and BFD on the interfaces you want the fast
detection for. IS-IS:

```
router isis {
  net 49.0000.0000.0000.0001.00;
  is-type level-2-only;
  segment-routing mpls;
  fast-reroute { ti-lfa; }
  interface eth0 {
    ipv4 { enable true; }
    bfd { enable true; }      // sub-second detection on this adjacency
  }
}
```

OSPFv2 (OSPFv3 is identical under `router ospfv3`):

```
router ospf {
  segment-routing { mpls; }
  fast-reroute { ti-lfa; }
  area 0 {
    interface eth0 {
      enable true;
      network-type point-to-point;
      bfd { enable true; }
    }
  }
}
```

For SRv6 repairs, enable the SRv6 flavour of segment routing instead
(IS-IS shown; see the [SRv6 chapter](ch-04-00-srv6.md) for locators):

```
router isis {
  segment-routing { srv6 { locator LOC1; } }
  fast-reroute { ti-lfa; }
}
```

Notes:

- `ti-lfa` is a presence container: an empty `fast-reroute {}` block is
  a no-op.
- TI-LFA without BFD still works — you keep protection against the
  *link-down* class (kernel-autonomous) and against anything the IGP
  hold timer eventually catches. BFD is what extends the fast path to
  the link-up class.
- `fast-reroute { backup-as-primary; }` swaps the installation order so
  the TI-LFA repair becomes the active path and the SPF primary the
  shadow — an operator knob for exercising the repair path without
  rewiring the topology.

## What gets installed

For each protected destination the FIB holds two routes and one
indirection:

```
route 10.0.0.8/32 metric m    ──nhid──▶ Gp (group) ──▶ { primary nexthop }
route 10.0.0.8/32 metric m+1  ──nhid──▶ repair nexthop (labels / segs attached)
```

`Gp` is a one-member kernel nexthop group allocated per
*(primary, backup)* pair — two prefixes sharing a primary but carrying
different repairs get distinct groups, so each switches onto *its own*
repair. The `metric+1` shadow route is the kernel-autonomous link-down
path and also covers the daemon-crash window; it stays installed at all
times.

In `show ip route`, repair paths print under the primary with a `?`
repair marker in place of the FIB `*>` marker, each line carrying its
own `[distance/metric]`:

```
L2 *> 10.0.0.8/32 [115/10] via 192.168.0.2, eth0, label 16800, 00:04:15
   *?             [115/1010] via 192.168.0.6, eth1, label 16500 16800, 00:04:15
```

`show isis route detail` (and the OSPF equivalents) tag the repair with
`Backup path: TI-LFA`, and `show nexthop` renders the protection group
with a `*` on the currently-active member:

```
ID: 23 refcnt: 1 valid: true installed: true
 *primary [12] via 192.168.0.2, eth0
  backup [19] via 192.168.0.6, eth1
```

## The BFD-down fast path

```
BFD down on adjacency A
  → IGP emits ProtectSwitch (before running SPF)
  → RIB finds every protection group whose active primary is A
  → one atomic RTM_NEWNEXTHOP REPLACE per group: { primary } → { repair }
  → all protected prefixes via A forward over their repairs
  → SPF runs afterwards and re-installs post-convergence routes as usual
```

The group replace is RCU-atomic in the kernel: every route referencing
the group id forwards via the new member immediately, with no route
churn and no per-prefix work. The repair's MPLS label stack or SRv6
segment list rides on the backup nexthop object itself, so the swap
carries the full encapsulation.

The switchover is **a bridge, not a steady state** — SPF reconvergence
supersedes its kernel state within milliseconds, by design. It is
therefore observable mainly in the daemon log:

```
ProtectSwitch 192.168.0.2 table 254: rewired 3 protection group(s) onto repairs
```

(the line is only emitted when at least one group actually moved).

**Recovery** is deliberately not an in-place revert. When the adjacency
comes back, the post-flap SPF re-produces the same *(primary, backup)*
pair, which re-arms the group onto the primary member through the same
atomic replace. IS-IS additionally applies its RFC 5882 hold-down, so a
recovering BFD session doesn't flap traffic back prematurely.

## ECMP destinations: leg eviction

TI-LFA deliberately computes **no repair for ECMP destinations** — the
surviving legs *are* the protection. Kernel nexthop groups can't nest,
so the ECMP group itself becomes the switch point: on BFD-down the same
fast path **evicts the dead leg** from every kernel ECMP group that
contains it, in one atomic replace per group, before SPF. Without this,
the kernel would keep hashing flows onto the dead leg until SPF
finished.

```
ProtectSwitch 192.168.0.2 table 254: evicted failed leg from 2 ECMP group(s)
```

One caveat: kernel ECMP groups are shared by member set, so an
*unprotected* route that happens to use the same ECMP set also loses
the dead leg. That is the desirable outcome — it just means the
eviction's reach is "every route via this group", not "every protected
route".

## SR-MPLS and SRv6 parity

Both encapsulations get the full fast path. SRv6-encapsulated nexthops
participate as group members on both sides — as protected primaries and
as repairs — and the atomic replace onto an SRv6 member carries the
segment list just as it carries a label stack. (SRv6 *local SIDs* —
`seg6local` routes — are not protected routes and are unaffected.)

## Requirements and fallback

The whole mechanism rides on kernel **nexthop objects** (Linux ≥ 5.3).
zebra-rs probes for support at startup; on older kernels, or when the
daemon is started with `--no-nhid`, routes are installed with embedded
gateways and there is no indirection to swap. Everything still
*functions* — TI-LFA shadow routes install, BFD tears the adjacency
down, SPF reconverges — but failover for the link-up class is back to
detection + SPF + per-prefix FIB churn.

## Verifying

```
show isis route detail        # "Backup path: TI-LFA" on protected routes
show ip route                 # repair paths marked  *?
show nexthop                  # protection groups, * = active member
show bfd                      # session state per adjacency
```

On a switchover, watch the daemon log for the `rewired … protection
group(s) onto repairs` / `evicted failed leg from … ECMP group(s)`
lines.

The BDD suite exercises every piece end to end: `@isis_tilfa`,
`@ospfv2_tilfa`, `@ospfv3_tilfa` and the SRv6 variants cover repair
computation and the link-down class; `@tilfa_bfd`, `@ospfv2_bfd_frr`
and `@ospfv3_bfd_frr` induce a BFD-only failure (control packets
dropped, link up) and assert the switchover fires before
reconvergence; `@ecmp_bfd_evict` covers leg eviction on an ECMP
diamond. The full architecture and kernel-probe record live in
`docs/design/nexthop-protect-kernel-failover.md`.
