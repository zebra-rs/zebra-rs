# IS-IS Area Proxy (RFC 9666)

A Level-2 backbone normally sees every router of every area that
provides transit for it, and its link-state database grows with the
whole network. Area Proxy (RFC 9666, Experimental) turns that around:
an entire Level-1 area keeps providing Level-2 transit but appears to
the backbone as **one single node**. Outside routers form their
adjacencies with a *Proxy System ID*, receive exactly one *Proxy LSP*
for the whole area, and never learn the area's internal topology —
the classic fabric-as-a-transit-node design for very large networks.

zebra-rs implements the full RFC: the Area Leader election (borrowed
from RFC 9667), the Proxy LSP, the boundary behavior that hides the
area, the inside SPF rules that keep routing loop-free, and the
Segment Routing extensions including the anycast Area SID.

## How it works

Everything inside the area (the **Inside Area**) runs Level-1/Level-2
IS-IS as usual. Enabling `area-proxy` adds five cooperating
mechanisms:

1. **Participation.** Every inside router advertises an Area Proxy
   TLV (type 20) in fragment 0 of its L2 LSP — the signal "I am ready
   to play". Pseudonodes advertise it too; the boundary filter later
   keys on this TLV.
2. **Area Leader election.** Routers configured with a
   `proxy-system-id` are Leader candidates and advertise the RFC 9667
   Area Leader sub-TLV (Router Capability TLV 242, type 27) in their
   **L1** LSP — the L1 LSDB *is* the inside area, so the election
   never leaks outside. Highest priority wins; ties break on the
   highest system-id. Candidates the last L1 SPF could not reach are
   ineligible, so a silently dead leader is displaced at SPF speed,
   not LSP-lifetime speed.
3. **Readiness and the proxy identity.** Once the elected leader
   observes that *every* inside router advertises the Area Proxy TLV,
   it adds the Proxy System Identifier sub-TLV to its own — the whole
   area now shares one proxy identity, learned from the leader's LSP.
4. **The Proxy LSP.** The leader originates one L2 LSP under the
   Proxy System ID containing the area's addresses, a proxy hostname,
   the area's prefixes (lowest metric per prefix, from the L1 LSDB),
   and one adjacency per *outside* neighbor, harvested from the
   Inside Edge Routers' L2 LSPs. On leader failover the successor
   regenerates it at the next sequence number; the backbone sees an
   LSP refresh, never a topology change.
5. **The boundary.** On an *Outside Circuit*, an Inside Edge Router
   sources its L2 IIHs and SNPs from the Proxy System ID (and sends
   none at all until that ID is learned), so the outside neighbor's
   adjacency — and its TLV 22 — terminate on the proxy node. In the
   flooding direction, L2 LSPs whose source is an inside router, or
   that carry the Area Proxy TLV, are filtered: only the Proxy LSP
   and other outside LSPs cross. CSNPs and PSNPs are filtered the
   same way, and an SNP emptied by the filter is not sent.

Inside routers must not consume their own abstraction: their L2 SPF
ignores the Proxy LSP, resolves the outside routers' proxy-pointing
adjacencies back to the real edge routers, and — per RFC 9666 §3.2 —
treats every intra-area metric as smaller than any inter-area metric,
so all inside routers pick boundary exits consistently with the
outside view (which sees the area as a zero-cost node).

## Configuration

The example is the topology the BDD suite pins
(`bdd/tests/features/isis_area_proxy.feature`):

```
      Inside Area 49.0001 (all L1L2, area-proxy)      Outside (area 49.0002)
    ┌────────────────────────────────────────────┐  ┌──────────────────────┐
        r1 ─────────── r2 ─────────── r3 ═══════════ r4 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ r5
     (candidate     (candidate     (candidate,      (L2-only)        (L2-only,
      priority 100)  priority 50)   edge)                             "beyond")
```

Every inside router enables participation and — because any candidate
must be able to originate the Proxy LSP if it wins — carries the
*same* proxy identity. Only the priorities differ:

```
set router isis net 49.0001.0000.0000.0001.00
set router isis area-proxy
set router isis area-proxy proxy-system-id 0000.0000.00aa
set router isis area-proxy priority 100
set router isis area-proxy hostname zaparea
```

`priority` defaults to 64 (the DIS default); `hostname` becomes the
Dynamic Hostname TLV of the Proxy LSP, so the backbone sees the area
under one name. A router configured with `area-proxy` but no
`proxy-system-id` participates without standing for election.

### Circuit classification

The boundary needs to know which circuits face outside. By default a
circuit that is **not also a Level-1 circuit** (effective level
L2-only) on a participating instance is an Outside Circuit — exactly
the RFC 9666 §5.1 rule. On the edge router r3:

```
set router isis interface i4 circuit-type level-2-only
```

is already enough. An explicit override exists for unusual layouts:

```
set router isis interface i4 area-proxy outside
set router isis interface i2 area-proxy inside
```

The outside routers r4/r5 need nothing special — plain `is-type
level-2-only` IS-IS in their own area. They do not know Area Proxy
exists; that is the point.

## Verifying

`show isis area-proxy` is the one-stop view. On the elected leader:

```
> show isis area-proxy
IS-IS Area Proxy (RFC 9666)
Participation:   enabled
Candidacy:       priority 100 (proxy-system-id 0000.0000.00aa)
Area Leader:     r1 (priority 100) — this system
Readiness:       3/3 inside routers advertise the Area Proxy TLV — READY
Proxy System ID: 0000.0000.00aa
Advertising the Proxy System Identifier sub-TLV
Proxy LSP:       originating, 1 fragment, seq 0x00000002
```

On a non-leader the same command shows the learned identity, and on
the edge router the classified boundary:

```
> show isis area-proxy
IS-IS Area Proxy (RFC 9666)
Participation:   enabled
Candidacy:       priority 10 (proxy-system-id 0000.0000.00aa)
Area Leader:     r1 (priority 100)
Readiness:       3/3 inside routers advertise the Area Proxy TLV — READY
Proxy System ID: 0000.0000.00aa
Outside Circuits: i4
```

The proof of the abstraction lives on the **outside** router. Its only
neighbor on the boundary link is the proxy identity, and its LSDB
holds its own world plus exactly one LSP for the entire inside area:

```
r4> show isis neighbor
System Id           Interface   L  State         Holdtime SNPA
zaparea             i3          2  Up            29       06a0.ea63.54e4

r4> show isis database
r4.00-00                  *       70  0x00000002  0x39c7      1189  0/0/0
r5.00-00                          84  0x00000003  0x1a22      1180  0/0/0
zaparea.00-00                     69  0x00000003  0x413e      1188  0/0/0
```

`show isis database detail` on r4 shows the Proxy LSP's content — the
area address, the proxy hostname, one adjacency back to r4 itself, and
the area's merged prefixes:

```
zaparea.00-00                     69  0x00000002  0x433d      1173  0/0/0
  Area address: 49.0001
  Protocol Supported: IPv4
  Hostname: zaparea
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0004.00, Metric: 10
  Extended IP Reachability: 10.0.12.0/30 (Metric: 10)
```

Traffic crosses in both directions: outside routers install routes
from the Proxy LSP, and inside routers — including ones nowhere near
the boundary — reach destinations *beyond* the outside neighbor
through the §3.2 SPF rules. On the deepest inside router:

```
r1> show ip route
L2 *> 10.0.0.4/32 [115/30] via 10.0.12.2, i2, 00:02:48
L2 *> 10.0.0.5/32 [115/40] via 10.0.12.2, i2, 00:02:48
```

Note what is *absent*: `show isis topology` on an inside router never
lists a `zaparea` vertex — inside routers flood the Proxy LSP but must
never route on it.

### Leader failover

Kill the leader and the priority-50 candidate takes over. The dead
leader's LSP lingers in the LSDB un-purged, but the reachability gate
removes it from candidacy as soon as the L1 SPF notices the
adjacency loss; the successor regenerates the Proxy LSP one sequence
number higher, and the backbone converges on it without ever seeing
the area's internals change:

```
r2> show isis area-proxy
Area Leader:     r2 (priority 50) — this system
Proxy LSP:       originating, 1 fragment, seq 0x00000003
```

This is why every candidate SHOULD carry identical `proxy-system-id`,
`hostname`, and `area-sid` configuration — a leadership change must
not change the area's identity.

## Segment Routing and the Area SID

With SR-MPLS enabled inside the area
(`set router isis segment-routing mpls`), the Proxy LSP presents a
coherent SR view of the area:

- **SRGB**: advertised only when *every* inside router advertises an
  SRGB with an identical starting value; the merged range is the
  minimum of all ranges. Mismatched starting values are a logged
  error and the SRGB is omitted — fix the block configuration rather
  than expect a partial merge.
- **Prefix-SIDs**: the lowest-metric winner of each merged prefix
  carries its Prefix-SID into the Proxy LSP with the P-Flag set and
  the E-Flag cleared (the boundary consumes no label on behalf of the
  abstracted area); the R-Flag is carried through.
- **Adjacency SIDs** toward outside neighbors are copied only when
  their L-Flag is unset; zebra-rs allocates local (L-set) Adj-SIDs,
  so in an all-zebra-rs network none cross — per the RFC.

The **Area SID** gives the whole area one anycast segment:

```
set router isis area-proxy area-sid prefix 10.0.0.100/32
set router isis area-proxy area-sid index 500
```

The leader distributes it in the Area Proxy TLV and advertises the
prefix as a Node SID in the Proxy LSP. Every Inside Edge Router —
leader or not — installs a pop for `SRGB-start + index`, so a packet
carrying the SID is delivered to whichever edge receives it and the
SID is consumed there. From the backbone:

```
r3> show ip route 10.0.0.1/32
L2 *> 10.0.0.1/32 [115/20] via 10.0.23.1, i2, label (16100)

r3> show ip route 10.0.0.100/32
L2 *> 10.0.0.100/32 [115/10] via 10.0.23.1, i2, label (16500)
```

(the parenthesized label is the no-PHP rendering — the copied SIDs
carry the P-Flag), and on the edge router:

```
r2> show mpls ilm
16500 ...  pop (Node SID index 500)
```

The SR behaviour has its own BDD feature,
`bdd/tests/features/isis_area_proxy_sr.feature`.

## Operational notes and limitations

- **Status.** RFC 9666 is Experimental, and the only other known
  implementation is Arista EOS (4.25.1F+). Wire-level interop against
  EOS has not yet been exercised; treat multi-vendor deployments as
  pilot territory.
- **All inside routers must be L1L2** on the inside links, and all of
  them must enable `area-proxy` — the leader withholds the proxy
  identity until every router in the L1 LSDB signals readiness, and
  the readiness census in `show isis area-proxy` tells you who is
  missing.
- **Boundary LANs with more than one Inside Edge Router are not
  supported** (RFC 9666 §5.2): two edges would both speak as the
  proxy identity on the same LAN. zebra-rs drops proxy-sourced IIHs
  defensively, but the supported design is point-to-point boundary
  circuits (or a single edge per LAN).
- **Misconfiguration is logged, not guessed around**: multiple
  distinct Proxy System IDs in the area, and mismatched SRGB starting
  values, each produce a warning in the log while the feature holds
  back the affected advertisement.
- **Metric precedence bounds.** The §3.2 intra-before-inter rule is
  implemented by packing both metric domains into the SPF cost;
  ordering is exact while each domain's *path total* stays below
  65536 (per-link metrics cap at 65535 for the comparison). Far above
  realistic inside-area diameters, but worth knowing if you run
  deliberately huge metrics.
- **Scope.** IPv4 and IPv6 prefixes are merged into the Proxy LSP;
  the SR merges cover SR-MPLS (SRv6 locator and MSD merging are not
  implemented), Multi-Topology is not merged, and — as the RFC itself
  states — MPLS *transit* through the area is out of scope: the Area
  Proxy data path is IP and SR.
