# Flexible Algorithm (Flex-Algo)

IS-IS Flexible Algorithm (RFC 9350) lets one IGP domain compute several
constrained topologies over the same links at the same time. Each
algorithm — a number from 128 to 255 — carries its own definition
(metric type plus link constraints), its own SPF, its own per-node
Prefix-SIDs, and therefore its own labels: which path a packet takes is
decided purely by which label is pushed onto it. Algorithm 0 (the
ordinary shortest path) keeps running unchanged underneath.

The classic use cases: keep a traffic class off certain links
(geography, jurisdiction, security), build a low-latency plane routed on
measured delay, or run disjoint planes for dual-plane services — all
without a second IGP, tunnels, or RSVP-TE state.

zebra-rs implements Flex-Algo for IS-IS over both Segment Routing
dataplanes: SR-MPLS (per-algorithm Prefix-SIDs, RFC 8667) and SRv6
(per-algorithm locators, RFC 9352). This chapter is the configuration
reference; a complete worked lab —
[`playset/isis-flexalgo`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo)
— walks the same configuration end to end with real traffic, and the
[AI-designed Flex-Algorithm demo](ch-13-02-flexalgo-ai-demo.md) has an
AI author it from intent.

## The four moving parts

A working Flex-Algorithm deployment is exactly four pieces of
configuration. Two are global to the router, two are per-interface:

| # | Config path | Scope | Purpose |
|---|---|---|---|
| 1 | `affinity-map` | top level (shared with OSPF) | Bind operator-friendly color names to bit positions (RFC 7308 Extended Admin Group) |
| 2 | `router isis interface <if> affinity` | per link | Color the links the constraint should act on |
| 3 | `router isis flex-algo <128-255>` | per instance | The Flexible Algorithm Definition (FAD): metric type, dataplane, constraints — and participation itself |
| 4 | `router isis interface <lo> ipv4 flex-algo-prefix-sid` | per loopback | A second Prefix-SID valid only inside that algorithm |

The division of labor matters: the **FAD never names a link**, and a
**link never names an algorithm**. The FAD says "exclude anything
colored `trans-pacific`"; the link coloring says "this link is
`trans-pacific`". Change which links carry the color and the
algorithm's topology follows — no other configuration moves.

For SRv6 there is a fifth piece,
`segment-routing srv6 flex-algo-locator`, covered
[below](#srv6-per-algorithm-locators).

## Complete example

One router from the
[isis-flexalgo playset](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo):
Tokyo (`tk`) participates in algorithm 128, which excludes trans-Pacific
links. Its `tk-sj` interface is a trans-Pacific link and carries the
color; `tk-sg` does not. The loopback holds two Prefix-SIDs — index
1100 for algorithm 0 and index 3100 for algorithm 128.

As a startup YAML (`--config-file`):

```yaml
affinity-map:
  affinity:
  - name: trans-pacific
    bit-position: 0
router:
  isis:
    net: 49.0000.0000.0000.0011.00
    is-type: level-2-only
    segment-routing:
      mpls: {}
    te-router-id: 10.0.0.11
    flex-algo:
    - algo: 128
      metric-type: igp
      dataplane:
        sr-mpls: true
      affinity:
        exclude-any:
        - trans-pacific
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 1100
        flex-algo-prefix-sid:
        - algo: 128
          index: 3100
    - if-name: tk-sj
      network-type: point-to-point
      affinity:
      - trans-pacific
      ipv4:
        enabled: true
      metric: 10
    - if-name: tk-sg
      network-type: point-to-point
      ipv4:
        enabled: true
      metric: 10
```

The same configuration in the `set`-line (formal) syntax — what
configure mode accepts, what `show running-config formal` prints, and
what the MCP `apply-config` tool consumes. Assuming IS-IS with SR-MPLS
is already running, the Flex-Algo delta is only these lines:

```
set affinity-map affinity trans-pacific bit-position 0
set router isis flex-algo 128 metric-type igp
set router isis flex-algo 128 dataplane sr-mpls true
set router isis flex-algo 128 affinity exclude-any trans-pacific
set router isis interface tk-sj affinity trans-pacific
set router isis interface lo ipv4 flex-algo-prefix-sid 128 index 3100
```

List keys are written as bare values (`flex-algo 128`,
`flex-algo-prefix-sid 128`), and a leaf-list takes one line per value —
excluding two colors is two `exclude-any` lines, not one line with two
names. Every `set` line has a `delete` counterpart;
`delete router isis flex-algo 128` removes the whole definition in one
line.

On at least one router — preferably two, for redundancy — additionally
originate the definition:

```
set router isis flex-algo 128 advertise-definition true
```

In the playset this is `ch` (Chicago) and `sg` (Singapore); every other
router carries the identical definition without the flag.

## Configuration reference

### `affinity-map` — the color table

```
set affinity-map affinity <name> bit-position <0-255>
```

Binds a name to one bit of the 256-bit Extended Admin Group (RFC 7308).
The table lives at the top level, outside `router isis`, because it is
shared by every IGP (IS-IS, OSPFv2, OSPFv3): one name space, one bit
numbering, referenced by per-link colors and by FAD constraints alike.

The table itself is **never advertised**. Only the resulting bitmaps
travel in LSPs, so every router in the domain must carry the same
name-to-bit mapping — if router A maps `trans-pacific` to bit 0 and
router B maps it to bit 1, the two prune different links and the
algorithm's topology silently diverges.

`bit-position` is mandatory. Names that a link or FAD references but
that do not resolve in the table are skipped at LSP-build/SPF time (the
reference itself is a plain string, so configuration can be staged in
any order).

### Link coloring — `affinity` on the interface

```
set router isis interface <if-name> affinity <name>
```

A leaf-list of affinity-map names on an IS-IS interface. The union of
the referenced bits is advertised as an Extended Admin Group bitmap
inside the link's Application-Specific Link Attributes sub-TLV (ASLA,
RFC 9479), marked as applying to the Flex-Algorithm application. The
ASLA is emitted only when at least one configured flex-algo actually
references link attributes, so coloring links in advance costs nothing
on the wire.

Color **both ends** of every link the constraint should act on. Each
router advertises (and each remote SPF prunes) its own directed half of
the link; one-sided coloring leaves the topology asymmetric. In the
playset, all three trans-Pacific links are colored on all six
interfaces: `sj-tk`/`tk-sj`, `se-sg`/`sg-se`, `sj-sy`/`sy-sj`.

A link may carry any number of colors, and different algorithms can
test different subsets — the coloring describes the link, not the
algorithm.

### The algorithm definition — `flex-algo`

```
set router isis flex-algo <128-255>
```

Creates one algorithm entry. **Creating the entry is what makes this
router a participant**: the algorithm number is added to the SR-Algorithm
advertisement in the Router Capability TLV, and the router computes a
per-algorithm SPF for it. Identifiers 0–127 are IANA-reserved;
user-defined algorithms are 128–255.

zebra-rs computes each algorithm with the **locally configured
definition**, so every participating router must carry the same,
complete definition — constraints included. A bare `flex-algo 128` with
no constraints would participate but compute *unconstrained* paths,
quietly violating the algorithm's intent. Configure the identical entry
on every router; that is also what RFC 9350 demands of a consistent
domain.

Leaves under `flex-algo <n>`:

| Leaf | Values / default | Meaning |
|---|---|---|
| `advertise-definition` | `true` / `false` (default `false`) | Originate the FAD sub-TLV in Router Capability TLV 242. At least one router per area must advertise — preferably two, for redundancy. Without any advertised FAD in the area, participants must not compute paths for the algorithm. |
| `metric-type` | `igp` (default), `min-unidir-link-delay`, `te-default` | FAD Metric-Type 0 / 1 / 2. See below. |
| `priority` | `0-255`, default `128` | FAD advertisement priority (RFC 9350 §5.1). When several routers advertise a FAD for the same algorithm, the highest priority wins. |
| `prefix-metric` | `true` / `false` (default `false`) | Sets the M-flag in the FAD Flags sub-TLV: path metrics to a prefix include the advertised prefix metric. |
| `dataplane sr-mpls` | `true` / `false` (default `false`) | Install this algorithm's paths as SR-MPLS label entries (per-algo Prefix-SIDs). |
| `dataplane srv6` | `true` / `false` (default `false`) | Install this algorithm's paths over SRv6 (per-algo locator). |
| `dataplane ip` | `true` / `false` (default `false`) | Plain-IP forwarding participation flag. |
| `affinity include-any <name>` | leaf-list | Keep only links carrying **at least one** of these colors. |
| `affinity include-all <name>` | leaf-list | Keep only links carrying **all** of these colors. |
| `affinity exclude-any <name>` | leaf-list | Prune every link carrying **any** of these colors. |
| `srlg-exclude <name>` | leaf-list | FAD Exclude-SRLG sub-TLV (RFC 9350 §6.2), referencing `/srlg/group` names. Advertised in the FAD; **not yet enforced at SPF time** in the current release. |
| `fast-reroute disable` | empty leaf | Opt this algorithm out of instance-level TI-LFA. See [TI-LFA interaction](#ti-lfa-interaction). |

**Metric types.** `igp` (Metric-Type 0) routes on the ordinary IS-IS
link metric and needs nothing extra. `min-unidir-link-delay`
(Metric-Type 1, RFC 8570) routes on each link's advertised minimum
unidirectional delay: the per-interface
`router isis interface <if> te-metric min-delay` (microseconds) supplies
it, and a link that advertises **no** delay is pruned from that
algorithm's topology entirely (RFC 9350 §15) — so a delay-based
algorithm needs delay configured on every link it should be able to
use. `te-default` (Metric-Type 2, RFC 5305) is accepted and advertised
but not yet honored in path computation — it currently falls back to
the IGP metric.

**Constraint semantics.** All three affinity constraints may be
combined; a link survives only if it passes every configured test. The
common patterns:

* `exclude-any` — avoidance: "never cross a link colored X". The
  playset's trans-Pacific exclusion.
* `include-any` — confinement to a set of colored links: the same
  colors, constraint inverted ("stay **on** trans-Pacific links").
* `include-all` — require a conjunction of colors (e.g. `encrypted`
  *and* `low-latency`).

Uncolored links pass `exclude-any` and fail both `include-*` tests —
so an `include-*` algorithm only ever uses links that are explicitly
colored.

### Per-algorithm Prefix-SIDs — `flex-algo-prefix-sid`

```
set router isis interface <if-name> ipv4 flex-algo-prefix-sid <algo> index <n>
set router isis interface <if-name> ipv4 flex-algo-prefix-sid <algo> absolute <label>
```

A second (third, …) Prefix-SID for the interface's prefix, advertised
as an additional Prefix-SID sub-TLV whose Algorithm field carries
`<algo>` (RFC 9350 §7) — alongside the algorithm-0 SID from the plain
`prefix-sid` container. Attach it to the loopback: the SID identifies
this node *within that algorithm's topology*, and pushing it is how
traffic is steered onto the constrained paths.

Like the algo-0 `prefix-sid`, either an `index` into the SRGB or an
`absolute` label can be given.

Two rules for choosing indexes:

* **Indexes must not overlap across algorithms.** All algorithms
  resolve indexes against the *same* SRGB, so reusing an index
  cross-wires two topologies in the label space. Use disjoint blocks —
  the playset uses algo-0 indexes 100..1100 and algo-128 indexes
  2100..3100 (algo-0 index + 2000), which with SRGB base 16000 yields
  labels 16100..17100 and 18100..19100.
* **Every participant needs one.** A router without a Prefix-SID for
  the algorithm cannot terminate constrained traffic, and a TI-LFA
  repair that would pass through it is dropped rather than approximated
  with an algorithm-0 label.

Adjacency-SIDs need no per-algorithm variant: an Adj-SID means "pop and
forward over this link" regardless of algorithm and is shared by all of
them.

### SRv6: per-algorithm locators

On the SRv6 dataplane the per-algorithm identity is a locator, not a
label:

```
set router isis segment-routing srv6 flex-algo-locator <algo> locator <name>
```

The named `/segment-routing/locator` is advertised in SRv6 Locator
TLV 27 with its Algorithm field set to `<algo>` (RFC 9352 §7.1); the
base `locator` leaf stays algorithm 0. Set `dataplane srv6 true` in the
FAD instead of (or alongside) `sr-mpls`. The locator name is a plain
string, so the IS-IS side can be committed before the global locator
exists.

## Rules for a working deployment

The checklist an authoring operator — human or AI — must satisfy.
Everything here follows from the sections above; violations mostly fail
*silently*, as wrong paths rather than error messages:

1. **Identical `affinity-map` on every router.** The name-to-bit table
   is not advertised; only agreement makes bit 0 mean the same thing
   everywhere.
2. **Identical, complete `flex-algo` definition on every participating
   router.** Participation is the entry's existence; the constraints
   must ride along, because each router computes with its local
   definition.
3. **`advertise-definition true` on at least one router, preferably
   two.** Without an advertised FAD the algorithm is dead in the
   domain, whatever is configured locally.
4. **Color both ends of every constrained link.**
5. **Per-algorithm SID indexes disjoint from algorithm 0 and from each
   other**, all within SRGB range.
6. **A `flex-algo-prefix-sid` on every participant's loopback** (or a
   `flex-algo-locator` for SRv6).
7. **Don't over-constrain.** Excluding too much partitions the
   algorithm's topology: destinations simply drop out of its RIB while
   algorithm 0 keeps working, and nothing warns. Check reachability
   after every constraint change (in the playset, downing the one
   EU–AP link partitions algorithm 128 while algorithm 0 is
   untouched).
8. For `min-unidir-link-delay`: **delay must be configured/advertised
   on every usable link** — no delay, no link.

## Applying at runtime

Flex-Algo configuration commits like any other zebra-rs configuration:
transactionally, with validation, through any of the management
surfaces — `vty` configure mode, `vtyctl apply`, the gRPC `Apply`
service, or the MCP `apply-config` tool. A batch of `set`/`delete`
lines is atomic per commit: on any error nothing is applied and the
offending line is reported.

On commit, IS-IS re-originates the self-LSP immediately (new SR-Algorithm
participation, FAD, ASLA colors, and per-algo SIDs), floods, and every
participant re-runs the per-algorithm SPF — a domain converges within a
few seconds. The reverse is symmetric: `delete` the four parts and the
per-algorithm RIB, labels, and advertisements disappear with them.

Because `show running-config formal` emits exactly the syntax
`configure`/`apply-config` accepts, extract-modify-apply round-trips
without translation — the property the
[AI demo](ch-13-02-flexalgo-ai-demo.md) is built on.

## Verification

`show isis flex-algo` is the summary view — local algorithms, peer
FADs, and per-peer participation:

```
tk>show isis flex-algo
Area 49.0000:

Local Flex-Algorithms:
  Algo  Metric                 Priority Adv FRR       Constraints
  128   igp                    -        no  off       exclude-any=trans-pacific

Level-2:
  Peer FADs:
    ch (0000.0000.0003): algo 128 priority 128 metric-type 0 calc-type 0
    sg (0000.0000.0009): algo 128 priority 128 metric-type 0 calc-type 0
  Peer SR-Algorithm Participation:
    se (0000.0000.0001): [0, 128]
    sj (0000.0000.0002): [0, 128]
    ...
```

The healthy signature: every peer lists the algorithm in its
participation set, and at least one `Peer FADs` entry exists. `Adv no`
means this router does not originate the FAD itself. Right after
startup a peer may briefly show `[0]` while its updated LSP is still
flooding.

Adding the algorithm id narrows the view
(`show isis flex-algo 128`), and the id is the entry point to every
per-algorithm view:

```
show isis flex-algo <128-255> { route | topology | spf | graph | repair-list }
```

Each has an algorithm-0 twin (`show isis route`, `show isis graph`, …)
to compare against — see [show isis](ch-14-04-show-isis.md) for the
full grammar. The two most useful during bring-up:

* `show isis flex-algo <n> graph` — the link-state graph *after* FAD
  pruning. A colored-and-excluded neighbor is simply absent. This is
  the first thing to check when paths look wrong: is the link actually
  gone from the graph?
* `show isis flex-algo <n> route` — the algorithm's own RIB, with the
  per-algorithm labels. In the playset, every US destination leaves
  Tokyo via Singapore (`tk-sg`) at metric 40–60 while `show ip route`
  keeps crossing the Pacific at 20.

On the wire, one LSP shows all the machinery at once
(`show isis database detail`):

```
  Router Capability: 10.0.0.11, D:0 S:0
   Segment Routing Algorithm: SPF(0) FlexAlgo(128)      <- participation
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0002.00, Metric: 10
    Application Specific Link Attributes:
     Applications: Flex-Algo
      Ext Admin Group: [0] 0x00000001                   <- link color, bit 0
  Extended IP Reachability: 10.0.0.11/32 (Metric: 10)
   SID: Index(1100), Algorithm: SPF(0), ...
   SID: Index(3100), Algorithm: FlexAlgo(128), ...      <- per-algo SID
```

And `show mpls ilm` shows both algorithms' label blocks installed in
the one table — same destinations, two labels, two different outgoing
interfaces. Steering a packet onto the constrained plane is pushing the
algorithm's label; the
[playset README](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo)
walks a real ping over algorithm 128 hop by hop, TTL-verified.

## TI-LFA interaction

TI-LFA is enabled once, at the instance level
(`set router isis fast-reroute ti-lfa`), and every algorithm the router
participates in inherits it — each algorithm's repair is computed
inside its *own* constrained topology and expressed with its *own*
SIDs, as RFC 9350 §12 requires. A repair built from algorithm-0
segments could traverse the very link the FAD excludes, silently
defeating the constraint; zebra-rs never does that, and drops a repair
outright when a node on it advertises no SID for the algorithm.

To exempt one algorithm from protection:

```
set router isis flex-algo 128 fast-reroute disable
```

The per-algorithm state shows in the `FRR` column of
`show isis flex-algo`: `on` (inherited and computed), `off`
(instance-level TI-LFA not enabled), or `disabled` (opted out). Per-algo
repairs are inspected with `show isis flex-algo <n> repair-list`.

## Wire encoding

| What | Where | RFC |
|---|---|---|
| Participation (SR-Algorithm list) | SR-Algorithm sub-TLV 19 in Router Capability TLV 242 | RFC 8667 §3.2, RFC 9350 §5.2 |
| FAD (metric-type, calc-type, priority, constraints) | FAD sub-TLV 26 in Router Capability TLV 242 | RFC 9350 §5.1 |
| Link colors | Extended Admin Group in the ASLA sub-TLV, Flex-Algo application bit | RFC 7308, RFC 9479 |
| Per-algorithm Prefix-SID | Prefix-SID sub-TLV with Algorithm = 128–255 | RFC 8667 §2.1, RFC 9350 §7 |
| Per-algorithm SRv6 locator | SRv6 Locator TLV 27, Algorithm field | RFC 9352 §7.1 |

## Related

* [`playset/isis-flexalgo`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo)
  — the full worked lab: eleven routers, three regions, algorithm 128
  excluding trans-Pacific links, with traffic proof.
* [AI-Designed Flex-Algorithm](ch-13-02-flexalgo-ai-demo.md) — an AI
  authors exactly this configuration from a sentence of intent, over
  MCP.
* [show isis reference](ch-14-04-show-isis.md) — the per-algorithm
  show views.
* [SRLG](ch-07-02-isis-srlg.md) — the named-group table
  `srlg-exclude` references.
