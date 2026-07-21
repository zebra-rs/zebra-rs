# IS-IS Flexible Algorithm (RFC 9350)

This playset demonstrates IS-IS Flexible Algorithm over SR-MPLS. An
eleven-node global backbone runs the standard shortest-path algorithm
(algorithm 0) *and* a second, constrained algorithm 128 at the same time,
over the same links. Algorithm 128 is defined to avoid every trans-Pacific
link, so traffic between Tokyo and the United States is forced the long way
round — through Asia and Europe — while algorithm 0 keeps using the direct
Pacific crossing.

Each node runs zebra-rs in its own network namespace, and its YAML
configuration is injected with the `vtyctl apply` command.

## Topology

Eleven nodes in three regions. The region of each node comes from
`ontology.json`, which is the input the Flex-Algorithm design is derived
from:

```
        AP                      US                        EU
  ┌──────────────┐      ┌──────────────────┐      ┌─────────────────┐
  │ tk  Tokyo    │      │ se  Seattle      │      │ ln  London      │
  │ sy  Sydney   │      │ sj  San Jose     │      │ fr  Frankfurt   │
  │ sg  Singapore│      │ ch  Chicago      │      └─────────────────┘
  └──────────────┘      │ da  Dallas       │
                        │ va  Virginia     │
                        │ at  Atlanta      │
                        └──────────────────┘
```

The six links that cross a region boundary are what the demo turns on:

```
  sj ── tk    US <-> AP    trans-pacific   excluded by algorithm 128
  se ── sg    US <-> AP    trans-pacific   excluded by algorithm 128
  sj ── sy    US <-> AP    trans-pacific   excluded by algorithm 128
  ch ── ln    US <-> EU
  va ── fr    US <-> EU
  fr ── sg    EU <-> AP
```

Once all three trans-Pacific links are excluded, the only way for an AP node
to reach a US node in algorithm 128 is `sg -> fr` into Europe and onward —
which is exactly the "must go through Asia and Europe" property we are
after. Every link has metric 10, and the full link list is in the appendix.

## Bring up all nodes

`./up.sh` sets up all namespaces, starts the zebra-rs routing daemon in each
of them, and injects the initial configuration.

``` shell
$ ./up.sh
bring up
runtime dir: /tmp/zebra-rs-playset/isis-flexalgo
teardown: stop zebra-rs
teardown: delete namespace se
teardown: delete namespace sj
...
create namespace: sg
create namespace: sy
create namespace: tk
create link: se-sg (se) <-> sg-se (sg)
create link: se-sj (se) <-> sj-se (sj)
create link: se-ch (se) <-> ch-se (ch)
create link: sj-sy (sj) <-> sy-sj (sy)
...
start zebra-rs: ch
start zebra-rs: da
...
apply config: sy
applied
apply config: tk
applied
```

You can then list the namespaces:

``` shell
$ ip netns
tk
sy
sg
fr
ln
at
va
da
ch
sj
se
```

`./down.sh` tears the whole thing back down.

## Algorithm 0: the unconstrained baseline

Let's look at the ordinary routing table on node `tk` (Tokyo).

``` shell
$ sudo ip netns exec tk vty
tk>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

L2 *> 10.0.0.1/32 [115/30] via 192.168.6.1, tk-sj, label 16100, weight 1, 00:00:08
                           via 192.168.15.1, tk-sg, label 16100, weight 1, 00:00:08
L2 *> 10.0.0.2/32 [115/20] via 192.168.6.1, tk-sj, label (16200), 00:00:08
L2 *> 10.0.0.3/32 [115/30] via 192.168.6.1, tk-sj, label 16300, 00:00:08
L2 *> 10.0.0.4/32 [115/30] via 192.168.6.1, tk-sj, label 16400, 00:00:08
L2 *> 10.0.0.5/32 [115/40] via 192.168.6.1, tk-sj, label 16500, weight 1, 00:00:08
                           via 192.168.15.1, tk-sg, label 16500, weight 1, 00:00:08
L2 *> 10.0.0.6/32 [115/40] via 192.168.6.1, tk-sj, label 16600, 00:00:08
L2 *> 10.0.0.7/32 [115/40] via 192.168.6.1, tk-sj, label 16700, weight 1, 00:00:08
                           via 192.168.15.1, tk-sg, label 16700, weight 1, 00:00:08
L2 *> 10.0.0.8/32 [115/30] via 192.168.15.1, tk-sg, label 16800, 00:00:08
L2 *> 10.0.0.9/32 [115/20] via 192.168.15.1, tk-sg, label (16900), 00:00:08
L2 *> 10.0.0.10/32 [115/30] via 192.168.6.1, tk-sj, label 17000, weight 1, 00:00:08
                            via 192.168.15.1, tk-sg, label 17000, weight 1, 00:00:08
C  *> 10.0.0.11/32 is directly connected, lo, 00:00:09
```

This is plain SR-MPLS: `sj` (San Jose, `10.0.0.2`) is one hop away over the
trans-Pacific link `tk-sj`, and most of the US is reached through it. The
parenthesized labels such as `(16200)` mean implicit-null — the SID owner is
directly adjacent, so penultimate-hop popping applies.

Note that `show ip route` only ever shows algorithm 0. Flex-Algorithm routes
live in their own per-algorithm RIB, shown further down.

## Take a look at the YAML configuration

Node `tk`'s configuration is in `tk.yaml`:

``` yaml
interface:
- if-name: lo
  ipv4:
    address: 10.0.0.11/32
- if-name: tk-sj
  ipv4:
    address: 192.168.6.2/24
- if-name: tk-sg
  ipv4:
    address: 192.168.15.2/24
system:
  hostname: tk
affinity-map:
  affinity:
  - name: trans-pacific
    bit-position: 0
router:
  isis:
    net: 49.0000.0000.0000.0011.00
    hostname: tk
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

There are four moving parts, and they are worth separating:

* **`affinity-map`** is the global name-to-bit table (RFC 7308 Extended
  Admin Group). It binds the operator-friendly name `trans-pacific` to bit
  position 0. This table is *not* advertised; every router needs the same
  copy so that everyone agrees what bit 0 means. It lives at the top level
  because it is shared with OSPF.

* **The per-link `affinity`** list colours `tk-sj` — the Tokyo-to-US link —
  with `trans-pacific`. `tk-sg` carries no affinity. This is the only place
  the topology is described; the algorithm definition below never names a
  link.

* **`flex-algo 128`** is the Flex-Algorithm Definition (FAD). It says: use
  the IGP metric, forward over SR-MPLS, and `exclude-any: trans-pacific` —
  prune every link carrying that colour before running SPF.

* **`flex-algo-prefix-sid`** gives the loopback a *second* Prefix-SID, index
  3100, valid only in algorithm 128, alongside the algorithm-0 index 1100.
  Two algorithms means two independent paths to the same loopback, so they
  need two different labels to steer with.

In this playset only `ch` and `sg` additionally set
`advertise-definition: true`. At least one router per area must originate
the FAD; two are configured for redundancy, one in the US and one in AP.
Every other node carries the identical definition and simply participates.

A note on the SID numbering: algorithm-0 indexes are 100..1100 and
algorithm-128 indexes are 2100..3100. They must not overlap, because both
resolve against the *same* SRGB (base 16000) — reusing an index across
algorithms would collide in the label space and cross-wire the two
topologies.

## How the constraint reaches the wire

Everything above is carried in `tk`'s own LSP. This one dump shows all
three mechanisms at once:

``` shell
tk>show isis database detail
tk.00-00                  *      178  0x00000001  0xb581      1190  0/0/0
  Area address: 49.0000
  Protocol Supported: IPv4
  LSP Buffer Size: 1492
  Hostname: tk
  Router Capability: 10.0.0.11, D:0 S:0
   Segment Routing: I:1 V:1, Global Block: Label(16000), Range: 8000
   Segment Routing Algorithm: SPF(0) FlexAlgo(128)
   Segment Routing Local Block: Label(15000), Range: 100
  TE Router ID: 10.0.0.11
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0002.00, Metric: 10
    Application Specific Link Attributes:
     L:0 SABM: 0x10 UDABM: 0x
     Applications: Flex-Algo
      Ext Admin Group: [0] 0x00000001
    Adjacency SID: Label(15000), Flag: F:0 B:0 V:1 L:1 S:0 P:0, Weight: 0
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0009.00, Metric: 10
    Adjacency SID: Label(15001), Flag: F:0 B:0 V:1 L:1 S:0 P:0, Weight: 0
  Extended IP Reachability: 10.0.0.11/32 (Metric: 10)
   SID: Index(1100), Algorithm: SPF(0), Flags: R:0 N:1 P:0 E:0 V:0 L:0
   SID: Index(3100), Algorithm: FlexAlgo(128), Flags: R:0 N:1 P:0 E:0 V:0 L:0
  Extended IP Reachability: 192.168.6.0/24 (Metric: 10)
  Extended IP Reachability: 192.168.15.0/24 (Metric: 10)
```

* `Segment Routing Algorithm: SPF(0) FlexAlgo(128)` is the *participation*
  advertisement — `tk` computes and forwards both algorithms.
* Neighbour `0000.0000.0002` is `sj`, i.e. the link `tk-sj`. It carries an
  **Application Specific Link Attributes** sub-TLV (ASLA, RFC 9479) with
  `Applications: Flex-Algo` and `Ext Admin Group: [0] 0x00000001` — bit 0
  set, the `trans-pacific` colour. Neighbour `0000.0000.0009` (`sg`) has no
  ASLA at all, because that link is uncoloured. This is the constraint
  crossing the wire; remote routers prune the link using this bit, not using
  any local configuration.
* The loopback advertises **two** Prefix-SIDs, one per algorithm.

## Examine the Flex-Algorithm state

``` shell
tk>show isis flex-algo
Area 49.0000:

Local Flex-Algorithms:
  Algo  Metric                 Priority Adv Constraints
  128   igp                    -        no  exclude-any=trans-pacific

Level-2:
  Peer FADs:
    ch (0000.0000.0003): algo 128 priority 128 metric-type 0 calc-type 0
    sg (0000.0000.0009): algo 128 priority 128 metric-type 0 calc-type 0
  Peer SR-Algorithm Participation:
    se (0000.0000.0001): [0, 128]
    sj (0000.0000.0002): [0, 128]
    ch (0000.0000.0003): [0, 128]
    da (0000.0000.0004): [0, 128]
    va (0000.0000.0005): [0, 128]
    at (0000.0000.0006): [0, 128]
    ln (0000.0000.0007): [0, 128]
    fr (0000.0000.0008): [0, 128]
    sg (0000.0000.0009): [0, 128]
    sy (0000.0000.0010): [0, 128]
```

`Adv no` on the local entry means `tk` is not a FAD originator; it uses the
definition learned from `ch` and `sg`, both of which appear under
`Peer FADs`. Every one of the ten peers reports `[0, 128]`, so the whole
domain participates.

Right after `./up.sh` a node may briefly show `[0]` for a peer whose updated
LSP is still flooding. It settles within a few seconds.

## Algorithm 128: the constrained paths

``` shell
tk>show isis flex-algo route algorithm 128
Area 49.0000:

Level-2 Algorithm 128:
  Prefix               Metric   Nexthop          Interface    Label
  10.0.0.1/32          60       192.168.15.1     tk-sg        18100
  10.0.0.2/32          60       192.168.15.1     tk-sg        18200
  10.0.0.3/32          50       192.168.15.1     tk-sg        18300
  10.0.0.4/32          60       192.168.15.1     tk-sg        18400
  10.0.0.5/32          40       192.168.15.1     tk-sg        18500
  10.0.0.6/32          50       192.168.15.1     tk-sg        18600
  10.0.0.7/32          40       192.168.15.1     tk-sg        18700
  10.0.0.8/32          30       192.168.15.1     tk-sg        18800
  10.0.0.9/32          20       192.168.15.1     tk-sg        18900
  10.0.0.10/32         30       192.168.15.1     tk-sg        19000
```

This is the whole point of the demo. **Every** destination leaves Tokyo over
`tk-sg` towards Singapore. The `tk-sj` link — one hop from San Jose in
algorithm 0 — is not used for anything, because the FAD pruned it before SPF
ran. Reaching San Jose (`10.0.0.2`) now costs 60 instead of 20.

The reverse direction behaves the same way. On `se` (Seattle), which has a
trans-Pacific link `se-sg` of its own:

``` shell
se>show isis flex-algo route algorithm 128
Area 49.0000:

Level-2 Algorithm 128:
  Prefix               Metric   Nexthop          Interface    Label
  10.0.0.2/32          20       192.168.1.2      se-sj        18200
  10.0.0.3/32          20       192.168.2.2      se-ch        18300
  10.0.0.4/32          30       192.168.1.2      se-sj        18400
  10.0.0.4/32          30       192.168.2.2      se-ch        18400
  10.0.0.5/32          30       192.168.2.2      se-ch        18500
  10.0.0.6/32          40       192.168.1.2      se-sj        18600
  10.0.0.6/32          40       192.168.2.2      se-ch        18600
  10.0.0.7/32          30       192.168.2.2      se-ch        18700
  10.0.0.8/32          40       192.168.2.2      se-ch        18800
  10.0.0.9/32          50       192.168.2.2      se-ch        18900
  10.0.0.10/32         60       192.168.2.2      se-ch        19000
  10.0.0.11/32         60       192.168.2.2      se-ch        19100
```

Seattle reaches Tokyo (`10.0.0.11`) eastwards via `se-ch` at a cost of 60,
even though Singapore is a single directly-connected hop away on `se-sg`.
Prefixes with two rows (`10.0.0.4`, `10.0.0.6`) are ECMP within
algorithm 128.

## `show mpls ilm` — two label ranges, one table

``` shell
se>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> i 115  15000  Pop         SR Adj (idx 0  )   se-sj        192.168.1.2
*> i 115  15001  Pop         SR Adj (idx 1  )   se-ch        192.168.2.2
*> i 115  15002  Pop         SR Adj (idx 2  )   se-sg        192.168.0.2
*> i 115  16100  Pop         SR Pfx (idx 100)   lo           10.0.0.1
*> i 115  16200  Pop         SR Pfx (idx 200)   se-sj        192.168.1.2
*> i 115  16300  Pop         SR Pfx (idx 300)   se-ch        192.168.2.2
...
*> i 115  16900  Pop         SR Pfx (idx 900)   se-sg        192.168.0.2
*> i 115  17000  17000       SR Pfx (idx 1000)  se-sg        192.168.0.2
*> i 115  17000  17000       SR Pfx (idx 1000)  se-sj        192.168.1.2
*> i 115  17100  17100       SR Pfx (idx 1100)  se-sg        192.168.0.2
*> i 115  17100  17100       SR Pfx (idx 1100)  se-sj        192.168.1.2
*> i 115  18200  Pop         SR Pfx (idx 2200)  se-sj        192.168.1.2
*> i 115  18300  Pop         SR Pfx (idx 2300)  se-ch        192.168.2.2
*> i 115  18400  18400       SR Pfx (idx 2400)  se-sj        192.168.1.2
*> i 115  18400  18400       SR Pfx (idx 2400)  se-ch        192.168.2.2
*> i 115  18500  18500       SR Pfx (idx 2500)  se-ch        192.168.2.2
...
*> i 115  18900  18900       SR Pfx (idx 2900)  se-ch        192.168.2.2
*> i 115  19000  19000       SR Pfx (idx 3000)  se-ch        192.168.2.2
*> i 115  19100  19100       SR Pfx (idx 3100)  se-ch        192.168.2.2
```

The `161xx`-`171xx` entries are algorithm 0 and the `182xx`-`191xx` entries
are algorithm 128, in one ILM. The contrast is easiest to see on Tokyo's two
node SIDs:

| label | algo | outgoing interface | direction |
|:------|:-----|:-------------------|:----------|
| 17100 | 0    | `se-sg` / `se-sj`  | across the Pacific |
| 19100 | 128  | `se-ch`            | eastward via Europe |

Same destination, same router, two labels, two completely different paths.
That is what a Flex-Algorithm buys you: the choice of path is made by which
label you push.

## Send real traffic over algorithm 128

`ping` on its own follows algorithm 0, because that is what the IP routing
table holds. To exercise the constrained path we push Tokyo's
algorithm-128 node SID (19100) explicitly. Use a private routing table so
zebra-rs's own table is left alone:

``` shell
$ sudo ip netns exec se ip route replace 10.0.0.11/32 \
      encap mpls 19100 via 192.168.2.2 dev se-ch table 100
$ sudo ip netns exec se ip rule add from 10.0.0.1 to 10.0.0.11 lookup 100 pref 100
$ sudo ip netns exec se ping -c 3 -I 10.0.0.1 10.0.0.11
--- 10.0.0.11 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1284ms
```

Now watch the same packet at three points along the way. Seattle pushes the
label and sends it *east*:

``` shell
se>tcpdump -lni se-ch "mpls and icmp[0]==8"
14:52:19.588147 MPLS (label 19100, tc 0, [S], ttl 64) IP 10.0.0.1 > 10.0.0.11: ICMP echo request, id 29646, seq 1, length 64
```

Frankfurt hands it to Singapore, still carrying 19100:

``` shell
fr>tcpdump -lni fr-sg "mpls and icmp[0]==8"
14:52:19.588169 MPLS (label 19100, tc 0, [S], ttl 61) IP 10.0.0.1 > 10.0.0.11: ICMP echo request, id 29646, seq 1, length 64
```

And it arrives at Tokyo from Singapore as plain IP, because `sg` is the
penultimate hop and popped the label:

``` shell
tk>tcpdump -lni tk-sg "icmp[0]==8"
14:52:19.588176 IP 10.0.0.1 > 10.0.0.11: ICMP echo request, id 29646, seq 1, length 64
```

The TTL is the proof of the route taken. It leaves `se` at 64 and reaches
the `fr-sg` link at 61, so exactly three routers decremented it in between:

```
  se ──> ch ──> ln ──> fr ──> sg ──> tk
  64     63     62     61
```

**Seattle → Chicago → London → Frankfurt → Singapore → Tokyo.** US to Europe
to Asia, never touching a trans-Pacific link — while algorithm 0 is
simultaneously carrying ordinary traffic straight across the Pacific on
`se-sg`.

Remember to remove the test rule afterwards:

``` shell
$ sudo ip netns exec se ip rule del from 10.0.0.1 to 10.0.0.11 lookup 100 pref 100
$ sudo ip netns exec se ip route flush table 100
```

## Things to try

* Colour a different set of links and watch the algorithm-128 RIB change
  without touching a single metric.
* Give algorithm 128 `include-any` instead of `exclude-any` to express the
  constraint the other way round.
* Add a second algorithm (129) with its own FAD, colours and Prefix-SID
  index block, and run three topologies over the same links.
* Down the `fr-sg` link (`sudo ip netns exec fr ip link set fr-sg down`).
  Algorithm 128 partitions — AP has no other way out — while algorithm 0
  keeps working over the Pacific.

## A note on TI-LFA

The instance-level `fast-reroute ti-lfa` knob protects algorithm 0 and works
here; the YANG also exposes a per-algorithm
`router isis flex-algo <n> fast-reroute ti-lfa`. As of this writing that
per-algorithm knob does **not** produce repair paths on the SR-MPLS
dataplane: enabling it yields no backup entries in the algorithm-128 RIB,
and `show isis ti-lfa` reports no per-algorithm section. The repair-label
resolver (`repair_segments_to_mpls_labels` in `zebra-rs/src/isis/tilfa.rs`)
takes no algorithm argument and resolves the algorithm-0 Prefix-SID, so a
repair list computed for algorithm 128 would in any case be built from
algorithm-0 segments and could steer traffic back onto an excluded link.
The SRv6 segment resolvers in the same file *are* algorithm-aware.

Treat per-algorithm TI-LFA over SR-MPLS as not yet implemented.

## Appendix: Loopbacks and Prefix-SIDs

| name | region | full name | loopback     | algo-0 SID / label | algo-128 SID / label |
|:-----|:-------|:----------|:-------------|:-------------------|:---------------------|
| se   | US     | Seattle   | 10.0.0.1/32  | 100 / 16100        | 2100 / 18100         |
| sj   | US     | San Jose  | 10.0.0.2/32  | 200 / 16200        | 2200 / 18200         |
| ch   | US     | Chicago   | 10.0.0.3/32  | 300 / 16300        | 2300 / 18300         |
| da   | US     | Dallas    | 10.0.0.4/32  | 400 / 16400        | 2400 / 18400         |
| va   | US     | Virginia  | 10.0.0.5/32  | 500 / 16500        | 2500 / 18500         |
| at   | US     | Atlanta   | 10.0.0.6/32  | 600 / 16600        | 2600 / 18600         |
| ln   | EU     | London    | 10.0.0.7/32  | 700 / 16700        | 2700 / 18700         |
| fr   | EU     | Frankfurt | 10.0.0.8/32  | 800 / 16800        | 2800 / 18800         |
| sg   | AP     | Singapore | 10.0.0.9/32  | 900 / 16900        | 2900 / 18900         |
| sy   | AP     | Sydney    | 10.0.0.10/32 | 1000 / 17000       | 3000 / 19000         |
| tk   | AP     | Tokyo     | 10.0.0.11/32 | 1100 / 17100       | 3100 / 19100         |

SRGB base is 16000, SRLB base 15000. `ch` and `sg` advertise the FAD.

## Appendix: Networks

All links have metric 10. Addresses are `.1` on the first-listed node and
`.2` on the second.

| link  | network         | regions  | affinity      |
|:------|:----------------|:---------|:--------------|
| se-sg | 192.168.0.0/24  | US <-> AP | trans-pacific |
| se-sj | 192.168.1.0/24  | US        |               |
| se-ch | 192.168.2.0/24  | US        |               |
| sj-sy | 192.168.3.0/24  | US <-> AP | trans-pacific |
| sj-da | 192.168.4.0/24  | US        |               |
| sj-ch | 192.168.5.0/24  | US        |               |
| sj-tk | 192.168.6.0/24  | US <-> AP | trans-pacific |
| ch-da | 192.168.7.0/24  | US        |               |
| ch-va | 192.168.8.0/24  | US        |               |
| ch-ln | 192.168.9.0/24  | US <-> EU |               |
| da-at | 192.168.10.0/24 | US        |               |
| va-at | 192.168.11.0/24 | US        |               |
| va-fr | 192.168.12.0/24 | US <-> EU |               |
| ln-fr | 192.168.13.0/24 | EU        |               |
| fr-sg | 192.168.14.0/24 | EU <-> AP |               |
| sg-tk | 192.168.15.0/24 | AP        |               |
| sg-sy | 192.168.16.0/24 | AP        |               |
