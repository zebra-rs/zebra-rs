# IS-IS TE metrics measured by STAMP

This playset demonstrates **delay-based routing that measures itself**. Every
link in an eleven-node global backbone is probed continuously with STAMP
(Simple Two-Way Active Measurement Protocol, RFC 8762). IS-IS advertises the
measured delay and loss as TE metrics (RFC 8570), and a Flexible Algorithm
(RFC 9350) routes on them. Nobody types a delay value into any config.

The topology is the one from [isis-flexalgo](../isis-flexalgo/README.md), but
where that lab colours links and excludes them, this one gives every link a
realistic propagation delay — roughly what fiber between the two cities
costs — and lets the network find the fastest path on its own:

* **Algorithm 0** routes on the IGP metric. Every link has metric 10, so it
  counts hops.
* **Algorithm 128** routes on each link's **minimum unidirectional delay**, as
  measured by STAMP and flooded by IS-IS (FAD metric-type 1).

The delays are real: `up.sh` puts a netem qdisc on both ends of every veth, so
a ping across the Pacific takes as long as it would on a submarine cable, and
STAMP measures exactly that.

Each node runs zebra-rs in its own network namespace, and loads its own
`<node>.yaml` at startup via the `--config-file` argument.

## Topology

Eleven nodes in three regions (the regions are in `ontology.json`):

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

Every link has IGP metric 10 and its own one-way delay, applied in both
directions:

| link  | regions   | one-way delay |
|:------|:----------|--------------:|
| se-sg | US <-> AP | 85 ms |
| sj-sy | US <-> AP | 75 ms |
| sj-tk | US <-> AP | 55 ms |
| ch-ln | US <-> EU | 45 ms |
| va-fr | US <-> EU | 45 ms |
| fr-sg | EU <-> AP | 80 ms |
| sg-sy | AP        | 45 ms |
| sg-tk | AP        | 35 ms |
| se-ch | US        | 25 ms |
| sj-ch | US        | 25 ms |
| sj-da | US        | 20 ms |
| ch-da | US        | 12 ms |
| da-at | US        | 11 ms |
| se-sj | US        | 10 ms |
| ch-va | US        | 10 ms |
| va-at | US        |  9 ms |
| ln-fr | EU        |  6 ms |

The table lives in `topology.sh` as `PLAYSET_LINK_DELAYS`; edit it to model a
different network. Addressing is in the appendix.

## Bring up all nodes

`./up.sh` sets up all namespaces, gives every link its delay, and starts the
zebra-rs routing daemon in each of them on that node's own `<node>.yaml` as
`--config-file`. The delays go on *before* the daemons start, so the very
first measurement already sees them. It needs `tc` and the netem qdisc
(`sch_netem`), which every mainstream distribution kernel ships.

``` shell
$ ./up.sh
bring up
runtime dir: /tmp/zebra-rs-playset/isis-te-metric
...
create link: sg-tk (sg) <-> tk-sg (tk)
create link: sg-sy (sg) <-> sy-sg (sy)
link delay: se-sg <-> sg-se 85ms each way
link delay: se-sj <-> sj-se 10ms each way
link delay: se-ch <-> ch-se 25ms each way
...
link delay: sg-tk <-> tk-sg 35ms each way
link delay: sg-sy <-> sy-sg 45ms each way
start zebra-rs: se
start zebra-rs: sj
...
start zebra-rs: tk
sleep 3sec
```

`./down.sh` tears the whole thing back down.

The links really are slow. Tokyo's link to San Jose is 55 ms each way, so a
ping across it takes 110 ms:

``` shell
$ sudo ip netns exec tk tc qdisc show dev tk-sj
qdisc netem 8030: root refcnt 13 limit 1000 delay 55ms
$ sudo ip netns exec tk ping -c 3 192.168.6.1
rtt min/avg/max/mdev = 110.251/112.228/116.061/2.710 ms
```

## Take a look at the YAML configuration

Node `tk`'s configuration is in `tk.yaml`:

``` yaml
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
      metric-type: min-unidir-link-delay
      dataplane:
        sr-mpls: true
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
      ipv4:
        enabled: true
      metric: 10
      te-metric:
        measurement:
          enabled: true
          interval: 100
          damping-period: 5
    - if-name: tk-sg
      ...
```

Two things are new compared to a plain SR-MPLS configuration:

* **`te-metric measurement`** on each point-to-point link turns on STAMP. Both
  ends of a link enable it; each end runs a Session-Sender towards its
  neighbour, and the neighbour answers from an implicit Session-Reflector —
  there is no separate reflector to configure. The session comes up with the
  IS-IS adjacency and goes away with it.
  * `interval` is the probe transmit interval in milliseconds.
  * `damping-period` is how often, at most, a new measurement is handed to
    IS-IS, in seconds.

  The values here — 100 ms and 5 s — are lab values chosen so the demo
  converges in seconds. The defaults are 1 s and 30 s, matching the periodic
  advertisement cadence of IOS-XR and SR-OS.

* **`flex-algo 128`** is a Flex-Algorithm Definition (FAD) with
  `metric-type: min-unidir-link-delay` — FAD metric-type 1. Its SPF costs each
  link by the *Min* field of the link's advertised Min/Max Unidirectional
  Link Delay, not by the IGP metric. `ch` and `sg` additionally set
  `advertise-definition: true`, one in the US and one in AP, so the
  definition survives either of them going away.

There is **no delay value anywhere in the configuration**. What IS-IS
advertises and what algorithm 128 computes with is what STAMP measured.

## STAMP sessions

`show stamp` lists one session per link:

``` shell
tk>show stamp
Interface  Local            Remote           State        Sent     Recv    Loss%  Last sample (min/avg/max)
tk-sj      192.168.6.2      192.168.6.1      Active        247      246        -  55058/55567/57589us (530us)
tk-sg      192.168.15.2     192.168.15.1     Active        247      246        -  35070/35721/37014us (523us)
```

`State Active` means replies are coming back, so the neighbour is reflecting.
The last column is the latest damping window: minimum, average and maximum
one-way delay, with the delay variation (jitter) in parentheses. Both
minimums sit within 100 µs of the 55 ms and 35 ms netem put on the links.

`show stamp session` has the detail per session:

``` shell
tk>show stamp session
STAMP Sessions:
    session 192.168.6.2 -> 192.168.6.1 (tk-sj)
        SSID: 2
        State: Active
        Probe interval: 100ms
        Damping period: 5s
        Uptime: 24 second(s)
        Counters: tx 247 rx 246 rx-invalid 0 tx-failed 0 reflected 246
        T4 timestamp source: kernel 246 userspace 0
        Reflector: stateless
        Loss (round-trip, 120s window): measuring, first bucket not closed yet
        Loss replies: late 0 duplicate 0 unmatched 0
        Last sample:
            Min delay: 55058 usec
            Max delay: 57589 usec
            Average delay: 55567 usec
            Delay variation: 530 usec
        Subscribers:
            isis: anomaly-threshold none, Anomalous: avg no, min no, max no
                loss: not advertised (interval 120s, threshold 10%, minimum-change 0.999999%, integrity 90%)
    ...
```

A few things worth noticing:

* **One-way delay without clock sync.** Each reply carries four timestamps,
  and the one-way delay is `((T4 − T1) − (T3 − T2)) / 2`: the sender's and the
  reflector's clocks each only ever subtract from themselves, so their offset
  cancels out.
* **`T4 timestamp source: kernel`** — receive times come from the kernel
  (`SO_TIMESTAMPING`), not from a userspace read after the daemon wakes up, so
  the daemon's own scheduling latency stays out of the measurement.
* **`Subscribers: isis`** — IS-IS is the consumer of this session. OSPF can
  subscribe to the same session on the same link; the measurement is shared.
* **Loss** is measured on the same probes, over a longer window (two minutes
  by default) because a loss ratio needs many probes to mean anything. It is
  covered at the end of this walkthrough.

## The measured delay on the wire

Here is `tk`'s own LSP:

``` shell
tk>show isis database detail
tk.00-00                  *      265  0x00000004  0x2b24      1190  0/0/0
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
      Unidirectional Link Delay: 55487 us
      Min/Max Unidirectional Link Delay: min 55046 us, max 57622 us
      Unidirectional Delay Variation: 428 us
    Unidirectional Link Delay: 55487 us
    Min/Max Unidirectional Link Delay: min 55046 us, max 57622 us
    Unidirectional Delay Variation: 428 us
    Adjacency SID: Label(15001), Flag: F:0 B:0 V:1 L:1 S:0 P:0, Weight: 0
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0009.00, Metric: 10
    Application Specific Link Attributes:
     L:0 SABM: 0x10 UDABM: 0x
     Applications: Flex-Algo
      Unidirectional Link Delay: 35723 us
      Min/Max Unidirectional Link Delay: min 35033 us, max 37677 us
      Unidirectional Delay Variation: 570 us
    Unidirectional Link Delay: 35723 us
    Min/Max Unidirectional Link Delay: min 35033 us, max 37677 us
    Unidirectional Delay Variation: 570 us
    Adjacency SID: Label(15000), Flag: F:0 B:0 V:1 L:1 S:0 P:0, Weight: 0
  Extended IP Reachability: 10.0.0.11/32 (Metric: 10)
   SID: Index(1100), Algorithm: SPF(0), Flags: R:0 N:1 P:0 E:0 V:0 L:0
   SID: Index(3100), Algorithm: FlexAlgo(128), Flags: R:0 N:1 P:0 E:0 V:0 L:0
  Extended IP Reachability: 192.168.6.0/24 (Metric: 10)
  Extended IP Reachability: 192.168.15.0/24 (Metric: 10)
```

Each adjacency carries the three RFC 8570 delay sub-TLVs, all in
microseconds:

| sub-TLV | what it holds | used by |
|:--|:--|:--|
| Unidirectional Link Delay (33) | the average | reporting, anomaly detection |
| Min/Max Unidirectional Link Delay (34) | the lowest and highest sample | **Min** is the Flex-Algo metric-type 1 cost |
| Unidirectional Delay Variation (35) | the jitter | reporting |

They appear twice: once inside an **Application Specific Link Attributes**
sub-TLV (ASLA, RFC 9479) whose SABM `0x10` marks the Flex-Algo application,
and once inline for applications that predate ASLA. Neighbour
`0000.0000.0002` is `sj`, so this is the `tk-sj` link at 55 ms; neighbour
`0000.0000.0009` is `sg`, the `tk-sg` link at 35 ms.

The delay is advertised **per direction**. `tk` advertises the `tk → sj`
direction it measured; `sj` advertises `sj → tk` in its own LSP. In this lab
the two agree because netem delays both directions equally.

### How often the LSP changes

A measured value is never quite constant, and every change to an LSP floods
the whole domain, so STAMP holds back. At the end of each damping period it
hands IS-IS a new value only if some field moved by more than 10 % (or 50 µs,
whichever is larger) since the last one it handed over. IS-IS then coalesces
changes under its own `lsp-gen-interval` throttle (50 ms for the first
change, 5 s for the ones that follow).

The jitter field is the restless one: on a netem'd veth it moves by more
than 50 µs from window to window often enough that each router refreshes its
LSP every few damping periods. That is harmless here, and it is one reason
the production damping period is 30 s rather than 5 s.

## Examine the Flex-Algorithm state

``` shell
tk>show isis flex-algo
Area 49.0000:

Local Flex-Algorithms:
  Algo  Metric                 Priority Adv FRR       Constraints
  128   minunidirlinkdelay     -        no  off       -

Level-2 definition selection:
  Algo 128: definition from sg (0000.0000.0009), priority 128; participating

Level-2:
  Peer FADs:
    ch (0000.0000.0003): algo 128 priority 128 metric-type 1 calc-type 0
    sg (0000.0000.0009): algo 128 priority 128 metric-type 1 calc-type 0
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

Both definitions say `metric-type 1` — minimum unidirectional link delay —
and the winner is `sg`'s (equal priority, so the higher system ID wins). All
eleven routers participate.

A link that advertises no delay has no metric-type 1 cost, and RFC 9350 §15
says such a link **must be pruned** from the algorithm's topology. So right
after `./up.sh`, until the first damping period has passed, algorithm 128 can
be briefly empty. It fills in within seconds.

## Algorithm 0 versus algorithm 128

Algorithm 0, Tokyo's ordinary routing table, counts hops. Everything is two to
four hops away, and wherever two paths tie it splits the traffic:

``` shell
tk>show ip route
...
L2 *> 10.0.0.1/32 [115/30] via 192.168.6.1, tk-sj, label 16100, weight 1, 00:00:18
                           via 192.168.15.1, tk-sg, label 16100, weight 1, 00:00:18
L2 *> 10.0.0.2/32 [115/20] via 192.168.6.1, tk-sj, label (16200), 00:00:19
L2 *> 10.0.0.3/32 [115/30] via 192.168.6.1, tk-sj, label 16300, 00:00:19
L2 *> 10.0.0.4/32 [115/30] via 192.168.6.1, tk-sj, label 16400, 00:00:19
L2 *> 10.0.0.5/32 [115/40] via 192.168.6.1, tk-sj, label 16500, weight 1, 00:00:17
                           via 192.168.15.1, tk-sg, label 16500, weight 1, 00:00:17
L2 *> 10.0.0.6/32 [115/40] via 192.168.6.1, tk-sj, label 16600, 00:00:19
L2 *> 10.0.0.7/32 [115/40] via 192.168.6.1, tk-sj, label 16700, weight 1, 00:00:18
                           via 192.168.15.1, tk-sg, label 16700, weight 1, 00:00:18
L2 *> 10.0.0.8/32 [115/30] via 192.168.15.1, tk-sg, label 16800, 00:00:18
L2 *> 10.0.0.9/32 [115/20] via 192.168.15.1, tk-sg, label (16900), 00:00:19
L2 *> 10.0.0.10/32 [115/30] via 192.168.6.1, tk-sj, label 17000, weight 1, 00:00:18
                            via 192.168.15.1, tk-sg, label 17000, weight 1, 00:00:18
...
```

Algorithm 128 counts microseconds:

``` shell
tk>show isis flex-algo 128 route
Area 49.0000:

Level-2 Algorithm 128:
  Prefix               Metric   Nexthop          Interface    Label
  10.0.0.1/32          65112    192.168.6.1      tk-sj        18100
  10.0.0.2/32          55056    192.168.6.1      tk-sj        18200
  10.0.0.3/32          80112    192.168.6.1      tk-sj        18300
  10.0.0.4/32          75133    192.168.6.1      tk-sj        18400
  10.0.0.5/32          90152    192.168.6.1      tk-sj        18500
  10.0.0.6/32          86195    192.168.6.1      tk-sj        18600
  10.0.0.7/32          121152   192.168.15.1     tk-sg        18700
  10.0.0.8/32          115110   192.168.15.1     tk-sg        18800
  10.0.0.9/32          35043    192.168.15.1     tk-sg        18900
  10.0.0.10/32         80079    192.168.15.1     tk-sg        19000
```

The metric is the sum of the measured minimum delays along the path, plus
the destination's prefix metric (10). Seattle (`10.0.0.1`) costs 65,112 µs:
55 ms to San Jose and 10 ms on to Seattle. Every tie algorithm 0 splits,
algorithm 128 resolves by latency:

| destination | algorithm 0 | algorithm 128 | why |
|:--|:--|:--|:--|
| se `10.0.0.1` | ECMP `tk-sj` / `tk-sg` | `tk-sj`, 65 ms | via Singapore is 35 + 85 = 120 ms |
| va `10.0.0.5` | ECMP | `tk-sj`, 90 ms | `tk-sj-ch-va` 55 + 25 + 10 |
| ln `10.0.0.7` | ECMP | `tk-sg`, 121 ms | `tk-sg-fr-ln` 35 + 80 + 6 beats `tk-sj-ch-ln` 55 + 25 + 45 by 4 ms |
| sy `10.0.0.10` | ECMP | `tk-sg`, 80 ms | via San Jose is 55 + 75 = 130 ms |

Equal-cost multipath looks harmless in algorithm 0, but it is not free: from
Virginia, algorithm 0 splits the traffic for Tokyo over two "equal" paths
that differ by 70 ms:

``` shell
va>show ip route 10.0.0.11
L2 *> 10.0.0.11/32 [115/40] via 192.168.8.1, va-ch, label 17100, weight 1, 00:00:17
                            via 192.168.12.2, va-fr, label 17100, weight 1, 00:00:17

va>show isis flex-algo 128 route
...
  10.0.0.11/32         90134    192.168.8.1      va-ch        19100
```

Half of those flows ride `va-ch-sj-tk` (90 ms) and half `va-fr-sg-tk`
(160 ms). Algorithm 128 sends them all the 90 ms way.

### Fewer hops is not faster

From Atlanta to Singapore the two algorithms do not just break a tie
differently — they disagree outright. The per-algorithm SPF shows the paths:

``` shell
at>show isis spf
...
  Destination sg, cost 30
    [0] nexthop va (at-va)
    paths:
      [0] va -> fr -> sg

at>show isis flex-algo 128 spf
...
  Destination sg, cost 121159
    [0] nexthop da (at-da)
    paths:
      [0] da -> sj -> tk -> sg
```

Algorithm 0 takes the three-hop route through Europe: 9 + 45 + 80 = 134 ms.
Algorithm 128 takes a *four*-hop route across the Pacific: 11 + 20 + 55 + 35
= 121 ms.

The graph behind that decision is visible too. `show isis flex-algo 128 graph`
costs every link with its measured minimum delay, one value per direction:

``` shell
tk>show isis flex-algo 128 graph

L2 algo 128 IS-IS Graph:

Nodes:
  tk [0000.0000.0011] (id: 0)
    Links:
      -> sj (cost: 55046)
      -> sg (cost: 35033)
      <- sj (cost: 55053)
      <- sg (cost: 35071)
  sg [0000.0000.0009] (id: 1)
    Links:
      -> se (cost: 85070)
      -> fr (cost: 80067)
      -> tk (cost: 35071)
      -> sy (cost: 45036)
...
```

Compare `show isis graph`, where every one of those links costs 10.

## Send real traffic over the low-latency path

`ping` on its own follows algorithm 0. To measure what algorithm 128 buys,
steer a ping between the two loopbacks onto the algorithm-128 Prefix-SIDs —
Singapore's is 18900, Atlanta's 18600 — in **both** directions, since a round
trip is only as fast as its slower half. Use a private routing table so
zebra-rs's own table is left alone.

First, the algorithm-0 baseline:

``` shell
$ sudo ip netns exec at ping -c 5 -I 10.0.0.6 10.0.0.9
rtt min/avg/max/mdev = 269.441/270.910/274.346/1.764 ms
```

Then steer Atlanta → Singapore onto label 18900 via Dallas, and Singapore →
Atlanta onto label 18600 via Tokyo (the first hop of each algorithm-128 path,
from `show isis flex-algo 128 route` on each node):

``` shell
$ sudo ip netns exec at ip route replace 10.0.0.9/32 \
      encap mpls 18900 via 192.168.10.1 dev at-da table 100
$ sudo ip netns exec at ip rule add from 10.0.0.6 to 10.0.0.9 lookup 100 pref 100
$ sudo ip netns exec sg ip route replace 10.0.0.6/32 \
      encap mpls 18600 via 192.168.15.2 dev sg-tk table 100
$ sudo ip netns exec sg ip rule add from 10.0.0.9 to 10.0.0.6 lookup 100 pref 100
$ sudo ip netns exec at ping -c 5 -I 10.0.0.6 10.0.0.9
rtt min/avg/max/mdev = 245.758/246.366/247.118/0.511 ms
```

**24.5 ms faster per round trip** — twice the 13 ms one-way difference
between the two paths, less some noise. Captured at three points along the
way, the timestamps spell out each link's delay:

``` shell
da>tcpdump -lni da-at "mpls and icmp[0]==8"
11:21:15.529222 MPLS (label 18900, tc 0, [S], ttl 64) IP 10.0.0.6 > 10.0.0.9: ICMP echo request, id 42934, seq 1, length 64

tk>tcpdump -lni tk-sj "mpls and icmp[0]==8"
11:21:15.604959 MPLS (label 18900, tc 0, [S], ttl 62) IP 10.0.0.6 > 10.0.0.9: ICMP echo request, id 42934, seq 1, length 64

sg>tcpdump -lni sg-tk "icmp[0]==8"
11:21:15.640010 IP 10.0.0.6 > 10.0.0.9: ICMP echo request, id 42934, seq 1, length 64
```

```
  at ──> da ──> sj ──> tk ──> sg
         .529         .605    .640
            +75.7 ms     +35.0 ms
            (20 + 55)    (35)
```

Dallas to Tokyo took 75.7 ms (`da-sj` 20 ms plus `sj-tk` 55 ms), and Tokyo to
Singapore 35 ms. `tk` is the penultimate hop, so it popped the label and the
packet reaches Singapore as plain IP.

Remove the test rules afterwards:

``` shell
$ sudo ip netns exec at ip rule del from 10.0.0.6 to 10.0.0.9 lookup 100 pref 100
$ sudo ip netns exec at ip route flush table 100
$ sudo ip netns exec sg ip rule del from 10.0.0.9 to 10.0.0.6 lookup 100 pref 100
$ sudo ip netns exec sg ip route flush table 100
```

## When a link's latency changes

This is what measurement is for. Suppose the cable between San Jose and Tokyo
is cut and the circuit is restored over a longer path, raising its delay from
55 ms to 120 ms. Nobody reconfigures anything; the network notices.

First, ask IS-IS to flag the link as **anomalous** if its average delay
crosses 100 ms. RFC 8570 carries an Anomalous (A) bit in each delay sub-TLV
for exactly this, so receivers can tell a degraded link from a slow one:

``` shell
tk>configure
tk#set router isis interface tk-sj te-metric measurement anomaly-threshold 100000
tk#commit
```

Then make the link slower, on both ends:

``` shell
$ sudo ip netns exec sj tc qdisc change dev sj-tk root netem delay 120ms
$ sudo ip netns exec tk tc qdisc change dev tk-sj root netem delay 120ms
```

STAMP sees it within one damping period:

``` shell
tk>show stamp
Interface  Local            Remote           State        Sent     Recv    Loss%  Last sample (min/avg/max)
tk-sj      192.168.6.2      192.168.6.1      Active        588      586    0.000  120036/120752/123503us (700us)
tk-sg      192.168.15.2     192.168.15.1     Active        589      588    0.000  35080/35577/37016us (481us)

tk>show stamp session
    session 192.168.6.2 -> 192.168.6.1 (tk-sj)
...
        Subscribers:
            isis: anomaly-threshold 100000us (reuse 100000us), Anomalous: avg yes, min yes, max yes
```

and every router sees it in `tk`'s LSP, with each delay field flagged `(A)`:

``` shell
se>show isis database detail
...
  Extended IS Reachability:
   Neighbor ID: 0000.0000.0002.00, Metric: 10
    Application Specific Link Attributes:
     L:0 SABM: 0x10 UDABM: 0x
     Applications: Flex-Algo
      Unidirectional Link Delay: 120596 us (A)
      Min/Max Unidirectional Link Delay: min 120054 us, max 122659 us (A)
      Unidirectional Delay Variation: 516 us
...
```

Algorithm 0 does not care — the IGP metric is still 10:

``` shell
tk>show ip route 10.0.0.1
L2 *> 10.0.0.1/32 [115/30] via 192.168.6.1, tk-sj, label 16100, weight 1, 00:00:52
                           via 192.168.15.1, tk-sg, label 16100, weight 1, 00:00:52
```

Algorithm 128 re-routes. About nine seconds after the delay changed — one
damping period, LSP generation and flooding across links that are now
themselves slow — Tokyo reaches Seattle through Singapore:

``` shell
tk>show isis flex-algo 128 route
Area 49.0000:

Level-2 Algorithm 128:
  Prefix               Metric   Nexthop          Interface    Label
  10.0.0.1/32          120155   192.168.15.1     tk-sg        18100
  10.0.0.2/32          120046   192.168.6.1      tk-sj        18200
  10.0.0.3/32          145116   192.168.6.1      tk-sj        18300
  10.0.0.4/32          140114   192.168.6.1      tk-sj        18400
  10.0.0.5/32          155152   192.168.6.1      tk-sj        18500
  10.0.0.6/32          151205   192.168.6.1      tk-sj        18600
  10.0.0.7/32          121228   192.168.15.1     tk-sg        18700
  10.0.0.8/32          115188   192.168.15.1     tk-sg        18800
  10.0.0.9/32          35090    192.168.15.1     tk-sg        18900
  10.0.0.10/32         80157    192.168.15.1     tk-sg        19000
```

Seattle moved from `tk-sj` (65 ms) to `tk-sg` (120 ms, `tk-sg-se`); the rest
of the US still goes via San Jose, because even at 120 ms it is the faster
way there. The same change reaches Atlanta, whose path to Singapore gives up
the Tokyo crossing for `da -> sj -> se -> sg` (126 ms).

Put the link back and everything returns — the delay, the cleared A bit, and
the routes, about seven seconds later:

``` shell
$ sudo ip netns exec sj tc qdisc change dev sj-tk root netem delay 55ms
$ sudo ip netns exec tk tc qdisc change dev tk-sj root netem delay 55ms

tk>show stamp session
...
            Min delay: 55056 usec
...
            isis: anomaly-threshold 100000us (reuse 100000us), Anomalous: avg no, min no, max no
```

`reuse-threshold` (default: the anomaly threshold itself) sets a separate,
lower bound for clearing the bit, so a link hovering at the threshold does not
flap it.

## Pinning a value statically

Measurement and configuration write the same TE metric fields. When both are
present on a link, **the configured value wins, field by field** — a hand-set
bound is authoritative, and the measurement fills in whatever was left unset.
Pin `tk-sj`'s minimum and maximum delay to 150 ms and 160 ms:

``` shell
tk>configure
tk#set router isis interface tk-sj te-metric min-delay 150000
tk#set router isis interface tk-sj te-metric max-delay 160000
tk#commit
```

``` shell
tk>show isis database detail
...
   Neighbor ID: 0000.0000.0002.00, Metric: 10
    Application Specific Link Attributes:
     L:0 SABM: 0x10 UDABM: 0x
     Applications: Flex-Algo
      Unidirectional Link Delay: 55548 us
      Min/Max Unidirectional Link Delay: min 150000 us, max 160000 us
      Unidirectional Delay Variation: 522 us
...
```

Min and max are the pinned values; the average and the variation are still
the live measurement. Since algorithm 128 costs a link by its minimum, the
`tk → sj` direction now costs 150 ms — for every router, including `tk` —
while `sj → tk`, which `sj` still measures, stays at 55 ms:

``` shell
sj>show isis flex-algo 128 graph
...
  tk [0000.0000.0011] (id: 5)
    Links:
      -> sj (cost: 150000)
      -> sg (cost: 35029)
      <- sj (cost: 55083)
      <- sg (cost: 35093)
```

and all of Tokyo's algorithm-128 traffic leaves over `tk-sg`. Delete the two
leaves to hand the link back to the measurement.

## Measured loss as a constraint

The same probes measure **loss**, advertised as the Unidirectional Link Loss
sub-TLV (36). Loss is not a metric but it can be a **constraint**: a FAD with
`exclude-max-link-loss` prunes every link whose advertised loss exceeds it.
Add one to algorithm 128 on the two routers that advertise the definition:

``` shell
ch#set router isis flex-algo 128 exclude-max-link-loss 1
sg#set router isis flex-algo 128 exclude-max-link-loss 1
```

Loss is averaged over two-minute intervals by default. To see it sooner,
shorten the interval on the link we are about to break — both ends, since
both measure it:

``` shell
fr#set router isis interface fr-sg te-metric measurement loss interval 30
sg#set router isis interface sg-fr te-metric measurement loss interval 30
```

Now make the Frankfurt–Singapore link drop 3 % of what Frankfurt sends:

``` shell
$ sudo ip netns exec fr tc qdisc change dev fr-sg root netem delay 80ms loss 3%
```

After a 30 s interval, both ends advertise it:

``` shell
fr>show stamp session
    session 192.168.14.1 -> 192.168.14.2 (fr-sg)
...
                loss: advertised 3.000000% (interval 30s, threshold 10%, minimum-change 0.999999%, integrity 90%)

tk>show isis database detail
fr.00-00 ...
   Neighbor ID: 0000.0000.0009.00, Metric: 10
    Application Specific Link Attributes:
     L:0 SABM: 0x10 UDABM: 0x
     Applications: Flex-Algo
      Unidirectional Link Delay: 80447 us
      Min/Max Unidirectional Link Delay: min 80067 us, max 82394 us
      Unidirectional Delay Variation: 392 us
      Unidirectional Link Loss: 1.666668%
...
```

(The first interval straddled the moment the loss started, so it read
1.67 %; the next one read the full 3 %.) With the default stateless
reflector, the advertised loss is **round-trip**: it counts a probe lost in
either direction, which is why `sg` — whose probes go out undamaged and whose
replies come back through the lossy direction — advertises it too.

The constraint travels in the definition. `sg`'s LSP carries it, encoded in
the wire unit of 0.000003 % — which makes 1 % exactly 0.999999 %:

``` shell
tk>show isis database detail
sg.00-00 ...
  Router Capability: 10.0.0.9, D:0 S:0
...
   Flex-Algorithm Definition: Algo 128, Metric-Type 1, Calc-Type 0, Priority 128
     FAD Exclude Max Link Loss: 0.999999% (333333)
```

Every router prunes the link, in both directions. `sg` has lost `fr` from its
algorithm-128 adjacency list:

``` shell
tk>show isis flex-algo 128 graph
...
  sg [0000.0000.0009] (id: 1)
    Links:
      -> se (cost: 85047)
      -> tk (cost: 35054)
      -> sy (cost: 45046)
      <- se (cost: 85059)
      <- sy (cost: 45067)
      <- tk (cost: 35057)
```

and Tokyo's algorithm-128 route to Frankfurt gives up the 115 ms path through
Singapore for the 131 ms one through San Jose, Chicago and London:

``` shell
tk>show isis flex-algo 128 route
...
  10.0.0.8/32          131278   192.168.6.1      tk-sj        18800
```

Algorithm 0, again, keeps using the lossy link. To undo, remove the loss
(`netem delay 80ms`), then delete `exclude-max-link-loss` on `ch` and `sg`
and the two `loss interval` leaves.

## Things to try

* **Add jitter.** `netem delay 55ms 5ms` makes the link's delay vary; watch
  the Delay Variation sub-TLV grow — and the LSPs refresh more often.
* **Make it asymmetric.** Put 80 ms on `tk-sj` and 30 ms on `sj-tk`. Both
  ends measure 55 ms: without synchronized clocks STAMP can only halve the
  round trip, so each direction is advertised as the average of the two.
* **Run it on OSPF.** The same measurement block exists under
  `router ospf area … interface` and `router ospfv3 area … interface`, and a
  link measured by both IGPs shares one STAMP session.
* **Use production timers.** Delete `interval` and `damping-period` to fall
  back to 1 s and 30 s, and compare how long a delay change takes to reach
  algorithm 128.
* **Compare with [isis-flexalgo](../isis-flexalgo/README.md).** The same
  topology, constrained by affinity instead of delay: the trans-Pacific links
  are excluded by name there, and here they are simply used when they are
  fast.

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

All links have IGP metric 10. Addresses are `.1` on the first-listed node and
`.2` on the second.

| link  | network         | regions   | one-way delay |
|:------|:----------------|:----------|--------------:|
| se-sg | 192.168.0.0/24  | US <-> AP | 85 ms |
| se-sj | 192.168.1.0/24  | US        | 10 ms |
| se-ch | 192.168.2.0/24  | US        | 25 ms |
| sj-sy | 192.168.3.0/24  | US <-> AP | 75 ms |
| sj-da | 192.168.4.0/24  | US        | 20 ms |
| sj-ch | 192.168.5.0/24  | US        | 25 ms |
| sj-tk | 192.168.6.0/24  | US <-> AP | 55 ms |
| ch-da | 192.168.7.0/24  | US        | 12 ms |
| ch-va | 192.168.8.0/24  | US        | 10 ms |
| ch-ln | 192.168.9.0/24  | US <-> EU | 45 ms |
| da-at | 192.168.10.0/24 | US        | 11 ms |
| va-at | 192.168.11.0/24 | US        |  9 ms |
| va-fr | 192.168.12.0/24 | US <-> EU | 45 ms |
| ln-fr | 192.168.13.0/24 | EU        |  6 ms |
| fr-sg | 192.168.14.0/24 | EU <-> AP | 80 ms |
| sg-tk | 192.168.15.0/24 | AP        | 35 ms |
| sg-sy | 192.168.16.0/24 | AP        | 45 ms |
