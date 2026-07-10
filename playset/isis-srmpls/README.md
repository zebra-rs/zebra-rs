# IS-IS SR-MPLS & TI-LFA

This playset demonstrates IS-IS SR-MPLS with TI-LFA fast reroute. Every core
node has a loopback address with a Prefix-SID index, so every node can reach
every other node's loopback over an SR-MPLS label-switched path. The topology
follows the example in the TI-LFA specification (RFC 9855). All core and edge
nodes run in separate network namespaces. Each node runs zebra-rs, and its
YAML configuration is injected with the `vtyctl apply` command.

## Topology

<img src="../images/TI-LFA.svg" alt="IS-IS SR-MPLS TI-LFA topology">

## Bring up all nodes

`./up.sh` sets up all namespaces, starts the zebra-rs routing daemon in each
of them, and injects the initial configuration.

``` shell
$ ./up.sh
bring up
teardown: stop zebra-rs
teardown: delete namespace e1
teardown: delete namespace e2
teardown: delete namespace s
...
apply config: r3
applied
apply config: d
applied
```

You can then list the namespaces:

``` shell
$ ip netns
d
r3
r2
r1
n3
n2
n1
s
e2
e1
```

## Examine routes on node `s`

Let's take a look at the routing table of node `s`. The following command
takes you into node `s`'s vty shell.

``` shell
$ sudo ip netns exec s vty
```

The `show ip route` command displays all of the IPv4 routing information.

``` shell
s>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> 10.0.0.1/32 is directly connected, lo, 00:00:50
L2 *> 10.0.0.2/32 [115/11] via 192.168.0.2, s-n1, label (16200), 00:00:44
L2 *> 10.0.0.3/32 [115/11] via 192.168.3.2, s-n2, label (16300), 00:00:44
L2 *> 10.0.0.4/32 [115/1010] via 192.168.1.2, s-n3, label (16400), 00:00:44
L2 *> 10.0.0.5/32 [115/12] via 192.168.0.2, s-n1, label 16500, weight 1, 00:00:44
                           via 192.168.3.2, s-n2, label 16500, weight 1, 00:00:44
L2 *> 10.0.0.6/32 [115/12] via 192.168.0.2, s-n1, label 16600, 00:00:44
L2 *> 10.0.0.7/32 [115/13] via 192.168.0.2, s-n1, label 16700, 00:00:43
L2 *> 10.0.0.8/32 [115/12] via 192.168.0.2, s-n1, label 16800, 00:00:43
C  *> 127.0.0.0/8 is directly connected, lo, 00:00:53
C  *> 172.16.0.0/24 is directly connected, s-e1, 00:00:50
S  *> 172.16.1.0/24 [1/0] via 10.0.0.8 (recursive), 00:00:50
                          via 192.168.0.2, s-n1, label 16800
C  *> 192.168.0.0/24 is directly connected, s-n1, 00:00:50
L2    192.168.0.0/24 [115/2] via 192.168.0.2, s-n1, 00:00:44
C  *> 192.168.1.0/24 is directly connected, s-n3, 00:00:50
L2    192.168.1.0/24 [115/2000] via 192.168.1.2, s-n3, 00:00:44
L2 *> 192.168.2.0/24 [115/2] via 192.168.0.2, s-n1, 00:00:44
C  *> 192.168.3.0/24 is directly connected, s-n2, 00:00:50
L2    192.168.3.0/24 [115/2] via 192.168.3.2, s-n2, 00:00:44
L2 *> 192.168.4.0/24 [115/1002] via 192.168.0.2, s-n1, weight 1, 00:00:44
                                via 192.168.3.2, s-n2, weight 1, 00:00:44
L2 *> 192.168.5.0/24 [115/3] via 192.168.0.2, s-n1, 00:00:43
L2 *> 192.168.6.0/24 [115/2] via 192.168.0.2, s-n1, 00:00:44
L2 *> 192.168.7.0/24 [115/2] via 192.168.3.2, s-n2, 00:00:44
L2 *> 192.168.8.0/24 [115/2] via 192.168.0.2, s-n1, 00:00:44
L2 *> 192.168.9.0/24 [115/1002] via 192.168.0.2, s-n1, 00:00:44
L2 *> 192.168.10.0/24 [115/1002] via 192.168.0.2, s-n1, weight 1, 00:00:44
                                 via 192.168.3.2, s-n2, weight 1, 00:00:44
```

A few things worth noticing:

* Every remote loopback (`10.0.0.X/32`) carries an MPLS label — the owner's
  Prefix-SID resolved against the SRGB (base 16000). Packets to `10.0.0.8`
  are pushed label `16800` and label-switched all the way to `d`.
* A parenthesized label such as `(16200)` means implicit-null: the SID owner
  is directly adjacent, so penultimate-hop popping (PHP) applies and no label
  is actually pushed on the wire.
* `10.0.0.5/32` (r1) is reachable at equal cost via `n1` and `n2`, so it is
  installed as an ECMP route with two labeled legs.
* The static route `172.16.1.0/24` is *recursive*: its configured nexthop
  `10.0.0.8` is not on a connected subnet, so it resolves through the IS-IS
  route to `10.0.0.8/32` and inherits its egress and label stack. More on
  this below.

## `ping` node `d`'s loopback address

Let's ping node `d` from `s`.

``` shell
s>ping 10.0.0.8
PING 10.0.0.8 (10.0.0.8) 56(84) bytes of data.
64 bytes from 10.0.0.8: icmp_seq=1 ttl=63 time=0.060 ms
64 bytes from 10.0.0.8: icmp_seq=2 ttl=63 time=0.049 ms
64 bytes from 10.0.0.8: icmp_seq=3 ttl=63 time=0.042 ms
64 bytes from 10.0.0.8: icmp_seq=4 ttl=63 time=0.055 ms
^C
--- 10.0.0.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3088ms
```

## Examine the MPLS-encapsulated packets on node `n1`

While the ping is running, we can observe the MPLS-encapsulated packets on
node `n1` with tcpdump. Keep the ping to `10.0.0.8` running, open a new
terminal, and log in to `n1` with `sudo ip netns exec n1 vty`.

``` shell
n1>tcpdump -li n1-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
02:53:21.384823 MPLS (label 16800, tc 0, [S], ttl 64) IP 192.168.0.1 > 10.0.0.8: ICMP echo request, id 5836, seq 4, length 64
02:53:21.890748 MPLS (label 16800, tc 0, [S], ttl 64) IP 192.168.0.1 > 10.0.0.8: ICMP echo request, id 5836, seq 5, length 64
02:53:22.396639 MPLS (label 16800, tc 0, [S], ttl 64) IP 192.168.0.1 > 10.0.0.8: ICMP echo request, id 5836, seq 6, length 64
^C
3 packets captured
3 packets received by filter
0 packets dropped by kernel
```

The echo requests arrive at `n1` carrying label `16800` — `d`'s Prefix-SID.
`n1` swaps the label and forwards toward `d` (in fact `n1` is the penultimate
hop, so it pops the label and delivers a plain IP packet to `d`).

## Take a look at the YAML configuration

Node `s`'s configuration is in `s.yaml`. After zebra-rs for namespace `s` has
been launched, the YAML configuration below is applied to it with `vtyctl
apply -f s.yaml`. If you are familiar with Kubernetes, this is exactly the
same idea as `kubectl apply -f config.yaml`.

``` yaml
interface:
- if-name: lo
  ipv4:
    address: 10.0.0.1/32
- if-name: s-e1
  ipv4:
    address: 172.16.0.2/24
- if-name: s-n1
  ipv4:
    address: 192.168.0.1/24
- if-name: s-n2
  ipv4:
    address: 192.168.3.1/24
- if-name: s-n3
  ipv4:
    address: 192.168.1.1/24
system:
  hostname: s
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    hostname: s
    is-type: level-2-only
    segment-routing:
      mpls: {}
    te-router-id: 10.0.0.1
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 100
    - if-name: s-n1
      ipv4:
        enabled: true
      metric: 1
    - if-name: s-n2
      ipv4:
        enabled: true
      metric: 1
    - if-name: s-n3
      ipv4:
        enabled: true
      metric: 1000
  static:
    ipv4:
      route:
      - prefix: 172.16.1.0/24
        nexthop:
        - address: 10.0.0.8
```

A few notes on this configuration:

* `system hostname` names the node — it is what the vty prompt (`s>` / `s#`)
  and `show hostname` display.
* `segment-routing mpls` enables SR-MPLS, and the loopback's
  `prefix-sid index 100` advertises `s`'s node SID (label 16000 + 100 =
  16100).
* The static route at the bottom is the interesting one. `172.16.1.0/24` is
  the subnet of edge host `e2`, which lives behind `d` and is not part of
  IS-IS at all. Its nexthop `10.0.0.8` is `d`'s loopback — not an address on
  any of `s`'s connected subnets — so zebra-rs resolves it *recursively*: it
  looks `10.0.0.8` up in the routing table, finds the IS-IS SR-MPLS route,
  and installs the static route with that route's egress interface and label
  stack (label `16800`). That is why `show ip route` displays it on two
  lines: the configured gateway marked `(recursive)`, and the resolved
  nexthop with the inherited label underneath. Whenever the IS-IS route to
  `10.0.0.8/32` changes, the static route is automatically re-resolved and
  re-installed — we will see this in action with TI-LFA below.

## `show mpls ilm` to examine the ILM (Incoming Label Map)

The MPLS ILM table — what the node does with each incoming label — can be
examined as follows:

``` shell
s>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> i 115  15000  Pop         SR Adj (idx 0  )   s-n1         192.168.0.2
*> i 115  15001  Pop         SR Adj (idx 1  )   s-n2         192.168.3.2
*> i 115  15002  Pop         SR Adj (idx 2  )   s-n3         192.168.1.2
*> i 115  16100  Pop         SR Pfx (idx 100)   lo           10.0.0.1
*> i 115  16200  Pop         SR Pfx (idx 200)   s-n1         192.168.0.2
*> i 115  16300  Pop         SR Pfx (idx 300)   s-n2         192.168.3.2
*> i 115  16400  Pop         SR Pfx (idx 400)   s-n3         192.168.1.2
*> i 115  16500  16500       SR Pfx (idx 500)   s-n1         192.168.0.2
*> i 115  16500  16500       SR Pfx (idx 500)   s-n2         192.168.3.2
*> i 115  16600  16600       SR Pfx (idx 600)   s-n1         192.168.0.2
*> i 115  16700  16700       SR Pfx (idx 700)   s-n1         192.168.0.2
*> i 115  16800  16800       SR Pfx (idx 800)   s-n1         192.168.0.2
```

SR-MPLS defines two kinds of SIDs, and both are visible in this table:

* **Prefix-SIDs** (`SR Pfx`) are *global*. Each node advertises a Prefix-SID
  *index* for its loopback in the Prefix-SID sub-TLV of the IS-IS Extended IP
  Reachability TLV. Every router in the domain resolves the index against the
  SRGB (Segment Routing Global Block, base 16000 here), so index 800 becomes
  label 16800 on every node, and a packet can cross the whole domain with a
  single label. Multi-hop entries are installed as a swap (e.g.
  `16500 -> 16500` toward `r1`); entries whose owner is directly adjacent
  (`16200`, `16300`, `16400`) or local (`16100`) are installed as `Pop`
  (penultimate-hop popping).
* **Adjacency-SIDs** (`SR Adj`) are *local*. Each node dynamically allocates
  one label per IS-IS adjacency from its SRLB (Segment Routing Local Block,
  base 15000 here) and advertises it in the Adj-SID sub-TLV of the Extended
  IS Reachability TLV. An Adjacency-SID means "pop and forward over this
  specific link", regardless of the IGP shortest path — TI-LFA uses them to
  steer repair traffic over links the SPF would not normally choose. Because
  they are allocated on adjacency bring-up, the actual values (15000, 15001,
  ...) can differ from run to run.

## Enable TI-LFA

Let's enable TI-LFA with `set router isis fast-reroute ti-lfa`.

``` shell
$ sudo ip netns exec s vty
s>configure
s#set router isis fast-reroute ti-lfa
s#commit
s#exit
s>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route
...
L2 *> 10.0.0.8/32 [115/12] via 192.168.0.2, s-n1, label 16800, 00:00:00
   *?             [115/13] via 192.168.3.2, s-n2, label 16500 15000 15002 16800, 00:00:00
```

Routes now show a second line marked with `?` — the pre-computed TI-LFA
backup path, installed in the kernel FIB alongside the primary so that
traffic can be switched over the moment the primary fails.

Let's decode the backup for destination `d`. TI-LFA protects the primary
first hop `n1` (node protection: the repair must survive `n1` going down
entirely, not just the `s-n1` link). It computes:

* the **P-space**: nodes `s` can reach without going through `n1`,
* the **Q-space** of `d`: nodes that reach `d` without going through `n1`,
* and the **post-convergence path** — the path the network will use after it
  reconverges on the failure: `s -> n2 -> r1 -> r2 -> r3 -> d`.

The repair is then encoded as an SR segment list along that path:

| label | segment              | meaning                                    |
|:------|:---------------------|:-------------------------------------------|
| 16500 | Node-SID of `r1`     | shortest-path to the P/Q node `r1` (via n2) |
| 15000 | Adj-SID `r1 -> r2`   | force the expensive `r1-r2` link            |
| 15002 | Adj-SID `r2 -> r3`   | force the expensive `r2-r3` link            |
| 16800 | Prefix-SID of `d`    | label-switch the rest of the way to `d`     |

(The two Adjacency-SID values come from each router's SRLB and can differ
between runs.)

The final `16800` deserves a comment: the repair list itself only steers the
packet to its release point `r3`. `r3` can IP-route a packet addressed to
`10.0.0.8`, but traffic *tunneled through* this route — such as our recursive
static route toward the edge prefix `172.16.1.0/24` — carries an inner
destination `r3` knows nothing about. Appending the destination's own
Prefix-SID keeps the packet label-switched all the way to `d`, so anything
riding this route survives the repair (RFC 9855 §6.1).

The graph-level view of the computation is available with `show isis ti-lfa`:

``` shell
s>show isis ti-lfa
TI-LFA: enabled (sr-mpls: on, srv6: off)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 20ms ago, took 1.008ms, inflight=false, pending=false
      ti-lfa: targets=6 mode=serial workers=1 spf{q=6 pc=6 dedup-saved=0} took 883μs

L2 TI-LFA repair paths:
  Destination r2 (vertex 15)
    [0] first-hop s.4 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2, via r2.3)
  Destination r3 (vertex 17)
    [0] first-hop s.4 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2, via r2.3)
          AdjSid(r2, r3, via r2.4)
  Destination d (vertex 18)
    [0] first-hop s.4 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2, via r2.3)
          AdjSid(r2, r3, via r2.4)
```

## Force the backup to become primary

There is a handy command for examining the TI-LFA backup path without
breaking anything:

``` shell
s>configure
s#set router isis fast-reroute backup-as-primary
s#commit
s#exit
s>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route
...
L2 *> 10.0.0.8/32 [115/12] via 192.168.3.2, s-n2, label 16500 15000 15002 16800, 00:00:00
   *?             [115/13] via 192.168.0.2, s-n1, label 16800, 00:00:00
```

This swaps the primary and backup paths, so we can exercise the TI-LFA
repair path with live traffic while every link and node stays up.

Notice the static route as well: because it resolves recursively through
`10.0.0.8/32`, it followed the swap and now forwards over the repair label
stack too — no static configuration change required.

## Examine the MPLS labels on the backup path

Let's send traffic over the TI-LFA repair path.

``` shell
$ sudo ip netns exec s vty
s>ping 10.0.0.8
PING 10.0.0.8 (10.0.0.8) 56(84) bytes of data.
64 bytes from 10.0.0.8: icmp_seq=1 ttl=63 time=0.152 ms
64 bytes from 10.0.0.8: icmp_seq=2 ttl=63 time=0.063 ms
64 bytes from 10.0.0.8: icmp_seq=3 ttl=63 time=0.102 ms
64 bytes from 10.0.0.8: icmp_seq=4 ttl=63 time=0.110 ms
```

Since the traffic now takes the TI-LFA path, we can capture it on node `n2`.
Log in to `n2` and watch the packets coming from `s`:

``` shell
$ sudo ip netns exec n2 vty
n2>tcpdump -li n2-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
02:52:57.099698 MPLS (label 16500, tc 0, ttl 64) (label 15000, tc 0, ttl 64) (label 15002, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 5610, seq 4, length 64
02:52:57.604501 MPLS (label 16500, tc 0, ttl 64) (label 15000, tc 0, ttl 64) (label 15002, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 5610, seq 5, length 64
02:52:58.116343 MPLS (label 16500, tc 0, ttl 64) (label 15000, tc 0, ttl 64) (label 15002, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 5610, seq 6, length 64
```

The packets carry the full repair label stack. Following it hop by hop:
`n2` pops `16500` (PHP toward `r1`), `r1` pops its Adjacency-SID `15000` and
forwards over `r1-r2`, `r2` pops `15002` and forwards over `r2-r3`, and `r3`
pops `16800` (PHP toward `d`) and delivers the packet to `d`.

## Edge-to-edge traffic over the protected SR-MPLS path

TI-LFA protection is not limited to the core: the recursive static routes
extend it to the edge hosts. In `s.yaml` above we had:

``` yaml
  static:
    ipv4:
      route:
      - prefix: 172.16.1.0/24
        nexthop:
        - address: 10.0.0.8
```

and `d.yaml` has the mirror image for the return direction:

``` yaml
  static:
    ipv4:
      route:
      - prefix: 172.16.0.0/24
        nexthop:
        - address: 10.0.0.1
```

Each edge router reaches the opposite edge subnet through the other's
loopback, and each static route inherits whatever SR-MPLS path — primary or
repair — currently serves that loopback. The result is bi-directional
protection for the edge-to-edge traffic, while the edge hosts themselves
(`e1` and `e2`) only carry a plain default route and know nothing about
MPLS.

Let's ping from `e1` to `e2` (the backup is still promoted to primary):

``` shell
$ sudo ip netns exec e1 vty
e1>ping 172.16.1.2
PING 172.16.1.2 (172.16.1.2) 56(84) bytes of data.
64 bytes from 172.16.1.2: icmp_seq=1 ttl=61 time=0.133 ms
64 bytes from 172.16.1.2: icmp_seq=2 ttl=61 time=0.066 ms
64 bytes from 172.16.1.2: icmp_seq=3 ttl=61 time=0.090 ms
64 bytes from 172.16.1.2: icmp_seq=4 ttl=61 time=0.088 ms
64 bytes from 172.16.1.2: icmp_seq=5 ttl=61 time=0.103 ms
```

Capturing on `n2` again shows the edge-to-edge packets riding the same
TI-LFA label stack — the inner IP header is now `172.16.0.1 > 172.16.1.2`,
plain host traffic tunneled through the protected core:

``` shell
$ sudo ip netns exec n2 vty
n2>tcpdump -li n2-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
02:52:59.720144 MPLS (label 16500, tc 0, ttl 63) (label 15000, tc 0, ttl 63) (label 15002, tc 0, ttl 63) (label 16800, tc 0, [S], ttl 63) IP 172.16.0.1 > 172.16.1.2: ICMP echo request, id 5630, seq 4, length 64
02:53:00.226361 MPLS (label 16500, tc 0, ttl 63) (label 15000, tc 0, ttl 63) (label 15002, tc 0, ttl 63) (label 16800, tc 0, [S], ttl 63) IP 172.16.0.1 > 172.16.1.2: ICMP echo request, id 5630, seq 5, length 64
02:53:00.733141 MPLS (label 16500, tc 0, ttl 63) (label 15000, tc 0, ttl 63) (label 15002, tc 0, ttl 63) (label 16800, tc 0, [S], ttl 63) IP 172.16.0.1 > 172.16.1.2: ICMP echo request, id 5630, seq 6, length 64
```

This is exactly the case the trailing Prefix-SID `16800` exists for: without
it, the repair would go unlabeled at `r3`, which has no route for
`172.16.1.0/24`, and this traffic would be dropped.

## Appendix: Core addresses & Prefix-SIDs

| name | address     | SID index | Prefix-SID label |
|:-----|:------------|:----------|:-----------------|
| s    | 10.0.0.1/32 | 100       | 16100            |
| n1   | 10.0.0.2/32 | 200       | 16200            |
| n2   | 10.0.0.3/32 | 300       | 16300            |
| n3   | 10.0.0.4/32 | 400       | 16400            |
| r1   | 10.0.0.5/32 | 500       | 16500            |
| r2   | 10.0.0.6/32 | 600       | 16600            |
| r3   | 10.0.0.7/32 | 700       | 16700            |
| d    | 10.0.0.8/32 | 800       | 16800            |

| name | address       |
|:-----|:--------------|
| e1   | 172.16.0.1/24 |
| e2   | 172.16.1.2/24 |

## Appendix: Networks

| link  | network         |
|:------|:----------------|
| s-e1  | 172.16.0.0/24   |
| s-n1  | 192.168.0.0/24  |
| s-n3  | 192.168.1.0/24  |
| n1-d  | 192.168.2.0/24  |
| s-n2  | 192.168.3.0/24  |
| r1-r2 | 192.168.4.0/24  |
| d-r3  | 192.168.5.0/24  |
| n1-r1 | 192.168.6.0/24  |
| n2-r1 | 192.168.7.0/24  |
| n1-r2 | 192.168.8.0/24  |
| r2-r3 | 192.168.9.0/24  |
| n3-r1 | 192.168.10.0/24 |
| d-e2  | 172.16.1.0/24   |
