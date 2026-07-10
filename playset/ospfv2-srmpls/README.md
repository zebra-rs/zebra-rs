# OSPFv2 SR-MPLS & TI-LFA

This playset demonstrates OSPFv2 SR-MPLS with TI-LFA fast reroute. It is the
OSPFv2 sibling of the [IS-IS SR-MPLS playset](../isis-srmpls/README.md): the
same RFC 9855 topology, addressing, and Prefix-SID plan, expressed with
OSPFv2 (single area 0, point-to-point links, and the SR extensions of
RFC 8665's Extended Prefix / Extended Link Opaque LSAs instead of IS-IS
sub-TLVs). Every core node advertises a Prefix-SID for its loopback, so any
node can reach every other node's loopback over an SR-MPLS label-switched
path. All core and edge nodes run in separate network namespaces. Each node
runs zebra-rs, and its YAML configuration is injected with the `vtyctl
apply` command.

## Topology

<img src="../images/TI-LFA.svg" alt="OSPFv2 SR-MPLS TI-LFA topology">

## Bring up all nodes

`./up.sh` sets up all namespaces, starts the zebra-rs routing daemon in each
of them, and injects the initial configuration. Note that this playset and
the IS-IS one use the same namespace names — bring up one of them at a time.

``` shell
$ ./up.sh
bring up
...
apply config: r3
applied
apply config: d
applied
```

## Examine routes on node `s`

Let's take a look at the routing table of node `s`.

``` shell
$ sudo ip netns exec s vty
s>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> 10.0.0.1/32 is directly connected, lo, 00:00:53
O     10.0.0.1/32 [110/0] via 0.0.0.0, lo, 00:00:53
O  *> 10.0.0.2/32 [110/1] via 192.168.0.2, s-n1, label (16200), 00:00:37
O  *> 10.0.0.3/32 [110/1] via 192.168.3.2, s-n2, label (16300), 00:00:37
O  *> 10.0.0.4/32 [110/1000] via 192.168.1.2, s-n3, label (16400), 00:00:37
O  *> 10.0.0.5/32 [110/2] via 192.168.0.2, s-n1, label 16500, weight 1, 00:00:31
                          via 192.168.3.2, s-n2, label 16500, weight 1, 00:00:31
O  *> 10.0.0.6/32 [110/2] via 192.168.0.2, s-n1, label 16600, 00:00:31
O  *> 10.0.0.7/32 [110/3] via 192.168.0.2, s-n1, label 16700, 00:00:31
O  *> 10.0.0.8/32 [110/2] via 192.168.0.2, s-n1, label 16800, 00:00:31
C  *> 127.0.0.0/8 is directly connected, lo, 00:00:55
C  *> 172.16.0.0/24 is directly connected, s-e1, 00:00:53
S  *> 172.16.1.0/24 [1/0] via 10.0.0.8 (recursive), 00:00:53
                          via 192.168.0.2, s-n1, label 16800
C  *> 192.168.0.0/24 is directly connected, s-n1, 00:00:53
O     192.168.0.0/24 [110/1] via 0.0.0.0, lo, 00:00:47
C  *> 192.168.1.0/24 is directly connected, s-n3, 00:00:53
O     192.168.1.0/24 [110/1000] via 0.0.0.0, lo, 00:00:47
O  *> 192.168.2.0/24 [110/2] via 192.168.0.2, s-n1, 00:00:37
C  *> 192.168.3.0/24 is directly connected, s-n2, 00:00:53
O     192.168.3.0/24 [110/1] via 0.0.0.0, lo, 00:00:47
O  *> 192.168.4.0/24 [110/1002] via 192.168.0.2, s-n1, weight 1, 00:00:31
                                via 192.168.3.2, s-n2, weight 1, 00:00:31
O  *> 192.168.5.0/24 [110/3] via 192.168.0.2, s-n1, 00:00:31
O  *> 192.168.6.0/24 [110/2] via 192.168.0.2, s-n1, 00:00:37
O  *> 192.168.7.0/24 [110/2] via 192.168.3.2, s-n2, 00:00:37
O  *> 192.168.8.0/24 [110/2] via 192.168.0.2, s-n1, 00:00:37
O  *> 192.168.9.0/24 [110/1002] via 192.168.0.2, s-n1, 00:00:31
O  *> 192.168.10.0/24 [110/1002] via 192.168.0.2, s-n1, weight 1, 00:00:31
                                 via 192.168.3.2, s-n2, weight 1, 00:00:31
```

The picture is the same as in the IS-IS playset, with the OSPF flavor:
routes are code `O` at administrative distance 110, and the loopback metrics
are the plain SPF path costs (e.g. `10.0.0.8/32` at cost 2 over `s-n1-d`).
Remote loopbacks carry the owner's Prefix-SID label; parenthesized labels
like `(16200)` are implicit-null (the owner is adjacent, so PHP applies);
`10.0.0.5/32` (r1) is ECMP over `n1` and `n2`; and the static route
`172.16.1.0/24` resolves recursively through the SR-MPLS route to `d`'s
loopback, inheriting label `16800` — see the IS-IS playset README for the
full explanation of the recursive static.

## Take a look at the YAML configuration

Node `s`'s configuration is in `s.yaml` and is applied with `vtyctl apply -f
s.yaml`. The interface addressing, `system hostname`, and the recursive
static route are identical to the IS-IS playset; only the `router` section
differs — a single OSPF area 0, with every core link declared
point-to-point and carrying an explicit `cost`:

``` yaml
system:
  hostname: s
router:
  ospf:
    router-id: 10.0.0.1
    segment-routing:
      mpls: {}
    area:
    - area-id: 0.0.0.0
      interface:
      - if-name: lo
        enabled: true
        prefix-sid:
          index: 100
      - if-name: s-n1
        enabled: true
        network-type: point-to-point
        cost: 1
      - if-name: s-n2
        enabled: true
        network-type: point-to-point
        cost: 1
      - if-name: s-n3
        enabled: true
        network-type: point-to-point
        cost: 1000
  static:
    ipv4:
      route:
      - prefix: 172.16.1.0/24
        nexthop:
        - address: 10.0.0.8
```

`segment-routing mpls` enables the SR extensions: the router advertises its
SRGB/SRLB in the Router Information Opaque LSA, the loopback's Prefix-SID in
an Extended Prefix Opaque LSA (RFC 8665), and one dynamically allocated
Adjacency-SID per neighbor in Extended Link Opaque LSAs.

## `show mpls ilm` to examine the ILM (Incoming Label Map)

``` shell
s>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> O 110  15000  Pop         SR Adj (idx 0  )   s-n1         192.168.0.2
*> O 110  15001  Pop         SR Adj (idx 0  )   s-n2         192.168.3.2
*> O 110  15002  Pop         SR Adj (idx 0  )   s-n3         192.168.1.2
*> O 110  16100  Pop         SR Pfx (idx 100)   lo           127.0.0.1
*> O 110  16200  Pop         SR Pfx (idx 200)   s-n1         192.168.0.2
*> O 110  16300  Pop         SR Pfx (idx 300)   s-n2         192.168.3.2
*> O 110  16400  Pop         SR Pfx (idx 400)   s-n3         192.168.1.2
*> O 110  16500  16500       SR Pfx (idx 500)   s-n1         192.168.0.2
*> O 110  16500  16500       SR Pfx (idx 500)   s-n2         192.168.3.2
*> O 110  16600  16600       SR Pfx (idx 600)   s-n1         192.168.0.2
*> O 110  16700  16700       SR Pfx (idx 700)   s-n1         192.168.0.2
*> O 110  16800  16800       SR Pfx (idx 800)   s-n1         192.168.0.2
```

Same structure as IS-IS, sourced from OSPF (`O`, distance 110): global
Prefix-SIDs resolved against the SRGB (base 16000) install as swap entries
for multi-hop owners and `Pop` for adjacent/local ones, and per-adjacency
Adjacency-SIDs from the SRLB (base 15000) install as `Pop` toward each
neighbor.

## Enable TI-LFA

``` shell
$ sudo ip netns exec s vty
s>configure
s#set router ospf fast-reroute ti-lfa
s#commit
s#exit
s>show ip route
...
O  *> 10.0.0.8/32 [110/2] via 192.168.0.2, s-n1, label 16800, 00:00:00
   *?             [110/3] via 192.168.3.2, s-n2, label 16500 15001 15001 16800, 00:00:00
```

The `?` line is the pre-computed TI-LFA backup, installed alongside the
primary. As in the IS-IS playset, the repair protects the first-hop node
`n1` and encodes the post-convergence path `s -> n2 -> r1 -> r2 -> r3 -> d`
as an SR segment list: Node-SID of the P/Q node `r1` (16500), the
Adjacency-SIDs forcing the expensive `r1-r2` and `r2-r3` links, and finally
`d`'s own Prefix-SID (16800) so the packet stays label-switched to the
destination (RFC 9855 §6.1). In this run `r1`'s Adj-SID for `r1-r2` and
`r2`'s Adj-SID for `r2-r3` happen to both be 15001 — Adjacency-SIDs are
local labels from each router's own SRLB, so the same value on different
routers is perfectly fine (and the values can differ from run to run).

OSPF has a graph-level view of the computation, plus a per-prefix
repair-list summary that shows the full segment lists — including the
trailing Prefix-SID of each destination:

``` shell
s>show ospf ti-lfa
OSPF TI-LFA repair paths:
  Destination 10.0.0.6 (vertex 5)
    [0] first-hop 10.0.0.3 (vertex 2, link_id 4)
        segments:
          Node-SID 10.0.0.5 (vertex 4)
          Adj-SID 10.0.0.5 -> 10.0.0.6 (vertex 4 -> 5)
  Destination 10.0.0.7 (vertex 6)
    [0] first-hop 10.0.0.3 (vertex 2, link_id 4)
        segments:
          Node-SID 10.0.0.5 (vertex 4)
          Adj-SID 10.0.0.5 -> 10.0.0.6 (vertex 4 -> 5)
          Adj-SID 10.0.0.6 -> 10.0.0.7 (vertex 5 -> 6)
  Destination 10.0.0.8 (vertex 7)
    [0] first-hop 10.0.0.3 (vertex 2, link_id 4)
        segments:
          Node-SID 10.0.0.5 (vertex 4)
          Adj-SID 10.0.0.5 -> 10.0.0.6 (vertex 4 -> 5)
          Adj-SID 10.0.0.6 -> 10.0.0.7 (vertex 5 -> 6)
s>show ospf repair-list
Prefix                 Primary via        Repair via         Segments
10.0.0.6/32            192.168.0.2        192.168.3.2        [16500, 15001, 16600]
10.0.0.7/32            192.168.0.2        192.168.3.2        [16500, 15001, 15001, 16700]
10.0.0.8/32            192.168.0.2        192.168.3.2        [16500, 15001, 15001, 16800]
192.168.5.0/24         192.168.0.2        192.168.3.2        [16500, 15001, 15001]
192.168.9.0/24         192.168.0.2        192.168.3.2        [16500, 15001]
```

Repairs exist exactly for the single-nexthop destinations behind `n1` —
`r2`, `r3`, `d`, and the transit subnets — while `r1` protects itself
through its surviving ECMP leg. Note how the pure IP prefixes
(`192.168.5.0/24`, `192.168.9.0/24`) have no trailing label: they carry no
Prefix-SID, so the repair releases the packet at a point that can IP-route
it, while the labeled `/32`s end with the destination's own SID.

## Force the backup to become primary

``` shell
s>configure
s#set router ospf fast-reroute backup-as-primary
s#commit
s#exit
s>show ip route
...
O  *> 10.0.0.8/32 [110/2] via 192.168.3.2, s-n2, label 16500 15001 15001 16800, 00:00:19
   *?             [110/3] via 192.168.0.2, s-n1, label 16800, 00:00:19
...
S  *> 172.16.1.0/24 [1/0] via 10.0.0.8 (recursive), 00:01:29
                          via 192.168.3.2, s-n2, label 16500 15001 15001 16800
```

The primary and backup paths swap, so the TI-LFA repair path can be
exercised with live traffic while every link and node stays up. The
recursive static route follows automatically: it re-resolves through the
promoted route and now forwards over the repair label stack too.

## Examine the MPLS labels on the backup path

Ping `d` from `s` and capture on node `n2`:

``` shell
$ sudo ip netns exec s vty
s>ping 10.0.0.8
PING 10.0.0.8 (10.0.0.8) 56(84) bytes of data.
64 bytes from 10.0.0.8: icmp_seq=1 ttl=63 time=0.038 ms
64 bytes from 10.0.0.8: icmp_seq=2 ttl=63 time=0.122 ms
64 bytes from 10.0.0.8: icmp_seq=3 ttl=63 time=0.117 ms
```

``` shell
$ sudo ip netns exec n2 vty
n2>tcpdump -li n2-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
03:09:47.128391 MPLS (label 16500, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 13850, seq 4, length 64
03:09:47.632973 MPLS (label 16500, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 13850, seq 5, length 64
03:09:48.136175 MPLS (label 16500, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 15001, tc 0, ttl 64) (label 16800, tc 0, [S], ttl 64) IP 192.168.3.1 > 10.0.0.8: ICMP echo request, id 13850, seq 6, length 64
```

Following the stack hop by hop: `n2` pops `16500` (PHP toward `r1`), `r1`
pops its Adj-SID `15001` and forwards over `r1-r2`, `r2` pops its own
`15001` and forwards over `r2-r3`, and `r3` pops `16800` (PHP toward `d`)
and delivers the packet to `d`.

## Edge-to-edge traffic over the protected SR-MPLS path

Exactly as in the IS-IS playset, the mirrored recursive statics on `s`
(`172.16.1.0/24 via 10.0.0.8`) and `d` (`172.16.0.0/24 via 10.0.0.1`)
extend the protection to the edge hosts, which only carry default routes.
With the backup still promoted:

``` shell
$ sudo ip netns exec e1 vty
e1>ping 172.16.1.2
PING 172.16.1.2 (172.16.1.2) 56(84) bytes of data.
64 bytes from 172.16.1.2: icmp_seq=1 ttl=61 time=0.043 ms
64 bytes from 172.16.1.2: icmp_seq=2 ttl=61 time=0.081 ms
64 bytes from 172.16.1.2: icmp_seq=3 ttl=61 time=0.079 ms
```

``` shell
$ sudo ip netns exec n2 vty
n2>tcpdump -li n2-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
03:09:50.803890 MPLS (label 16500, tc 0, ttl 63) (label 15001, tc 0, ttl 63) (label 15001, tc 0, ttl 63) (label 16800, tc 0, [S], ttl 63) IP 172.16.0.1 > 172.16.1.2: ICMP echo request, id 13868, seq 6, length 64
```

The edge-to-edge packets ride the same repair label stack, with the plain
host addresses (`172.16.0.1 > 172.16.1.2`) as the inner header — traffic the
repair's release point could never route without the trailing `16800`.

## Appendix

The Prefix-SID plan, edge addresses, and per-link networks are identical to
the IS-IS playset — see the [appendix there](../isis-srmpls/README.md#appendix-core-addresses--prefix-sids).
The only routing difference is the protocol: OSPFv2 area 0 with
point-to-point interface costs in place of IS-IS level-2 metrics.
