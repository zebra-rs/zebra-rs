# OSPFv3 SRv6 (classic SID) & TI-LFA

This playset demonstrates OSPFv3 SRv6 with TI-LFA fast reroute and a BGP L3
service layer, using classic full-length SIDs (RFC 8986 — no
uSID/compression). It is the OSPFv3 sibling of the
[IS-IS SRv6 playset](../isis-srv6-classic/README.md): the same RFC 9855
topology on a pure IPv6 data plane, with the routing expressed as a single
OSPFv3 area 0 carrying the SRv6 extensions (RFC 9513 over the RFC 8362
extended LSAs) instead of IS-IS TLVs. Every core node owns an SRv6
*locator* (`fcbb:bbbb:X::/48`) instantiating an **End** SID, one **End.X**
SID per adjacency, and — on the edge routers — an **End.DT6** service SID.
The edge LANs are carried by iBGP between `s` and `d` as an SRv6
IPv6-unicast service (RFC 9252); the core carries no edge state. All core
and edge nodes run in separate network namespaces; each node runs zebra-rs
and its YAML configuration is injected with `vtyctl apply`.

## Topology

<img src="../images/TI-LFA.svg" alt="OSPFv3 SRv6 TI-LFA topology">

Loopbacks are `2001:db8::X/128`, locators `fcbb:bbbb:X::/48`, link networks
`2001:db8:N::/64`, and the two edge LANs are `2001:db8:100::/64` (e1 behind
s) and `2001:db8:200::/64` (e2 behind d). This playset shares namespace
names with the other SR playsets — bring up one of them at a time.

## Bring up all nodes

``` shell
$ ./up.sh
bring up
...
apply config: r3
applied
apply config: d
applied
```

OSPFv3 full-mesh convergence plus the iBGP session take a little while —
the session rides loopback reachability and retries its connection, so give
the lab a minute or two before expecting the service route.

## Examine routes on node `s`

``` shell
$ sudo ip netns exec s vty
s>show ipv6 route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> 2001:db8::1/128 is directly connected, lo, 00:02:50
O     2001:db8::1/128 [110/0] via ::, lo, 00:02:50
O  *> 2001:db8::2/128 [110/1] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:34
O  *> 2001:db8::3/128 [110/1] via fe80::8c26:f1ff:fe37:472c, s-n2, 00:02:34
O  *> 2001:db8::4/128 [110/1000] via fe80::ec58:22ff:fe66:3d20, s-n3, 00:02:34
O  *> 2001:db8::5/128 [110/2] via fe80::8c26:f1ff:fe37:472c, s-n2, weight 1, 00:02:28
                              via fe80::9461:feff:fe12:9ee9, s-n1, weight 1, 00:02:28
O  *> 2001:db8::6/128 [110/2] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:28
O  *> 2001:db8::7/128 [110/3] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:22
O  *> 2001:db8::8/128 [110/2] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:22
B     2001:db8::8/128 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:00:45
...
C  *> 2001:db8:100::/64 is directly connected, s-e1, 00:02:50
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:00:45
i  *> fcbb:bbbb:1::/128 [115/0] is directly connected, sr0, seg6local End, 00:02:50
i  *> fcbb:bbbb:1:40::/128 [115/0] is directly connected, sr0, seg6local End.DT6, 00:02:50
i  *> fcbb:bbbb:1:e000::/128 [115/0] is directly connected, s-n1, seg6local End.X nh6 2001:db8:1::2, s-n1, 00:02:40
i  *> fcbb:bbbb:1:e001::/128 [115/0] is directly connected, s-n2, seg6local End.X nh6 2001:db8:2::2, s-n2, 00:02:40
i  *> fcbb:bbbb:1:e002::/128 [115/0] is directly connected, s-n3, seg6local End.X nh6 2001:db8:3::2, s-n3, 00:02:40
O  *> fcbb:bbbb:2::/48 [110/1] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:34
O  *> fcbb:bbbb:3::/48 [110/1] via fe80::8c26:f1ff:fe37:472c, s-n2, 00:02:34
O  *> fcbb:bbbb:4::/48 [110/1000] via fe80::ec58:22ff:fe66:3d20, s-n3, 00:02:34
O  *> fcbb:bbbb:5::/48 [110/2] via fe80::8c26:f1ff:fe37:472c, s-n2, weight 1, 00:02:28
                               via fe80::9461:feff:fe12:9ee9, s-n1, weight 1, 00:02:28
O  *> fcbb:bbbb:6::/48 [110/2] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:28
O  *> fcbb:bbbb:7::/48 [110/3] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:22
O  *> fcbb:bbbb:8::/48 [110/2] via fe80::9461:feff:fe12:9ee9, s-n1, 00:02:22
...
```

The picture matches the IS-IS SRv6 playset with the OSPFv3 flavor: routes
are code `O` at distance 110, locators are advertised through the RFC 9513
SRv6 extensions and routed as plain `/48`s, and the node's own SIDs (End,
End.DT6, End.X) are `seg6local` /128 routes on `sr0` / the adjacency
interfaces. The unselected `O ... via ::, lo` lines are OSPFv3's
self-originated prefixes losing to their connected counterparts. The remote
edge LAN `2001:db8:200::/64` is a **BGP** route toward d's End.DT6 service
SID, and the unselected `B` copies of core prefixes show the same
advertisement losing to the IGP by distance.

``` shell
s>show bgp ipv6 summary
IPv6 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65000 VRF default vrf-id 0
RIB entries 9
Peers 1

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
2001:db8::8     4      65000         5         2        0    0    0 00:00:45 Established        4/5 s
```

## Take a look at the YAML configuration

Node `s`'s configuration (`s.yaml`). The `segment-routing locator` and
`router bgp` blocks are identical to the IS-IS SRv6 playset — the service
layer is IGP-agnostic; only the IGP section differs (OSPFv3 area 0,
point-to-point interfaces with explicit costs):

``` yaml
system:
  hostname: s
segment-routing:
  locator:
  - name: LOC1
    prefix: fcbb:bbbb:1::/48
router:
  ospfv3:
    router-id: 10.0.0.1
    segment-routing:
      srv6:
        locator: LOC1
    area:
    - area-id: 0.0.0.0
      interface:
      - if-name: lo
        enabled: true
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
  bgp:
    global:
      as: 65000
      router-id: 10.0.0.1
    timer:
      adv-interval:
        ibgp: 1
        ebgp: 1
    segment-routing:
      srv6:
        locator: LOC1
        ipv6-unicast: {}
    neighbor:
    - remote-address: 2001:db8::8
      remote-as: 65000
      update-source: 2001:db8::1
      enabled: true
      afi-safi:
      - name: ipv6
        enabled: true
        encapsulation-type: srv6
    afi-safi:
    - name: ipv6
      redistribute:
        connected: {}
```

`router ospfv3 segment-routing srv6 locator LOC1` advertises the locator
and instantiates the End / End.X SIDs; `router bgp segment-routing srv6 ...
ipv6-unicast` carves the End.DT6 service SID from the same locator and
`redistribute connected` + `encapsulation-type: srv6` export the edge LAN
with it. No static routes anywhere; the edge hosts carry only an IPv6
default route.

## `ping` node `d`'s loopback — plain IPv6 on the wire

``` shell
s>ping 2001:db8::8
PING 2001:db8::8 (2001:db8::8) 56 data bytes
64 bytes from 2001:db8::8: icmp_seq=1 ttl=63 time=0.050 ms
64 bytes from 2001:db8::8: icmp_seq=2 ttl=63 time=0.127 ms
```

``` shell
n1>tcpdump -li n1-s ip6 and icmp6
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:25:02.229484 IP6 2001:db8:1::1 > 2001:db8::8: ICMP6, echo request, id 55791, seq 4, length 64
```

Core forwarding is plain IPv6 — no labels, no encapsulation.

## The BGP service path — IPv6-in-IPv6 on the wire

Edge-to-edge traffic is different: `s` has no IGP route for
`2001:db8:200::/64`, so the BGP service route encapsulates it toward d's
End.DT6 SID (H.Encaps), and the core forwards it by the locator route:

``` shell
n1>tcpdump -li n1-s ip6 and dst net fcbb:bbbb:8::/48
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:25:03.903410 IP6 2001:db8:1::1 > fcbb:bbbb:8:40::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 55809, seq 4, length 64
```

At `d`, the End.DT6 SID decapsulates and delivers the inner packet to `e2`.

## Enable TI-LFA

``` shell
s>configure
s#set router ospfv3 fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via fe80::9461:feff:fe12:9ee9, s-n1, 00:00:00
   *?                 [110/3] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::], s-n2, 00:00:00
```

The `?` backup is an SRH-insertion repair along the post-convergence path
`s -> n2 -> r1 -> r2 -> r3 -> d` (P-space / Q-space, node protection of the
first hop `n1`): End of `r1`, End.X `r1 -> r2`, End.X `r2 -> r3` — and, as
in the IS-IS SRv6 playset, **no destination SID**: H.Insert keeps the
packet's current destination as the SRH's final segment. (The End.X
suffixes are allocated at adjacency bring-up and can differ between runs.)

OSPFv3 offers both the graph view and the per-prefix repair-list summary:

``` shell
s>show ospfv3 ti-lfa
OSPFv3 TI-LFA repair paths:
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
s>show ospfv3 repair-list
Prefix                         Primary via                Repair via                 Segments
2001:db8::6/128                fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::]
2001:db8::7/128                fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::]
2001:db8::8/128                fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::]
2001:db8:9::/64                fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::]
2001:db8:11::/64               fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::]
fcbb:bbbb:6::/48               fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::]
fcbb:bbbb:7::/48               fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::]
fcbb:bbbb:8::/48               fe80::9461:feff:fe12:9ee9  fe80::8c26:f1ff:fe37:472c  [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::]
```

Compare with the [OSPFv2 SR-MPLS repair-list](../ospfv2-srmpls/README.md):
there the labeled /32 repairs ended with the destination's own Prefix-SID,
while these SRv6 segment lists never name the destination — the H.Insert
encoding carries the original destination in the packet itself. Note also
that the protected set includes the remote **locators** (`fcbb:bbbb:8::/48`
et al.) — that is what will keep the BGP service alive below.

## Force the backup to become primary

``` shell
s>configure
s#set router ospfv3 fast-reroute backup-as-primary
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::], s-n2, 00:00:04
   *?                 [110/3] via fe80::9461:feff:fe12:9ee9, s-n1, 00:00:04
...
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n2, 00:01:15
...
O  *> fcbb:bbbb:8::/48 [110/2] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e001::], s-n2, 00:00:04
```

The IGP primaries and backups swap. The BGP service route still says
"encapsulate toward `fcbb:bbbb:8:40::`" — but notice its rendered egress
followed the promotion to `s-n2`: nexthop tracking re-resolved the service
SID through the promoted **locator** route underneath. The service layer
composes with protection by routing the outer destination.

## The repair on the wire — and two SRHs on the service packet

With the backup promoted, ping `d`'s loopback from `s`, ping `e2` from
`e1`, and capture on `n2`:

``` shell
n2>tcpdump -li n2-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:25:34.606796 IP6 2001:db8:2::1 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]2001:db8::8, [1]fcbb:bbbb:6:e001::, [2]fcbb:bbbb:5:e003::, [3]fcbb:bbbb:5::) ICMP6, echo request, id 56589, seq 10, length 64
09:25:34.606460 IP6 2001:db8:1::1 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]fcbb:bbbb:8:40::, [1]fcbb:bbbb:6:e001::, [2]fcbb:bbbb:5:e003::, [3]fcbb:bbbb:5::) RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 56590, seq 10, length 64
```

The first packet is the router-originated ping: one inserted SRH
(`segleft=3`) whose final segment `[0]` is the original destination
`2001:db8::8`. The second is the protected service flow, read inside-out:
the plain host packet (`2001:db8:100::100 > 2001:db8:200::100`), the
**service** encapsulation toward d's End.DT6 SID (`segleft=0`), and the
**TI-LFA repair** SRH spliced on top (`segleft=3`) with the service SID as
*its* final segment. Each layer only ever routes the destination of the
layer below.

(As in the IS-IS SRv6 playset: after insertion the packet is routed by its
first segment, and r1's locator is ECMP from `s`, so which of `n1`/`n2`
carries a given flow depends on the flow hash.)

## Appendix: Loopbacks, locators & links

| name | loopback        | locator            | End SID        |
|:-----|:----------------|:-------------------|:---------------|
| s    | 2001:db8::1/128 | fcbb:bbbb:1::/48   | fcbb:bbbb:1::  |
| n1   | 2001:db8::2/128 | fcbb:bbbb:2::/48   | fcbb:bbbb:2::  |
| n2   | 2001:db8::3/128 | fcbb:bbbb:3::/48   | fcbb:bbbb:3::  |
| n3   | 2001:db8::4/128 | fcbb:bbbb:4::/48   | fcbb:bbbb:4::  |
| r1   | 2001:db8::5/128 | fcbb:bbbb:5::/48   | fcbb:bbbb:5::  |
| r2   | 2001:db8::6/128 | fcbb:bbbb:6::/48   | fcbb:bbbb:6::  |
| r3   | 2001:db8::7/128 | fcbb:bbbb:7::/48   | fcbb:bbbb:7::  |
| d    | 2001:db8::8/128 | fcbb:bbbb:8::/48   | fcbb:bbbb:8::  |

End.X SIDs (one per adjacency) and the BGP End.DT6 service SIDs (e.g.
`s`: `fcbb:bbbb:1:40::`, `d`: `fcbb:bbbb:8:40::`) are carved dynamically
from each node's locator; suffix assignment depends on allocation order and
can differ between runs. OSPFv3 router-ids are `10.0.0.X` (a v3 router-id
is a 32-bit value even in an IPv6-only network).

| name | address              |
|:-----|:---------------------|
| e1   | 2001:db8:100::100/64 |
| e2   | 2001:db8:200::100/64 |

| link  | network           |
|:------|:------------------|
| s-e1  | 2001:db8:100::/64 |
| s-n1  | 2001:db8:1::/64   |
| s-n2  | 2001:db8:2::/64   |
| s-n3  | 2001:db8:3::/64   |
| n1-r1 | 2001:db8:4::/64   |
| n2-r1 | 2001:db8:5::/64   |
| r1-n3 | 2001:db8:6::/64   |
| n1-r2 | 2001:db8:7::/64   |
| r1-r2 | 2001:db8:8::/64   |
| r2-r3 | 2001:db8:9::/64   |
| n1-d  | 2001:db8:10::/64  |
| d-r3  | 2001:db8:11::/64  |
| d-e2  | 2001:db8:200::/64 |
