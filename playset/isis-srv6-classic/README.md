# IS-IS SRv6 (classic SID) & TI-LFA

This playset demonstrates IS-IS SRv6 with TI-LFA fast reroute and a BGP L3
service layer, using classic full-length SIDs (RFC 8986 — no
uSID/compression). It is the SRv6 sibling of the
[IS-IS SR-MPLS playset](../isis-srmpls/README.md): the same RFC 9855
topology and metrics, but the data plane is pure IPv6. Every core node owns
an SRv6 *locator* (`fcbb:bbbb:X::/48`) from which it instantiates its SIDs —
an **End** SID (the SRv6 analog of a node SID) and one **End.X** SID per
IS-IS adjacency (the analog of an adjacency SID). The edge LANs are carried
by an iBGP session between `s` and `d` as an SRv6 L3 service (RFC 9252):
each edge router advertises its connected prefixes with an **End.DT6**
service SID, and the remote side encapsulates edge traffic toward that SID.
There are no labels anywhere: steady-state core forwarding is plain IPv6,
service traffic is IPv6-in-IPv6 (H.Encaps), and the TI-LFA repair is an SRH
(Segment Routing Header) *inserted* into the packet in flight. All core and
edge nodes run in separate network namespaces; each node runs zebra-rs and
its YAML configuration is injected with `vtyctl apply`.

## Topology

<img src="../images/TI-LFA.svg" alt="IS-IS SRv6 TI-LFA topology">

Loopbacks are `2001:db8::X/128`, locators `fcbb:bbbb:X::/48`, and the two
edge LANs are `2001:db8:100::/64` (e1 behind s) and `2001:db8:200::/64`
(e2 behind d). This playset shares namespace names with the other SR
playsets — bring up one of them at a time.

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

## Examine routes on node `s`

``` shell
$ sudo ip netns exec s vty
s>show ipv6 route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> ::1/128 is directly connected, lo, 00:00:54
C  *> 2001:db8::1/128 is directly connected, lo, 00:00:51
L2 *> 2001:db8::2/128 [115/11] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:50
L2 *> 2001:db8::3/128 [115/11] via fe80::b812:f7ff:fe1e:fdf7, s-n2, 00:00:50
L2 *> 2001:db8::4/128 [115/1010] via fe80::485f:fff:fe9e:7084, s-n3, 00:00:50
L2 *> 2001:db8::5/128 [115/12] via fe80::b812:f7ff:fe1e:fdf7, s-n2, weight 1, 00:00:49
                               via fe80::d093:4fff:fee7:d2fa, s-n1, weight 1, 00:00:49
L2 *> 2001:db8::6/128 [115/12] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:49
L2 *> 2001:db8::7/128 [115/13] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:45
B     2001:db8::8/128 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:00:46
L2 *> 2001:db8::8/128 [115/12] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:45
...
C  *> 2001:db8:100::/64 is directly connected, s-e1, 00:00:51
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:00:46
i  *> fcbb:bbbb:1::/128 [115/0] is directly connected, sr0, seg6local End, 00:00:51
B  *> fcbb:bbbb:1:40::/128 [200/0] is directly connected, sr0, seg6local End.DT6, 00:00:51
i  *> fcbb:bbbb:1:e000::/128 [115/0] is directly connected, s-n2, seg6local End.X nh6 2001:db8:0:2::2, s-n2, 00:00:51
i  *> fcbb:bbbb:1:e001::/128 [115/0] is directly connected, s-n1, seg6local End.X nh6 2001:db8:0:1::2, s-n1, 00:00:51
i  *> fcbb:bbbb:1:e002::/128 [115/0] is directly connected, s-n3, seg6local End.X nh6 2001:db8:0:3::2, s-n3, 00:00:51
L2 *> fcbb:bbbb:2::/48 [115/1] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:50
L2 *> fcbb:bbbb:3::/48 [115/1] via fe80::b812:f7ff:fe1e:fdf7, s-n2, 00:00:50
L2 *> fcbb:bbbb:4::/48 [115/1000] via fe80::485f:fff:fe9e:7084, s-n3, 00:00:50
L2 *> fcbb:bbbb:5::/48 [115/2] via fe80::b812:f7ff:fe1e:fdf7, s-n2, weight 1, 00:00:49
                               via fe80::d093:4fff:fee7:d2fa, s-n1, weight 1, 00:00:49
L2 *> fcbb:bbbb:6::/48 [115/2] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:49
L2 *> fcbb:bbbb:7::/48 [115/3] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:45
L2 *> fcbb:bbbb:8::/48 [115/2] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:45
...
```

Compared with the SR-MPLS playsets, several things stand out:

* Steady-state core routes carry **no encapsulation at all** — remote
  loopbacks are plain IPv6 routes via link-local nexthops. In SRv6 an
  encapsulation appears only where a path must be steered.
* `s`'s own SIDs are installed as `seg6local` /128 routes carved from its
  locator `fcbb:bbbb:1::/48`: the **End** SID (`fcbb:bbbb:1::`, on the
  dedicated `sr0` device), the **End.DT6** service SID
  (`fcbb:bbbb:1:40::` — decapsulate and look the inner packet up in the
  IPv6 table; BGP carves it, so the entry renders `B` [200/0]), and one
  **End.X** per adjacency
  (`...:e000::`–`...:e002::`). These are the SRv6 equivalents of the MPLS
  ILM entries.
* Every remote locator is a routed `/48` — reaching another node's SIDs is
  just longest-prefix matching, no label distribution needed.
* The remote edge LAN `2001:db8:200::/64` is a **BGP** route whose nexthop
  is rendered `via seg6 [fcbb:bbbb:8:40::]` — d's End.DT6 service SID.
  d redistributes its connected prefixes into iBGP with SRv6 encapsulation,
  and `s` steers matching traffic into an IPv6-in-IPv6 tunnel toward that
  SID. The unselected `B` copies of the core prefixes (e.g.
  `2001:db8::8/128`) show the same advertisement losing to the IGP route
  by administrative distance — only the prefixes the IGP does not carry
  (the edge LANs) actually use the service path.

The iBGP session runs between the two loopbacks:

``` shell
s>show bgp ipv6 summary
IPv6 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65000 VRF default vrf-id 0
RIB entries 9
Peers 1

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
2001:db8::8     4      65000         6         4        0    0    0 00:01:58 Established        4/5 s
```

## Take a look at the YAML configuration

Node `s`'s configuration (`s.yaml`), applied with `vtyctl apply -f s.yaml`:

``` yaml
system:
  hostname: s
segment-routing:
  locator:
  - name: LOC1
    prefix: fcbb:bbbb:1::/48
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    hostname: s
    is-type: level-2-only
    segment-routing:
      srv6:
        locator: LOC1
    interface:
    - if-name: lo
      ipv6:
        enabled: true
    - if-name: s-n1
      network-type: point-to-point
      metric: 1
      ipv6:
        enabled: true
    - if-name: s-n2
      network-type: point-to-point
      metric: 1
      ipv6:
        enabled: true
    - if-name: s-n3
      network-type: point-to-point
      metric: 1000
      ipv6:
        enabled: true
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

Two layers share the same locator:

* The `segment-routing locator` block defines the node's SID space, and
  `router isis segment-routing srv6 locator LOC1` hands it to IS-IS, which
  advertises it (SRv6 Locator TLV, RFC 9352) and instantiates the
  End / End.X SIDs.
* `router bgp segment-routing srv6 ... ipv6-unicast` carves the **End.DT6**
  service SID from the same locator (RFC 9252 IPv6-unicast service).
  `redistribute connected` exports the node's connected prefixes — the only
  ones that matter are the edge LANs, since the IGP already carries the
  core links — and `encapsulation-type: srv6` on the neighbor attaches the
  SRv6 SID to the advertisements. Note there is no static route anywhere:
  the edge reachability is a BGP service riding the SRv6 transport, the
  IPv6 analog of the recursive statics in the SR-MPLS playsets.

The edge hosts `e1`/`e2` still carry only a plain IPv6 default route toward
their first-hop router.

## `ping` node `d`'s loopback — plain IPv6 on the wire

``` shell
s>ping 2001:db8::8
PING 2001:db8::8 (2001:db8::8) 56 data bytes
64 bytes from 2001:db8::8: icmp_seq=1 ttl=63 time=0.053 ms
64 bytes from 2001:db8::8: icmp_seq=2 ttl=63 time=0.091 ms
```

Capturing on `n1` shows the contrast with SR-MPLS: no labels, no extra
headers — just the ICMPv6 packet, routed hop by hop on the IGP path:

``` shell
n1>tcpdump -li n1-s ip6 and icmp6
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:11:03.963785 IP6 2001:db8:0:1::1 > 2001:db8::8: ICMP6, echo request, id 48941, seq 4, length 64
```

## The BGP service path — IPv6-in-IPv6 on the wire

Edge-to-edge traffic looks different: `s` has no IGP route for
`2001:db8:200::/64`, so the BGP service route encapsulates it toward d's
End.DT6 SID. Ping from `e1` and capture on `n1`:

``` shell
$ sudo ip netns exec e1 vty
e1>ping 2001:db8:200::100
```

``` shell
n1>tcpdump -li n1-s ip6 and dst net fcbb:bbbb:8::/48
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:09:05.524230 IP6 2001:db8:0:1::1 > fcbb:bbbb:8:40::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 47808, seq 5, length 64
```

The host's packet rides *inside* a fresh IPv6 header addressed to
`fcbb:bbbb:8:40::` (H.Encaps). The core routers forward it by the locator
route `fcbb:bbbb:8::/48` — they know nothing about the edge prefixes. At
`d`, the End.DT6 SID decapsulates and delivers the inner packet to `e2`.

## Enable TI-LFA

``` shell
s>configure
s#set router isis fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
L2 *> 2001:db8::8/128 [115/12] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:00
   *?                 [115/13] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e000::, fcbb:bbbb:6:e002::], s-n2, 00:00:00
```

The `?` backup line is a **seg6** path: an SRH carrying the
post-convergence path `s -> n2 -> r1 -> r2 -> r3 -> d` as a list of SRv6
SIDs, computed exactly as in the SR-MPLS playsets (P-space / Q-space, node
protection of the first hop `n1`):

| segment              | SID                  | meaning                                  |
|:---------------------|:---------------------|:------------------------------------------|
| End of `r1`          | `fcbb:bbbb:5::`      | shortest-path to the P/Q node `r1`         |
| End.X `r1 -> r2`     | `fcbb:bbbb:5:e000::` | force the expensive `r1-r2` link           |
| End.X `r2 -> r3`     | `fcbb:bbbb:6:e002::` | force the expensive `r2-r3` link           |

(The End.X suffixes are allocated per adjacency at bring-up and can differ
between runs.)

Unlike SR-MPLS, **no destination SID is appended**: the repair is applied
by *SRH insertion* (H.Insert), which keeps the packet's current destination
address as the SRH's final segment. When the last repair SID has been
consumed, the destination reverts and normal IPv6 forwarding finishes the
job — the "get all the way to the destination" guarantee that the MPLS
repair needs a trailing Prefix-SID for is built into the encoding here.

``` shell
s>show isis ti-lfa
TI-LFA: enabled (sr-mpls: off, srv6: on)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 22ms ago, took 502μs, inflight=false, pending=false
      ti-lfa: targets=6 mode=serial workers=1 spf{q=6 pc=6 dedup-saved=0} took 412μs

L2 TI-LFA repair paths:
  Destination r2 (vertex 5)
    [0] first-hop n2 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2)
  Destination r3 (vertex 6)
    [0] first-hop n2 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2)
          AdjSid(r2, r3)
  Destination d (vertex 7)
    [0] first-hop n2 (vertex 2, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2)
          AdjSid(r2, r3)
```

## Force the backup to become primary

``` shell
s>configure
s#set router isis fast-reroute backup-as-primary
s#commit
s#exit
s>show ipv6 route
...
L2 *> 2001:db8::8/128 [115/12] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e000::, fcbb:bbbb:6:e002::], s-n2, 00:00:00
   *?                 [115/13] via fe80::d093:4fff:fee7:d2fa, s-n1, 00:00:00
...
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:01:10
...
L2 *> fcbb:bbbb:8::/48 [115/2] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e000::, fcbb:bbbb:6:e002::], s-n2, 00:00:00
```

The IGP primaries and backups swap, so the repair can be exercised with
live traffic while everything stays up. Look closely at the service chain:
the BGP route for `2001:db8:200::/64` is **unchanged** — it still says
"encapsulate toward `fcbb:bbbb:8:40::`" — but the **locator route**
`fcbb:bbbb:8::/48` underneath it is now promoted onto the TI-LFA repair.
The service layer never needs to know: protection composes by routing the
outer destination.

## Examine the SRH on the repair path

Ping `d`'s loopback from `s` and capture the repair in flight:

``` shell
s>ping 2001:db8::8
PING 2001:db8::8 (2001:db8::8) 56 data bytes
64 bytes from 2001:db8::8: icmp_seq=1 ttl=63 time=0.058 ms
64 bytes from 2001:db8::8: icmp_seq=2 ttl=63 time=0.199 ms
```

``` shell
n1>tcpdump -li n1-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:11:12.180217 IP6 2001:db8:0:2::1 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]2001:db8::8, [1]fcbb:bbbb:6:e002::, [2]fcbb:bbbb:5:e000::, [3]fcbb:bbbb:5::) ICMP6, echo request, id 49474, seq 4, length 64
```

A type-4 routing header (SRH) has been *inserted* into the ICMPv6 packet.
The destination is currently the first segment (`fcbb:bbbb:5::`, r1's End
SID, `segleft=3`), the repair SIDs sit at indices [3]..[1], and index
**[0] is the original destination `2001:db8::8`** — the final segment the
packet returns to once the repair is done. Each SID owner processes its
segment: `r1` executes End, then its own End.X toward `r2`; `r2` executes
its End.X toward `r3`; at that point the destination is back to
`2001:db8::8` and `r3` forwards plain IPv6 to `d`.

One subtlety: this capture is from `n1`, even though the route says the
repair egresses `s-n2`. After the SRH is inserted the packet is routed by
its *current* destination — the first segment — and r1's locator
`fcbb:bbbb:5::/48` is ECMP-reachable from `s` (cost 2 via both `n1` and
`n2`), so each flow hashes onto one of the legs. The repair intent lives in
the SRH itself, not in the first physical hop.

## Protected service traffic — two SRHs on one packet

The best packet in the playset: with the backup still promoted, ping from
`e1` to `e2` and capture the *protected service* traffic:

``` shell
e1>ping 2001:db8:200::100
PING 2001:db8:200::100 (2001:db8:200::100) 56 data bytes
64 bytes from 2001:db8:200::100: icmp_seq=1 ttl=63 time=0.187 ms
64 bytes from 2001:db8:200::100: icmp_seq=2 ttl=63 time=0.111 ms
```

``` shell
n1>tcpdump -li n1-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:09:33.819965 IP6 2001:db8:0:1::1 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]fcbb:bbbb:8:40::, [1]fcbb:bbbb:6:e002::, [2]fcbb:bbbb:5:e000::, [3]fcbb:bbbb:5::) RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 48291, seq 5, length 64
```

Read it inside-out: the innermost packet is the plain host flow
(`2001:db8:100::100 > 2001:db8:200::100`); around it, the **service**
encapsulation toward d's End.DT6 SID (`segleft=0`,
`[0]fcbb:bbbb:8:40::`); and spliced on top, the **TI-LFA repair** SRH
(`segleft=3`) steering the outer packet along the post-convergence path,
with the service SID itself as *its* final segment. Service and protection
compose cleanly because each layer only ever routes the destination of the
layer below.

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
from each node's locator; the suffix assignment depends on allocation order
and can differ between runs.

| name | address              |
|:-----|:---------------------|
| e1   | 2001:db8:100::100/64 |
| e2   | 2001:db8:200::100/64 |

| link  | network            |
|:------|:-------------------|
| s-e1  | 2001:db8:100::/64  |
| s-n1  | 2001:db8:0:1::/64  |
| s-n2  | 2001:db8:0:2::/64  |
| s-n3  | 2001:db8:0:3::/64  |
| n1-r1 | 2001:db8:0:4::/64  |
| n2-r1 | 2001:db8:0:5::/64  |
| r1-n3 | 2001:db8:0:6::/64  |
| n1-r2 | 2001:db8:0:7::/64  |
| r1-r2 | 2001:db8:0:8::/64  |
| r2-r3 | 2001:db8:0:9::/64  |
| n1-d  | 2001:db8:0:10::/64 |
| d-r3  | 2001:db8:0:11::/64 |
| d-e2  | 2001:db8:200::/64  |
