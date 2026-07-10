# IS-IS SRv6 (classic SID) & TI-LFA

This playset demonstrates IS-IS SRv6 with TI-LFA fast reroute, using
classic full-length SIDs (RFC 8986 — no uSID/compression). It is the SRv6
sibling of the [IS-IS SR-MPLS playset](../isis-srmpls/README.md): the same
RFC 9855 topology and metrics, but the data plane is pure IPv6. Every core
node owns an SRv6 *locator* (`fcbb:bbbb:X::/48`) from which it instantiates
its SIDs — an **End** SID (the SRv6 analog of a node SID) and one **End.X**
SID per IS-IS adjacency (the analog of an adjacency SID). There are no
labels anywhere: steady-state forwarding is plain IPv6, and the TI-LFA
repair is an SRH (Segment Routing Header) *inserted* into the packet in
flight. All core and edge nodes run in separate network namespaces; each
node runs zebra-rs and its YAML configuration is injected with `vtyctl
apply`.

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

C  *> ::1/128 is directly connected, lo, 00:00:47
C  *> 2001:db8::1/128 is directly connected, lo, 00:00:44
L2 *> 2001:db8::2/128 [115/11] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:43
L2 *> 2001:db8::3/128 [115/11] via fe80::385b:79ff:fef0:7528, s-n2, 00:00:43
L2 *> 2001:db8::4/128 [115/1010] via fe80::8e6:14ff:fe3e:b841, s-n3, 00:00:43
L2 *> 2001:db8::5/128 [115/12] via fe80::4f6:dff:fedb:16d6, s-n1, weight 1, 00:00:42
                               via fe80::385b:79ff:fef0:7528, s-n2, weight 1, 00:00:42
L2 *> 2001:db8::6/128 [115/12] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:42
L2 *> 2001:db8::7/128 [115/13] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:38
L2 *> 2001:db8::8/128 [115/12] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:38
...
C  *> 2001:db8:100::/64 is directly connected, s-e1, 00:00:44
L2 *> 2001:db8:200::/64 [115/12] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:38
i  *> fcbb:bbbb:1::/128 [115/0] is directly connected, sr0, seg6local End, 00:00:44
i  *> fcbb:bbbb:1:e000::/128 [115/0] is directly connected, s-n2, seg6local End.X nh6 2001:db8:0:2::2, s-n2, 00:00:44
i  *> fcbb:bbbb:1:e001::/128 [115/0] is directly connected, s-n1, seg6local End.X nh6 2001:db8:0:1::2, s-n1, 00:00:44
i  *> fcbb:bbbb:1:e002::/128 [115/0] is directly connected, s-n3, seg6local End.X nh6 2001:db8:0:3::2, s-n3, 00:00:44
L2 *> fcbb:bbbb:2::/48 [115/1] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:43
L2 *> fcbb:bbbb:3::/48 [115/1] via fe80::385b:79ff:fef0:7528, s-n2, 00:00:43
L2 *> fcbb:bbbb:4::/48 [115/1000] via fe80::8e6:14ff:fe3e:b841, s-n3, 00:00:43
L2 *> fcbb:bbbb:5::/48 [115/2] via fe80::4f6:dff:fedb:16d6, s-n1, weight 1, 00:00:42
                               via fe80::385b:79ff:fef0:7528, s-n2, weight 1, 00:00:42
L2 *> fcbb:bbbb:6::/48 [115/2] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:42
L2 *> fcbb:bbbb:7::/48 [115/3] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:38
L2 *> fcbb:bbbb:8::/48 [115/2] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:38
...
```

Compared with the SR-MPLS playsets, three things stand out:

* Steady-state routes carry **no encapsulation at all** — remote loopbacks
  are plain IPv6 routes via link-local nexthops. In SRv6 the "label" only
  appears when a path must be steered (TI-LFA below); the common case is
  ordinary IPv6 forwarding.
* `s`'s own SIDs are installed as `seg6local` /128 routes carved from its
  locator `fcbb:bbbb:1::/48`: the **End** SID (`fcbb:bbbb:1::`, on the
  dedicated `sr0` device) and one **End.X** per adjacency
  (`...:e000::`–`...:e002::`), each bound to a specific neighbor. These are
  the SRv6 equivalents of the MPLS ILM entries.
* Every remote locator is a routed `/48` — reaching `fcbb:bbbb:5::` (r1's
  End SID) is just longest-prefix matching, no label distribution needed.
* The edge LANs (`2001:db8:100::/64`, `2001:db8:200::/64`) are ordinary
  IS-IS prefixes: `s` and `d` advertise them as *passive* IS-IS interfaces,
  so no static routes are required at all (see below).

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
    - if-name: s-e1
      passive: true
      ipv6:
        enabled: true
```

The `segment-routing locator` block defines the node's SID space, and
`router isis segment-routing srv6 locator LOC1` hands it to IS-IS, which
advertises it (SRv6 Locator TLV, RFC 9352) and dynamically instantiates the
End / End.X SIDs seen above. Because the locator has no `behavior: usid`,
the SIDs use the classic RFC 8986 full-SID layout.

Note the edge model difference from the SR-MPLS playsets: there is **no
static route**. The LAN toward `e1` is simply a passive IS-IS interface —
the prefix is flooded into the IGP and routed natively, and (as we will see)
TI-LFA protects it like any other prefix. The edge hosts `e1`/`e2` still
carry only a plain IPv6 default route toward their first-hop router.

## `ping` node `d`'s loopback — plain IPv6 on the wire

``` shell
s>ping 2001:db8::8
PING 2001:db8::8 (2001:db8::8) 56 data bytes
64 bytes from 2001:db8::8: icmp_seq=1 ttl=63 time=0.060 ms
64 bytes from 2001:db8::8: icmp_seq=2 ttl=63 time=0.244 ms
64 bytes from 2001:db8::8: icmp_seq=3 ttl=63 time=0.067 ms
```

Capturing on `n1` shows the contrast with SR-MPLS: no labels, no headers —
just the ICMPv6 packet itself:

``` shell
n1>tcpdump -li n1-s ip6 and icmp6
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
08:58:23.944697 IP6 2001:db8:0:1::1 > 2001:db8::8: ICMP6, echo request, id 42218, seq 4, length 64
```

## Enable TI-LFA

``` shell
s>configure
s#set router isis fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
L2 *> 2001:db8::8/128 [115/12] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:00
   *?                 [115/13] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e002::], s-n2, 00:00:00
```

The `?` backup line is a **seg6** path: the repair is an SRH carrying the
post-convergence path `s -> n2 -> r1 -> r2 -> r3 -> d` as a list of SRv6
SIDs, computed exactly as in the SR-MPLS playsets (P-space / Q-space, node
protection of the first hop `n1`):

| segment              | SID                  | meaning                                  |
|:---------------------|:---------------------|:------------------------------------------|
| End of `r1`          | `fcbb:bbbb:5::`      | shortest-path to the P/Q node `r1`         |
| End.X `r1 -> r2`     | `fcbb:bbbb:5:e003::` | force the expensive `r1-r2` link           |
| End.X `r2 -> r3`     | `fcbb:bbbb:6:e002::` | force the expensive `r2-r3` link           |

Unlike SR-MPLS, **no destination SID is appended**: the repair is applied
by *SRH insertion* (H.Insert), which keeps the packet's original
destination address as the SRH's final segment. When the last repair SID
has been consumed, the destination address simply reverts to the original
one and normal IPv6 forwarding finishes the job — the "get all the way to
`d`" guarantee that the MPLS repair needs a trailing Prefix-SID for is
built into the encoding here.

``` shell
s>show isis ti-lfa
TI-LFA: enabled (sr-mpls: off, srv6: on)
SPF stats:
  L1: never run, inflight=false, pending=false
  L2: last 22ms ago, took 515μs, inflight=false, pending=false
      ti-lfa: targets=6 mode=serial workers=1 spf{q=6 pc=6 dedup-saved=0} took 423μs

L2 TI-LFA repair paths:
  Destination r2 (vertex 5)
    [0] first-hop n2 (vertex 1, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2)
  Destination r3 (vertex 6)
    [0] first-hop n2 (vertex 1, link_id 4)
        segments:
          NodeSid(r1)
          AdjSid(r1, r2)
          AdjSid(r2, r3)
  Destination d (vertex 7)
    [0] first-hop n2 (vertex 1, link_id 4)
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
L2 *> 2001:db8::8/128 [115/12] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e002::], s-n2, 00:00:04
   *?                 [115/13] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:04
...
L2 *> 2001:db8:200::/64 [115/12] via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e002::], s-n2, 00:00:04
   *?                   [115/13] via fe80::4f6:dff:fedb:16d6, s-n1, 00:00:04
```

The primary and backup swap, so the repair can be exercised with live
traffic while everything stays up. Note that `e2`'s LAN prefix
`2001:db8:200::/64` is promoted right along with `d`'s loopback — as an
ordinary IS-IS prefix it received its own first-class TI-LFA repair, no
recursive-static indirection required.

## Examine the SRH on the repair path

Ping `d` from `s` and capture on node `n2`:

``` shell
s>ping 2001:db8::8
PING 2001:db8::8 (2001:db8::8) 56 data bytes
64 bytes from 2001:db8::8: icmp_seq=1 ttl=63 time=0.223 ms
64 bytes from 2001:db8::8: icmp_seq=2 ttl=63 time=0.109 ms
```

``` shell
n2>tcpdump -li n2-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
08:58:49.763802 IP6 2001:db8:0:2::1 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]2001:db8::8, [1]fcbb:bbbb:6:e002::, [2]fcbb:bbbb:5:e003::, [3]fcbb:bbbb:5::) ICMP6, echo request, id 42954, seq 4, length 64
```

This is the whole repair in one line: a type-4 routing header (SRH) has
been *inserted* into the ICMPv6 packet. The destination is currently the
first segment (`fcbb:bbbb:5::`, r1's End SID, `segleft=3`), the repair
SIDs sit at indices [3]..[1], and index **[0] is the original destination
`2001:db8::8`** — the final segment the packet returns to once the repair
is done. Each SID owner processes its segment: `r1` executes End, then its
own End.X toward `r2`; `r2` executes its End.X toward `r3`; at that point
`segleft` reaches 0 with the destination back to `2001:db8::8`, and `r3`
forwards it to `d` as plain IPv6.

## Edge-to-edge traffic over the protected path

With the backup still promoted, ping from `e1` to `e2`:

``` shell
$ sudo ip netns exec e1 vty
e1>ping 2001:db8:200::100
PING 2001:db8:200::100 (2001:db8:200::100) 56 data bytes
64 bytes from 2001:db8:200::100: icmp_seq=1 ttl=61 time=0.115 ms
64 bytes from 2001:db8:200::100: icmp_seq=2 ttl=61 time=0.100 ms
64 bytes from 2001:db8:200::100: icmp_seq=3 ttl=61 time=0.220 ms
```

``` shell
n1>tcpdump -li n1-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:02:28.101440 IP6 2001:db8:100::100 > fcbb:bbbb:5::: RT6 (len=8, type=4, segleft=3, last-entry=3, tag=0, [0]2001:db8:200::100, [1]fcbb:bbbb:6:e002::, [2]fcbb:bbbb:5:e003::, [3]fcbb:bbbb:5::) ICMP6, echo request, id 44539, seq 5, length 64
```

Two things are worth savoring here:

* The source and final segment are the **plain edge host addresses**
  (`2001:db8:100::100 -> [0]2001:db8:200::100`). The host's ordinary IPv6
  packet had the repair SRH spliced into it in flight at `s` — no static
  route, no service configuration, no encapsulation state anywhere. In the
  SR-MPLS playsets the same protection required the recursive static
  routes plus the trailing Prefix-SID; with SRv6 insertion it falls out of
  the IGP for free.
* This capture is from `n1`, not `n2`. After the SRH is inserted, the
  packet is routed by its *current* destination — the first segment,
  `fcbb:bbbb:5::` — and r1's locator is ECMP-reachable from `s` (cost 2
  via both `n1` and `n2`). This flow hashed onto the `n1` leg, while the
  earlier `s -> d` ping hashed onto `n2`. The repair intent lives in the
  SRH itself, not in the first physical hop.

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

End.X SIDs are carved dynamically from each node's locator (e.g. `s`'s
`fcbb:bbbb:1:e000::`–`e002::`), one per adjacency; the suffix assignment
depends on adjacency bring-up order and can differ between runs.

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
