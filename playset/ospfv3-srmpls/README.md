# OSPFv3 SR-MPLS & TI-LFA

This playset demonstrates OSPFv3 SR-MPLS with TI-LFA fast reroute: IPv6
routing with an MPLS label data plane (RFC 8666 — OSPFv3 extensions for
Segment Routing). It completes the IGP x data-plane matrix of the
[TI-LFA playset family](../README.md): the same RFC 9855 topology as the
other four labs, with OSPFv3 area 0 carrying Prefix-SIDs that resolve
against the SRGB (base 16000), so IPv6 destinations forward over MPLS
label-switched paths. The edge story mirrors the
[IS-IS SR-MPLS playset](../isis-srmpls/README.md) in IPv6 form: a
*recursive IPv6 static route* whose nexthop is the remote loopback
resolves through the SR-MPLS route and inherits its label stack. All core
and edge nodes run in separate network namespaces; each node runs zebra-rs
and its YAML configuration is injected with `vtyctl apply`.

## Topology

<img src="../images/TI-LFA.svg" alt="OSPFv3 SR-MPLS TI-LFA topology">

Loopbacks are `2001:db8::X/128` with Prefix-SID index `X00` (so `d` =
`2001:db8::8`, label 16800), link networks `2001:db8:N::/64`, and the two
edge LANs are `2001:db8:100::/64` (e1 behind s) and `2001:db8:200::/64`
(e2 behind d). This playset shares namespace names with the other SR
playsets — bring up one of them at a time.

## Bring up all nodes

``` shell
$ ./up.sh
bring up
...
apply config: d
applied
```

OSPFv3 full-mesh convergence takes a little longer than the v2/IS-IS labs;
give it half a minute before checking routes.

## Examine routes on node `s`

``` shell
$ sudo ip netns exec s vty
s>show ipv6 route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> 2001:db8::1/128 is directly connected, lo, 00:01:03
O     2001:db8::1/128 [110/0] via ::, lo, 00:01:03
O  *> 2001:db8::2/128 [110/1] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16200, 00:00:47
O  *> 2001:db8::3/128 [110/1] via fe80::748b:c9ff:fea7:d6e0, s-n2, label 16300, 00:00:47
O  *> 2001:db8::4/128 [110/1000] via fe80::605c:e2ff:fe51:4115, s-n3, label 16400, 00:00:47
O  *> 2001:db8::5/128 [110/2] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16500, weight 1, 00:00:41
                              via fe80::748b:c9ff:fea7:d6e0, s-n2, label 16500, weight 1, 00:00:41
O  *> 2001:db8::6/128 [110/2] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16600, 00:00:47
O  *> 2001:db8::7/128 [110/3] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16700, 00:00:41
O  *> 2001:db8::8/128 [110/2] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16800, 00:00:41
...
C  *> 2001:db8:100::/64 is directly connected, s-e1, 00:01:03
S  *> 2001:db8:200::/64 [1/0] via 2001:db8::8 (recursive), 00:01:03
                              via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16800
...
```

Two things worth noticing against the sibling labs:

* Every remote loopback carries its Prefix-SID label — over **IPv6
  link-local nexthops**. This is MPLS forwarding on an IPv6-only network.
  And unlike the v2/IS-IS labs, even the *adjacent* owners' labels
  (`16200`, `16300`, `16400`) print unparenthesized: OSPFv3 originates its
  Prefix-SIDs with the NP (no-PHP) flag (RFC 8666 §5), so the label rides
  all the way to the owner instead of being popped at the penultimate hop.
* The IPv6 static route `2001:db8:200::/64` (e2's LAN) is *recursive*: its
  nexthop `2001:db8::8` is d's loopback, so it resolves through the
  SR-MPLS route and inherits label 16800 — the exact IPv6 mirror of the
  IS-IS playset's IPv4 recursive static.

The no-PHP behaviour is also visible in the ILM — adjacent owners are
swap entries, not `Pop`:

``` shell
s>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> O 110  15000  Pop         SR Adj (idx 0  )   s-n1         fe80::486c:d6ff:fe9a:c5ba
*> O 110  15001  Pop         SR Adj (idx 0  )   s-n2         fe80::748b:c9ff:fea7:d6e0
*> O 110  15002  Pop         SR Adj (idx 0  )   s-n3         fe80::605c:e2ff:fe51:4115
*> O 110  16100  Pop         SR Pfx (idx 100)   lo           ::1
*> O 110  16200  16200       SR Pfx (idx 200)   s-n1         fe80::486c:d6ff:fe9a:c5ba
*> O 110  16300  16300       SR Pfx (idx 300)   s-n2         fe80::748b:c9ff:fea7:d6e0
*> O 110  16400  16400       SR Pfx (idx 400)   s-n3         fe80::605c:e2ff:fe51:4115
*> O 110  16500  16500       SR Pfx (idx 500)   s-n1         fe80::486c:d6ff:fe9a:c5ba
*> O 110  16500  16500       SR Pfx (idx 500)   s-n2         fe80::748b:c9ff:fea7:d6e0
*> O 110  16600  16600       SR Pfx (idx 600)   s-n1         fe80::486c:d6ff:fe9a:c5ba
*> O 110  16700  16700       SR Pfx (idx 700)   s-n1         fe80::486c:d6ff:fe9a:c5ba
*> O 110  16800  16800       SR Pfx (idx 800)   s-n1         fe80::486c:d6ff:fe9a:c5ba
```

## Take a look at the YAML configuration

Node `s`'s configuration (`s.yaml`) — OSPFv3 area 0 with point-to-point
costs, `segment-routing mpls`, the loopback Prefix-SID, and the recursive
edge static:

``` yaml
interface:
- if-name: lo
  ipv6:
    address: 2001:db8::1/128
- if-name: s-n1
  ipv6:
    address: 2001:db8:1::1/64
- if-name: s-n2
  ipv6:
    address: 2001:db8:2::1/64
- if-name: s-n3
  ipv6:
    address: 2001:db8:3::1/64
- if-name: s-e1
  ipv6:
    address: 2001:db8:100::1/64
system:
  hostname: s
router:
  ospfv3:
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
    ipv6:
      route:
      - prefix: 2001:db8:200::/64
        nexthop:
        - address: 2001:db8::8
```

`d.yaml` carries the mirror static (`2001:db8:100::/64` via
`2001:db8::1`), giving bi-directional protection for the edge-to-edge
traffic; the edge hosts themselves only hold an IPv6 default route.

## Edge traffic — MPLS over the IPv6 core

``` shell
$ sudo ip netns exec e1 vty
e1>ping 2001:db8:200::100
PING 2001:db8:200::100 (2001:db8:200::100) 56 data bytes
64 bytes from 2001:db8:200::100: icmp_seq=1 ttl=60 time=0.050 ms
64 bytes from 2001:db8:200::100: icmp_seq=2 ttl=60 time=0.117 ms
```

``` shell
n1>tcpdump -nli n1-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:13:27.327517 MPLS (label 16800, tc 0, [S], ttl 63) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 21823, seq 4, length 64
```

The plain IPv6 host packet rides label 16800 — the label the recursive
static inherited — and, because of the NP flag, keeps it until `d` itself
pops it.

## Enable TI-LFA

``` shell
s>configure
s#set router ospfv3 fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16800, 00:00:00
   *?                 [110/3] via fe80::748b:c9ff:fea7:d6e0, s-n2, label 16500 15003 15001 16800, 00:00:00
```

The `?` backup encodes the post-convergence path
`s -> n2 -> r1 -> r2 -> r3 -> d` (P-space / Q-space, node protection of
the first hop `n1`) as `[Node-SID(r1), Adj-SID(r1->r2), Adj-SID(r2->r3),
Prefix-SID(d)]` — the same trailing destination SID as the other SR-MPLS
labs, so traffic tunneled through the route survives the repair
(RFC 9855 §6.1). The Adj-SID values come from each router's SRLB and can
differ between runs.

``` shell
s>show ospfv3 repair-list
Prefix                         Primary via                Repair via                 Segments
2001:db8::6/128                fe80::486c:d6ff:fe9a:c5ba  fe80::748b:c9ff:fea7:d6e0  [16500, 15003, 16600]
2001:db8::7/128                fe80::486c:d6ff:fe9a:c5ba  fe80::748b:c9ff:fea7:d6e0  [16500, 15003, 15001, 16700]
2001:db8::8/128                fe80::486c:d6ff:fe9a:c5ba  fe80::748b:c9ff:fea7:d6e0  [16500, 15003, 15001, 16800]
2001:db8:9::/64                fe80::486c:d6ff:fe9a:c5ba  fe80::748b:c9ff:fea7:d6e0  [16500, 15003]
2001:db8:11::/64               fe80::486c:d6ff:fe9a:c5ba  fe80::748b:c9ff:fea7:d6e0  [16500, 15003, 15001]
```

As in the OSPFv2 lab, the labeled /128s end their segment lists with the
destination's own Prefix-SID, while pure IP prefixes release at a point
that can route them.

## Force the backup to become primary

``` shell
s>configure
s#set router ospfv3 fast-reroute backup-as-primary
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via fe80::748b:c9ff:fea7:d6e0, s-n2, label 16500 15003 15001 16800, 00:00:05
   *?                 [110/3] via fe80::486c:d6ff:fe9a:c5ba, s-n1, label 16800, 00:00:05
...
S  *> 2001:db8:200::/64 [1/0] via 2001:db8::8 (recursive), 00:01:34
                              via fe80::748b:c9ff:fea7:d6e0, s-n2, label 16500 15003 15001 16800
```

The repair is promoted — and the recursive IPv6 static follows it
automatically: nexthop tracking re-resolves `2001:db8::8` through the
promoted route and re-installs the static with the full repair stack. No
static configuration changed.

## The repair on the wire

With the backup promoted, ping from `e1` again and capture on `n2`:

``` shell
n2>tcpdump -nli n2-s mpls
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:13:58.494483 MPLS (label 16500, tc 0, ttl 63) (label 15003, tc 0, ttl 63) (label 15001, tc 0, ttl 63) (label 16800, tc 0, [S], ttl 63) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 22592, seq 4, length 64
```

The edge host's IPv6 packet rides the full 4-label repair: `n2` pops
`16500` (PHP toward `r1` — adjacency and node SIDs of *transit* hops still
PHP normally), `r1` pops its Adj-SID toward `r2`, `r2` pops its Adj-SID
toward `r3`, and the trailing `16800` label-switches the final stretch to
`d`, which delivers to `e2`.

Deleting `backup-as-primary` (and `ti-lfa`) puts everything back:
the static re-resolves to `label 16800` via `s-n1` on the next
resolve cycle.

## Appendix

The Prefix-SID plan matches the whole family (index `X00` → label
`16X00`); addressing:

| name | loopback        | SID index | label |
|:-----|:----------------|:----------|:------|
| s    | 2001:db8::1/128 | 100       | 16100 |
| n1   | 2001:db8::2/128 | 200       | 16200 |
| n2   | 2001:db8::3/128 | 300       | 16300 |
| n3   | 2001:db8::4/128 | 400       | 16400 |
| r1   | 2001:db8::5/128 | 500       | 16500 |
| r2   | 2001:db8::6/128 | 600       | 16600 |
| r3   | 2001:db8::7/128 | 700       | 16700 |
| d    | 2001:db8::8/128 | 800       | 16800 |

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

OSPFv3 router-ids are `10.0.0.X` (a 32-bit value even on an IPv6-only
network).
