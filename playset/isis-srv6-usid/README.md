# IS-IS SRv6 (uSID) & TI-LFA

This playset is the **uSID** (compressed SID, NEXT-C-SID flavor — RFC 9800)
variant of the [IS-IS SRv6 classic playset](../isis-srv6-classic/README.md).
The topology, addressing, locators, BGP End.DT6 service layer, and the
shared walkthrough arc are identical (this README adds a static-route
walkthrough of its own) — the *only* configuration difference is one
line per node:

``` yaml
segment-routing:
  locator:
  - name: LOC1
    prefix: fcbb:bbbb:1::/48
    behavior: usid          # <-- this line
```

With `behavior: usid`, the locator's 48 bits split into a 32-bit uSID
*block* (`fcbb:bbbb`) shared by the whole domain and a 16-bit *node id*
(`0001`..`0008`), and every SID becomes a 16-bit micro-instruction that
can be packed with others into a single 128-bit *carrier*. Where the
classic lab needed one 128-bit SID per repair segment, this lab fits the
whole TI-LFA repair into one address.

## Bring up all nodes

Same as the classic lab (`./up.sh`, shared namespace names — one playset
at a time; OSPFv3 + iBGP need a minute or two to settle).

## The uSID machinery in the kernel

``` shell
$ sudo ip netns exec s vty
s>show ipv6 route
...
i  *> fcbb:bbbb:1::/48 [115/0] is directly connected, sr0, seg6local End, 00:01:00
...
```

The node's own SID space looks different from the classic lab: instead of
a /128 End SID, the **whole locator /48** installs as an End with the
NEXT-C-SID flavor — the *uN* SID. In the kernel:

``` shell
s>ip -6 route show fcbb:bbbb:1::/48
fcbb:bbbb:1::/48  encap seg6local action End flavors next-csid lblen 32 nflen 16 dev sr0 proto isis metric 1024
```

`lblen 32 nflen 16` is the uSID split: 32-bit block, 16-bit node
function. Any packet whose destination starts `fcbb:bbbb:0001:...` is
processed by `s`, which *shifts* the address 16 bits left (consuming its
own id) and forwards on whatever micro-instruction surfaces next.

The adjacency SIDs exist in two forms on every node — here on `r1`:

``` shell
r1>ip -6 route | grep seg6local
fcbb:bbbb:5:e000::  encap seg6local action End.X nh6 2001:db8:0:4::1 dev r1-n1 proto isis metric 1024
fcbb:bbbb:5:e003::  encap seg6local action End.X nh6 2001:db8:0:8::2 dev r1-r2 proto isis metric 1024
fcbb:bbbb:5::/48  encap seg6local action End flavors next-csid lblen 32 nflen 16 dev sr0 proto isis metric 1024
fcbb:bbbb:e000::/48  encap seg6local action End.X nh6 2001:db8:0:4::1 flavors next-csid lblen 32 nflen 16 dev r1-n1 proto isis metric 1024
fcbb:bbbb:e003::/48  encap seg6local action End.X nh6 2001:db8:0:8::2 flavors next-csid lblen 32 nflen 16 dev r1-r2 proto isis metric 1024
...
```

The *addressed* form (`fcbb:bbbb:5:e003::`, plain End.X) serves packets
that name the SID explicitly; the *shifted* form
(`fcbb:bbbb:e003::/48`, NEXT-C-SID flavored **uA**) is what a packet
matches right after an upstream uSID consumed the node id — it executes
the cross-connect and shifts again. This pair is the entire
shift-and-forward pipeline of RFC 9800, visible as ordinary kernel
routes.

## Static routes over the SRv6 core

Three short experiments, best run from the fresh bring-up (each one
cleans up after itself). Together they tell one story: what a static
route does — and doesn't — get from an SRv6 underlay. They are the
live companion to the *SRv6 Static Routes* chapter of the book; the
[classic lab](../isis-srv6-classic/README.md) has the same walkthrough
on full-width SIDs.

### Recursion alone is not enough

`e2`'s subnet `2001:db8:200::/64` normally rides BGP with an End.DT6
service SID. Suppose we tried to reach it with a plain recursive
static instead, using `d`'s loopback as the gateway:

``` shell
$ sudo ip netns exec s vty
s>configure
s#set router static ipv6 route 2001:db8:200::/64 nexthop 2001:db8::8
s#commit
s#exit
s>show ipv6 route
...
B     2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n1, 00:00:30
S  *> 2001:db8:200::/64 [1/0] via 2001:db8::8 (recursive), 00:00:03
                              via fe80::8c94:9ff:fed4:4562, s-n1
```

The static (distance 1) displaces the BGP service route (200) and
resolves recursively just fine — but the covering route to
`2001:db8::8` is a *plain* IS-IS route (SRv6 encapsulates only where a
SID says so), so there is no transport to inherit. The kernel gets a
bare `via fe80::… proto static`, the packet leaves `s` unencapsulated,
and it dies one hop in — the core routes only links, loopbacks, and
locators:

``` shell
$ sudo ip netns exec e1 ping 2001:db8:200::100
3 packets transmitted, 0 received, 100% packet loss

n1>ip -6 route get 2001:db8:200::100
RTNETLINK answers: Network is unreachable
```

Delete it before moving on
(`delete router static ipv6 route 2001:db8:200::/64`, then `commit`) —
the BGP route takes the prefix back.

### An all-static SRv6 service

The BGP service layer can be rebuilt out of nothing but static
configuration. Egress side: pin a decap SID on `d` at an
operator-reserved function value (the `E064`+ range is exactly for
this):

``` shell
d#set router static ipv6 route fcbb:bbbb:8:e064::/128 action End.DT6
d#commit
d>show ipv6 route
...
S  *> fcbb:bbbb:8:e064::/128 [1/0] is directly connected, sr0, seg6local End.DT6, 00:00:03

d>ip -6 route show fcbb:bbbb:8:e064::/128
fcbb:bbbb:8:e064::  encap seg6local action End.DT6 table main dev sr0 proto static metric 1024 pref medium
```

Ingress side: steer the prefix into that SID with an explicit segment
list:

``` shell
s#set router static ipv6 route 2001:db8:200::/64 segments fcbb:bbbb:8:e064::
s#commit
s>show ipv6 route
...
S  *> 2001:db8:200::/64 [1/0] via seg6 [fcbb:bbbb:8:e064::], s-n1, 00:00:03

s>ip -6 route show 2001:db8:200::/64
2001:db8:200::/64 nhid 14  encap seg6 mode encap segs 1 [ fcbb:bbbb:8:e064:: ] via fcbb:bbbb:8:e064:: dev s-n1 proto static metric 1024 onlink pref medium
```

The edge-to-edge ping now works over the purely static path, and a
capture on `n1` shows both directions of the split-brain service —
the request tunneled to the pinned static SID, the reply still riding
`d`'s BGP-allocated one:

``` shell
$ sudo ip netns exec e1 ping 2001:db8:200::100
3 packets transmitted, 3 received, 0% packet loss

n1>tcpdump -nli n1-s ip6 proto 43
13:02:02.507740 IP6 2001:db8:0:1::1 > fcbb:bbbb:8:e064::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:e064::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 63058, seq 1, length 64
13:02:02.507780 IP6 2001:db8:0:10::2 > fcbb:bbbb:1:40::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:1:40::) IP6 2001:db8:200::100 > 2001:db8:100::100: ICMP6, echo reply, id 63058, seq 1, length 64
```

Clean up: delete `s`'s `2001:db8:200::/64` static and `d`'s
`fcbb:bbbb:8:e064::/128` SID.

### Inheriting the encapsulation

When a static route's gateway is covered by a route that *already*
carries SRv6 encapsulation — like the BGP End.DT6 service route —
recursive resolution inherits the segment list, the same way SR-MPLS
statics inherit label stacks in the [isis-srmpls](../isis-srmpls/README.md)
lab. Give `e2` a second loopback and reach it through a gateway inside
the BGP-served subnet:

``` shell
$ sudo ip netns exec e2 ip addr add 3001:db8::2/128 dev lo

d#set router static ipv6 route 3001:db8::2/128 nexthop 2001:db8:200::100
s#set router static ipv6 route 3001:db8::2/128 nexthop 2001:db8:200::100
```

The same command means different things on the two routers. On `d` the
gateway is on a connected subnet — a plain static. On `s` it is
covered only by the BGP SRv6 route, so the static inherits its
encapsulation:

``` shell
s>show ipv6 route
...
S  *> 3001:db8::2/128 [1/0] via 2001:db8:200::100 (recursive), 00:00:03
                            via seg6 [fcbb:bbbb:8:40::], s-n1

s>ip -6 route show 3001:db8::2
3001:db8::2 nhid 13  encap seg6 mode encap segs 1 [ fcbb:bbbb:8:40:: ] via fcbb:bbbb:8:: dev s-n1 proto static metric 1024 onlink pref medium

s>ip -6 route show 2001:db8:200::/64
2001:db8:200::/64 nhid 13  encap seg6 mode encap segs 1 [ fcbb:bbbb:8:40:: ] via fcbb:bbbb:8:: dev s-n1 proto bgp metric 1024 onlink pref medium
```

Note the two routes share `nhid 13`: the inherited entry is
byte-identical to the covering route's nexthop, so the kernel nexthop
group is reused. The resolution is tracked — if the BGP route moves or
disappears, the static follows or is withdrawn. And it forwards:

``` shell
$ sudo ip netns exec e1 ping 3001:db8::2
3 packets transmitted, 3 received, 0% packet loss
```

(BGP routes inherit the same way — a BGP next-hop covered by an SRv6
service route produces `proto bgp … encap seg6` entries; see the
`bgp_srv6_nht` BDD feature for that variant.) Clean up: delete the
`3001:db8::2/128` statics on `s` and `d`, and drop the address from
`e2`'s loopback.

## TI-LFA: the whole repair in one carrier

``` shell
s>configure
s#set router isis fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
L2 *> 2001:db8::8/128 [115/12] via fe80::4471:d5ff:fe05:192e, s-n1, 00:00:00
   *?                 [115/13] via seg6 [fcbb:bbbb:5:e003:e000::], s-n2, 00:00:00
```

Compare with the classic lab's backup for the same destination:

```
classic:  via seg6 [fcbb:bbbb:5::, fcbb:bbbb:5:e003::, fcbb:bbbb:6:e002::]
uSID:     via seg6 [fcbb:bbbb:5:e003:e000::]
```

The same three repair instructions — reach `r1`, cross `r1->r2`, cross
`r2->r3` — pack into a single carrier: block `fcbb:bbbb`, then the
micro-instructions `0005` (uN of r1), `e003` (r1's uA toward r2), `e000`
(r2's uA toward r3, renumbered into the shifted space). Each hop consumes
its own 16 bits and forwards; when the carrier is spent, the SRH advances
to its final segment — the original destination, exactly as in the
classic lab (H.Insert keeps it as segment [0]).

## Force the backup to become primary, and look at the wire

``` shell
s>configure
s#set router isis fast-reroute backup-as-primary
s#commit
s#exit
s>show ipv6 route
...
L2 *> 2001:db8::8/128 [115/12] via seg6 [fcbb:bbbb:5:e003:e000::], s-n2, 00:00:05
   *?                 [115/13] via fe80::4471:d5ff:fe05:192e, s-n1, 00:00:05
...
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n2, 00:01:31
```

(The BGP End.DT6 service route follows the promoted locator underneath,
exactly as in the classic lab.)

``` shell
n2>tcpdump -nli n2-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n2-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:23:45.360700 IP6 2001:db8:0:2::1 > fcbb:bbbb:5:e003:e000::: RT6 (len=4, type=4, segleft=1, last-entry=1, tag=0, [0]2001:db8::8, [1]fcbb:bbbb:5:e003:e000::) ICMP6, echo request, id 27686, seq 8, length 64
```

The inserted SRH is `len=4, segleft=1` — **two entries** (the carrier and
the original destination), versus the classic lab's `len=8, segleft=3`
four-entry header. Half the header for the same repair; that is the uSID
value proposition on one line of tcpdump.

The protected BGP service traffic stacks the same way — repair carrier
over service SID over host packet, with the repair SRH shrunk to two
entries:

``` shell
10:23:46.581677 IP6 2001:db8:0:1::1 > fcbb:bbbb:5:e003:e000::: RT6 (len=4, type=4, segleft=1, last-entry=1, tag=0, [0]fcbb:bbbb:8:40::, [1]fcbb:bbbb:5:e003:e000::) RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 27687, seq 11, length 64
```

## Everything else

...is the classic lab, unchanged: the topology and appendix tables, the
BGP IPv6-unicast service with End.DT6 SIDs (`fcbb:bbbb:X:40::` — carved
from the same uSID locators), the edge hosts with plain default routes,
and the walkthrough commands. See the
[classic README](../isis-srv6-classic/README.md) for the full narrative;
run this lab side by side (one at a time) to compare the SID tables,
repair lists, and SRH sizes.
