# SRv6 Static Routes

Static routes can both *steer traffic into* an SRv6 encapsulation
(ingress) and *terminate* SRv6 traffic with a local endpoint behavior
(egress). Together the two sides build a complete SRv6 path out of
nothing but static configuration — no BGP or IGP signaling of the
service prefix required.

On the ingress side, the IPv6 `route` entry takes a `segments`
segment list instead of a nexthop:

```
router static {
  ipv6 {
    route <prefix> {
      segments <sid> [<sid> ...];   # H.Encap segment list
      encap-type H.Encap.Red;       # optional; default H.Encap
    }
  }
}
```

On the egress side, a `route` entry whose prefix *is the SID* takes an
`action` — the seg6local endpoint behavior installed for that SID:

```
router static {
  ipv6 {
    route <sid>/128 {
      action End.DT6;     # End | uN | End.DT4/DT6/DT46 | End.DX4/DX6 | End.X | uA
      vrf <name>;         # for End.DT*: VRF table for the inner lookup
      nh6 <address>;      # for End.DX6 / End.X / uA: cross-connect adjacency
      nh4 <address>;      # for End.DX4
    }
  }
}
```

`End.DT4` / `End.DT6` / `End.DT46` decapsulate the outer IPv6 header
and look the inner packet up in the VRF named by `vrf` — omit it to
look up in the default (main) table. The `End.DX*` cross-connect
variants forward the decapsulated packet straight to the `nh6`/`nh4`
adjacency instead of doing a lookup (RFC 8986 §4.4/§4.5).

## Worked example

The walkthrough below runs on the
[`playset/isis-srv6-usid`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-srv6-usid)
lab (`./up.sh`): an IS-IS SRv6 core between ingress `s` (locator
`fcbb:bbbb:1::/48`) and egress `d` (locator `fcbb:bbbb:8::/48`), with
edge hosts `e1` (`2001:db8:100::/64` behind `s`) and `e2`
(`2001:db8:200::/64` behind `d`). In the lab those edge prefixes are
carried by BGP over SRv6; here we reach `e2`'s subnet with static
routes instead — the static route wins the RIB selection over BGP
(distance 1 vs 200), so the commands below can be applied to the
running lab as-is.

### Why recursion alone is not enough

A [recursive static route](ch-01-02-recursive-static-route.md) via
`d`'s loopback resolves fine over the SRv6 core:

```
s#set router static ipv6 route 2001:db8:200::/64 nexthop 2001:db8::8
s#commit
s#exit
s>show ipv6 route
...
S  *> 2001:db8:200::/64 [1/0] via 2001:db8::8 (recursive), 00:00:02
                              via fe80::f86f:61ff:fecf:b69a, s-n1
```

But the covering route here — the IGP route to `d`'s loopback — is a
*plain* IPv6 route, so there is no transport to inherit: the packet
leaves `s` unencapsulated, still addressed to its final destination.
The first core router has no route for that destination (only `s` and
`d` know the edge prefixes), so the traffic dies one hop in:

```
$ sudo ip netns exec e1 ping 2001:db8:200::100
...
3 packets transmitted, 0 received, 100% packet loss

n1$ ip -6 route get 2001:db8:200::100
RTNETLINK answers: Network is unreachable
```

To tunnel through a core that routes only on locators, the SRv6
encapsulation must be configured explicitly.

### Egress: pin a static End.DT6 SID on `d`

Give `d` a decapsulation endpoint at an operator-pinned SID under its
locator (the E064+ function range is reserved for exactly this — see
[SRv6 SID allocation](ch-04-00-srv6.md)):

```
d#set router static ipv6 route fcbb:bbbb:8:e064::/128 action End.DT6
d#commit
```

zebra-rs installs the SID as a kernel `seg6local` route on the `sr0`
dummy interface:

```
d>show ipv6 route
...
S  *> fcbb:bbbb:8:e064::/128 [1/0] is directly connected, sr0, seg6local End.DT6, 00:01:58

d$ ip -6 route show | grep e064
fcbb:bbbb:8:e064::  encap seg6local action End.DT6 table main dev sr0 proto static metric 1024 pref medium
```

Packets arriving for this SID are decapsulated and the inner IPv6
destination looked up in the main table — where `e2`'s subnet is a
connected route.

### Ingress: steer the prefix into the SID on `s`

Replace the plain-nexthop static with a `segments` route pointing at
the pinned SID:

```
s#delete router static ipv6 route 2001:db8:200::/64
s#set router static ipv6 route 2001:db8:200::/64 segments fcbb:bbbb:8:e064::
s#commit
s#exit
s>show ipv6 route
...
S  *> 2001:db8:200::/64 [1/0] via seg6 [fcbb:bbbb:8:e064::], s-n1, 00:00:02
```

The kernel route carries the H.Encap:

```
s$ ip -6 route show | grep 2001:db8:200
2001:db8:200::/64 nhid 14  encap seg6 mode encap segs 1 [ fcbb:bbbb:8:e064:: ] via fcbb:bbbb:8:e064:: dev s-n1 proto static metric 1024 onlink pref medium
```

Note the `via fcbb:bbbb:8:e064:: dev s-n1`: the *first segment* is
itself resolved recursively — the SID is covered by the IS-IS route to
`d`'s locator `fcbb:bbbb:8::/48`, and the encapsulated packet follows
whatever path the IGP currently has for it. The core never sees the
inner destination, only the locator.

### End-to-end

```
$ sudo ip netns exec e1 ping 2001:db8:200::100
...
3 packets transmitted, 3 received, 0% packet loss
```

Capturing on core node `n1` shows the outer IPv6 header addressed to
the SID, the SRH, and the untouched inner packet:

```
n1>tcpdump -li n1-s ip6 dst net fcbb:bbbb:8::/48
11:14:17.317221 IP6 2001:db8:0:1::1 > fcbb:bbbb:8:e064::: RT6 (len=2, type=4, segleft=0,
  last-entry=0, tag=0, [0]fcbb:bbbb:8:e064::) IP6 2001:db8:100::100 > 2001:db8:200::100:
  ICMP6, echo request, id 59564, seq 1, length 64
```

`d` decapsulates at the static End.DT6 SID and delivers the inner
packet to `e2`. The reverse direction can be built the same way — a
static End.DT6 SID on `s` and a `segments` route on `d` (in the lab,
the return path is already covered by BGP over SRv6).

## Inheriting segments from a covering SRv6 route

Explicit `segments` are only needed when nothing in the routing table
carries the encapsulation already. When the static route's gateway is
itself covered by an **SRv6-encapsulated route** — a BGP-over-SRv6
service route learned with `encapsulation-type srv6` — recursive
resolution inherits that route's segment list, exactly the way an
SR-MPLS covering route donates its label stack.

Consider an ingress router that learned `2001:db8:cafe::/64` from BGP
over SRv6 (installed as `via seg6 [fcbb:bbbb:1:40::]`, the egress PE's
End.DT6 SID), and a static route whose gateway lives inside that
prefix:

```
set router static ipv6 route 3001:db8::1/128 nexthop 2001:db8:cafe::1
```

The gateway is not on-link; NHT resolves it through the BGP route and
the static comes out carrying the inherited encapsulation:

```
z3>show ipv6 route 3001:db8::1/128
S  *> 3001:db8::1/128 [1/0] via 2001:db8:cafe::1 (recursive), 00:00:03
                            via seg6 [fcbb:bbbb:1:40::], i1

z3$ ip -6 route show 3001:db8::1
3001:db8::1 nhid 2  encap seg6 mode encap segs 1 [ fcbb:bbbb:1:40:: ] via fcbb:bbbb:1:: dev i1 proto static metric 1024 onlink pref medium
```

The kernel nexthop is shared with the covering BGP route (same
`nhid`) — the nexthop group dedupes on the segment list. Traffic to
the static prefix is encapsulated to the egress PE, decapsulated by
its End.DT6 SID, and routed onward there — so, as with recursive
SR-MPLS statics, the egress node must know the inner prefix. The
resolution is tracked: if the covering BGP route moves or is
withdrawn, the static is re-resolved or pulled from the FIB, and
deleting the static releases its shared seg6 nexthop group.

Two boundaries of the inheritance are worth knowing:

- Plain IGP-SRv6 routes (a remote loopback reachable natively) carry
  no encapsulation, so there is nothing to inherit — that is the
  explicit-`segments` case above.
- A resolution chain that would need *both* an MPLS label stack and an
  SRv6 segment list (mixed transport) does not resolve: a kernel
  nexthop carries at most one encapsulation, so the route is withheld
  rather than installed half-encapsulated.

The inheritance is not limited to static routes: a **BGP route** whose
next-hop is covered by an SRv6-encapsulated route inherits the segment
list the same way — the SRv6 analog of Inter-AS Option C, where
service routes ride a BGP-learned transport tunnel. A service node
behind the egress PE can peer iBGP with the ingress *through the
tunnel itself* and advertise service prefixes with its own address as
the next-hop; the ingress resolves that next-hop through the SRv6
transport route and installs the service routes as
`proto bgp … encap seg6` entries. (An MPLS-labelled route — LU or
VPN — refuses SRv6 transport instead: a label stack cannot ride a
seg6 encapsulation, so such a resolution withholds the route rather
than installing it half-encapsulated.)

The BDD features `static_srv6_nht` and `bgp_srv6_nht` run both
variants end to end: a three-router line where only the ingress and
egress speak BGP, the middle router knows nothing but locators, and
the ping to a node behind the egress succeeds only because the
inherited encapsulation tunnels the packet across the core.

## Notes

- With more than one segment, `segments <s1> <s2> ...` installs the
  full SRH; the default encapsulation is `H.Encap` (RFC 8986 §5.1),
  so the kernel carries every configured segment. Opt into the
  SRH-reduced form with `encap-type H.Encap.Red`.
- `segments` and `nexthop` are alternative forwarding models on the
  same route; when both are configured, the segment list wins.
- The `distance` and `metric` leaves work on SRv6-steered routes the
  same as on ordinary static routes, so an SRv6 path can also serve as
  a [floating backup](ch-01-01-floating-static-route.md).
- Static `segments` steering is IPv6-only today. IPv4 service
  prefixes ride SRv6 through the BGP machinery (L3VPN over SRv6 with
  `End.DT4`/`End.DT46` SIDs) rather than through static routes.
