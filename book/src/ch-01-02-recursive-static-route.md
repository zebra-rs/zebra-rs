# Recursive Static Route

A recursive static route is a static route whose next-hop address is
not on a directly connected subnet. The configured gateway is instead
*resolved through the routing table*: zebra-rs looks the gateway up in
the RIB, finds the route that covers it, and installs the static route
with that covering route's actual on-link nexthop and egress
interface.

In zebra-rs recursion is automatic — there is no `recursive` knob to
enable. Every static nexthop is resolved through the RIB at
FIB-install time (the same next-hop tracking machinery the routing
protocols use), whether the gateway is one hop away or several.

## Example

The router below reaches the remote network 172.16.0.0/16 via the
gateway 10.1.1.1, but 10.1.1.1 is itself not directly connected — it
is reachable through the on-link router 10.0.0.254:

```
interface eth0 {
  ipv4 {
    address 10.0.0.1/24;
  }
}
router static {
  ipv4 {
    route 10.1.1.1/32 {
      nexthop 10.0.0.254;
    }
    route 172.16.0.0/16 {
      nexthop 10.1.1.1;
    }
  }
}
```

When the route to 172.16.0.0/16 is committed, zebra-rs resolves its
gateway 10.1.1.1 through the RIB: the lookup matches the
10.1.1.1/32 route, whose nexthop 10.0.0.254 is on-link on eth0. The
recursive route is installed into the kernel already flattened to the
resolved adjacency:

```
$ ip route show
10.1.1.1 via 10.0.0.254 dev eth0 proto static
172.16.0.0/16 via 10.0.0.254 dev eth0 proto static
```

The resolving route does not have to be another static route — a
gateway learned from OSPF, IS-IS, or BGP works the same way.

## Resolution over an SR-MPLS underlay

When the gateway sits behind an SR-MPLS underlay, resolution inherits
more than the egress: the static route also picks up the covering
route's **transport label stack**, so its traffic is label-switched
through the core rather than forwarded as a plain IP hop.

The [`playset/isis-srmpls`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-srmpls)
lab is a runnable demonstration (`./up.sh` and walk through its
README). Its ingress node `s` runs IS-IS with `segment-routing mpls`
and carries exactly one piece of static configuration — a route to the
far edge subnet `172.16.1.0/24` (host `e2`, behind node `d`, not part
of IS-IS at all) via `d`'s loopback:

```yaml
router:
  static:
    ipv4:
      route:
      - prefix: 172.16.1.0/24
        nexthop:
        - address: 10.0.0.8
```

`10.0.0.8` is not on any of `s`'s connected subnets. NHT resolves it
through the IS-IS SR-MPLS route to `10.0.0.8/32`, which carries `d`'s
Prefix-SID label:

```
s>show ip route
...
L2 *> 10.0.0.8/32 [115/12] via 192.168.0.2, s-n1, label 16800, 00:00:43
S  *> 172.16.1.0/24 [1/0] via 10.0.0.8 (recursive), 00:00:50
                          via 192.168.0.2, s-n1, label 16800
```

The static route displays as the recursive two-liner — the configured
gateway marked `(recursive)`, and underneath it the resolved nexthop
with the **inherited label** `16800`. The kernel route carries the
matching `encap mpls 16800` push, so traffic to the edge subnet is
label-switched all the way to `d`.

Because the resolution re-runs whenever the covering route changes,
the static route follows the underlay through IGP reconvergence — the
playset walks this further: with TI-LFA enabled, promoting the
repair path (`fast-reroute backup-as-primary`) moves the static route
onto the full repair label stack with no configuration change.

## Recursive resolution and SRv6

The label inheritance above is an SR-MPLS behavior. Over an **SRv6**
underlay, recursive resolution still works — the gateway is resolved
and the route installs with the flattened plain-IPv6 nexthop — but the
resolution does **not** inherit any SRv6 encapsulation from the
covering route. When the destination prefix is unknown to the core
(the usual reason for tunneling), a recursive static route alone will
not deliver the traffic; steer it into an SRv6 encapsulation
explicitly with the `segments` leaf instead — see
[SRv6 Static Routes](ch-01-04-srv6-static-route.md).

## Tracking topology changes

Resolution is not a one-shot operation. zebra-rs re-resolves static
nexthops whenever the underlying routes change:

- If the route covering the gateway moves to a different path (a link
  fails and the IGP reconverges), the static route is reinstalled with
  the new egress.
- If the gateway becomes unreachable — no route covers it anymore —
  the static route is withdrawn from the kernel FIB until the gateway
  resolves again.

This is what makes recursive static routes useful: you can pin *what*
the traffic should reach (the remote prefix and its logical gateway)
while leaving *how to get to the gateway* to the rest of the routing
table. A single recursive route toward an intermediate router replaces
per-destination routes, and it adapts to topology changes underneath
it without any configuration change.

Verify the resolution with a scoped lookup:

```
show ip route 172.16.0.0/16
```
