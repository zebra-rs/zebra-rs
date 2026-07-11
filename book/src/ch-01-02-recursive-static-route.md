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
gateway learned from OSPF, IS-IS, or BGP works the same way. When the
gateway sits behind an SR-MPLS underlay (an IS-IS route carrying a
prefix-SID, say), the resolution also inherits the underlay's
transport label stack, so the static route forwards through the
labeled path rather than as a plain IP hop.

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
