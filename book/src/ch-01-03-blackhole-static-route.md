# Blackhole (Discard) Static Route

A blackhole static route drops all traffic to a prefix in the
forwarding plane instead of forwarding it. The discard decision is
expressed as a nexthop keyword, `blackhole`, so a route configured
this way still satisfies the requirement that every static route
carry a nexthop:

```
router static {
  ipv4 {
    route 10.9.9.0/24 {
      nexthop blackhole;
    }
  }
  ipv6 {
    route 2001:db8:dead::/48 {
      nexthop blackhole;
    }
  }
}
```

The keyword sits at the nexthop-address position (the address key is
a union of an IP address and the `blackhole` enum), so
`nexthop blackhole` and `nexthop <address>` are alternatives at the
same point in the tree.

zebra-rs installs the route into the kernel FIB as an
`RTN_BLACKHOLE` entry with no gateway — `ip route show` renders it
as `blackhole 10.9.9.0/24`. Packets matching the prefix (and not a
more specific route) are dropped by the kernel without a word to
their sender, rather than being forwarded along a default route or
looping.

## Telling the sender: `nexthop unreachable`

`unreachable` is the second discard keyword. The packet is dropped
just the same, and its sender is answered with an ICMP Destination
Unreachable, so an application fails at once instead of waiting for
its own timeout:

```
router static {
  ipv4 {
    route 10.9.9.0/24 {
      nexthop unreachable;
    }
  }
  ipv6 {
    route 2001:db8:dead::/48 {
      nexthop unreachable;
    }
  }
}
```

The kernel route is an `RTN_UNREACHABLE` entry, which `ip route show`
renders as `unreachable 10.9.9.0/24`, and the show commands say which
kind a discard route is:

```
router> show ip route
S  *> 10.8.8.0/24 [1/0] is a discard (blackhole), 00:00:12
S  *> 10.9.9.0/24 [1/0] is a discard (unreachable), 00:00:12
```

What a host behind the router sees:

```
host$ ping -c 1 10.9.9.1
From 192.0.2.1 icmp_seq=1 Destination Host Unreachable

host$ ping -c 1 2001:db8:dead::1
From 2001:db8:1::1 icmp_seq=1 Destination unreachable: No route
```

| | `nexthop blackhole` | `nexthop unreachable` |
|---|---|---|
| The packet | dropped | dropped |
| The sender | hears nothing | ICMP Destination Unreachable |
| Use it for | traffic that deserves no answer (an attack sink) | your own unused address space, so that hosts fail fast |

- **One keyword per route.** A commit that leaves both on one route
  is refused. To change the kind, delete one and set the other in the
  same commit; the kernel route changes kind in place.
- Like `blackhole`, the keyword applies to the routes of a VRF
  (`router static vrf <name> ...`) as well, and the route's `metric`
  and `distance` apply to it.
- The router sends the ICMP error only when it forwards (IP forwarding
  is on), and the kernel limits how often it sends one.

## Why aggregate with a discard route

The common use is at an aggregation boundary. When a router
advertises a summary prefix (for example an OSPF `area range` or a
BGP aggregate) it originates one covering route for a block whose
components may be only partially populated. Without a discard route
for the aggregate, traffic to an *unpopulated* part of the block can
match the aggregator's own default and loop back. A blackhole route
for the aggregate prefix, less specific than every real component,
absorbs that traffic locally instead.

This makes the discard route the forwarding-plane companion to
summarization; the aggregate origination features consume the same
RIB `Nexthop::Blackhole` primitive that `nexthop blackhole` exposes
here. The DHCPv6 client holds a delegated prefix the same way, with
the `unreachable` kind
([DHCP client](ch-00-10-dhcp-client.md)).
