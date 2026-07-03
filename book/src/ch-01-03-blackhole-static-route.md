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
more specific route) are dropped by the kernel with an
`ICMP net unreachable` / `EACCES` locally, rather than being
forwarded along a default route or looping.

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
here.
