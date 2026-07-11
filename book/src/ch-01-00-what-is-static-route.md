# Static Route

A static route is a type of routing configuration where the network path between
a source and a destination is manually defined by a network administrator.
Unlike dynamic routing protocols, which automatically adjust routes based on
changing network conditions, static routes are manually configured and remain
fixed until the network administrator makes a change.

The key characteristics of static routes are:

1. Manual Configuration: The network administrator manually defines the next-hop
   router or interface to reach a specific destination network. This is done
   through the configuration interface of a router or network device.

2. Fixed Routing: Once configured, the static route does not automatically
   adjust to changes in the network topology. The path remains fixed until the
   administrator updates the static route.

3. Simplicity: Static routes are simple to configure and maintain, making them
   suitable for small, stable networks where the network topology is well-known
   and unlikely to change frequently.

4. Limited Scalability: As the network grows in size and complexity, managing a
   large number of static routes can become cumbersome and error-prone. Dynamic
   routing protocols are better suited for larger, more complex networks.

5. Reliability: Static routes can provide a reliable and predictable routing
   path, as long as the configured next-hop router or interface remains
   available and the network topology does not change.

## Configuration model

Static routes live under the top-level `router static` block, split by
address family. Each `route` entry is keyed by its destination prefix
and carries one or more `nexthop` entries plus optional route-level
attributes:

```
router static {
  ipv4 {
    route <prefix> {
      nexthop <address | blackhole> {
        metric <metric>;        # per-nexthop metric (primary/backup)
        weight <1-255>;         # ECMP weight
        label <label> ...;      # MPLS labels to push
      }
      distance <1-255>;         # administrative distance (default 1)
      metric <metric>;          # route metric
    }
  }
  ipv6 {
    route <prefix> {
      ...                       # same shape, IPv6 addresses
    }
  }
}
```

Points worth knowing:

- A bare `route <prefix>` with no nexthop carries no forwarding
  information and is rejected at commit — every route needs at least
  one `nexthop` (an IP address, or the `blackhole` keyword — see
  [Blackhole (Discard) Static Route](ch-01-03-blackhole-static-route.md)).
- Configuring several nexthops on one route gives ECMP; unequal
  `weight` values give weighted (UCMP) load-sharing, and unequal
  per-nexthop `metric` values give a primary/backup pair — see
  [Floating Static Route](ch-01-01-floating-static-route.md).
- The default administrative distance for a static route is **1**, so
  a static route normally wins over any dynamic protocol. Raise it
  with the `distance` leaf to make the static route a fallback.
- The nexthop does not need to be on a directly connected subnet —
  zebra-rs resolves it through the routing table automatically; see
  [Recursive Static Route](ch-01-02-recursive-static-route.md).
- Per-VRF static routes use the same shape nested under
  `router static vrf <name> { ... }` and install into that VRF's
  kernel routing table.
- IPv6 routes additionally accept SRv6 attributes (`segments`,
  `encap-type`, seg6local `action`, …); see the
  [SRv6 chapter](ch-04-00-srv6.md).

## Example

Suppose you have a small office network with the following setup:

The main office has a router (Router A) with the IP address 192.168.1.1 on the
local network. There is a remote branch office that needs to be accessed from
the main office network. The remote branch office has a router (Router B) with
the IP address 10.0.0.1 on its local network. The network between the main
office and the remote branch office is a wide-area network (WAN) with the IP
subnet 172.16.0.0/24.

On Router A, you would configure a static route for the remote branch
office network, 10.0.0.0/24:

```
interface eth0 {
  ipv4 {
    address 172.16.0.1/24;
  }
}
interface eth1 {
  ipv4 {
    address 192.168.1.1/24;
  }
}
router static {
  ipv4 {
    route 10.0.0.0/24 {
      nexthop 172.16.0.2;
    }
  }
}
```

In the CLI the same route is one `set` command from configure mode,
followed by `commit`:

```
set router static ipv4 route 10.0.0.0/24 nexthop 172.16.0.2
```

This tells Router A that to reach the 10.0.0.0/24 network, it should
forward the traffic to the next-hop router at 172.16.0.2, which is the WAN
interface of Router B. On Router B, you would configure the mirror-image
static route for the main office network, 192.168.1.0/24:

```
interface eth0 {
  ipv4 {
    address 172.16.0.2/24;
  }
}
interface eth1 {
  ipv4 {
    address 10.0.0.1/24;
  }
}
router static {
  ipv4 {
    route 192.168.1.0/24 {
      nexthop 172.16.0.1;
    }
  }
}
```

This tells Router B that to reach the 192.168.1.0/24 network, it should forward
the traffic to the next-hop router at 172.16.0.1, which is the WAN interface of
Router A. Now, when a device on the main office network (192.168.1.0/24) needs
to communicate with a device on the remote branch office network (10.0.0.0/24),
the traffic will be forwarded to Router A, which will then use the static route
to send the traffic to Router B, and vice versa.

IPv6 static routes follow exactly the same shape under the `ipv6`
container:

```
router static {
  ipv6 {
    route 2001:db8:100::/48 {
      nexthop 2001:db8:1::2;
    }
  }
}
```

## ECMP

A route with several nexthops at the same metric load-balances across
them. The optional `weight` leaf makes the split unequal (UCMP):

```
router static {
  ipv4 {
    route 10.0.0.0/24 {
      nexthop 172.16.0.2 {
        weight 2;
      }
      nexthop 172.16.1.2 {
        weight 1;
      }
    }
  }
}
```

## Verifying

Installed static routes appear in `show ip route` (or
`show ipv6 route`) with the `S` marker, and can be looked up
individually:

```
show ip route 10.0.0.0/24
```
