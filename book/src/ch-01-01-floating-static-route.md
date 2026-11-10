# Floating Static Route

Floating static routes, also known as backup static routes, provide an
alternative path for network traffic in the event of a primary route
failure. The route is considered "floating" because it is deliberately
made *less preferred* than the primary path, so it carries traffic only
when the primary becomes unavailable.

zebra-rs expresses this in two ways, depending on what the backup is
backing up:

1. **Backing up a dynamic protocol route** — raise the static route's
   *administrative distance* above the protocol's.
2. **Backing up another static path to the same prefix** — give one
   route two nexthops with different *per-nexthop metrics*.

## Floating above a dynamic protocol (distance)

The `distance` leaf sets the route's administrative distance. The RIB
selects the entry with the lowest distance for each prefix, so the
distance decides which *protocol* wins. A static route defaults to
distance **1**, which beats every dynamic protocol — to turn it into a
backup, raise its distance above the protocol's default:

| Protocol | Default distance |
|---|---|
| Static | 1 |
| OSPF | 110 |
| IS-IS | 115 |
| BGP | 200 |

For example, a default route normally learned from the IGP, with a
static escape hatch toward a fallback gateway that only takes over when
the IGP route disappears:

```
router static {
  ipv4 {
    route 0.0.0.0/0 {
      distance 250;
      nexthop 10.0.0.254;
    }
  }
}
```

While OSPF holds a default route (distance 110), the static route at
distance 250 stays unselected. When the OSPF route is withdrawn, the
floating static is installed into the kernel FIB; when the OSPF route
returns, it preempts the static again.

## Floating between two static nexthops (per-nexthop metric)

The `route` list is keyed by the destination prefix, so the classic
"configure the same prefix twice at two distances" pattern from other
CLIs does not apply — there is exactly one static `route` entry per
prefix. Instead, the primary and backup paths are two `nexthop`
entries of that one route, distinguished by per-nexthop `metric`.

Consider a router with two uplinks: the primary ISP on eth0 and a
backup ISP on eth1.

```
interface eth0 {
  ipv4 {
    address 192.168.1.1/24;
  }
}
interface eth1 {
  ipv4 {
    address 10.0.0.1/24;
  }
}
router static {
  ipv4 {
    route 0.0.0.0/0 {
      nexthop 192.168.1.254 {
        metric 100;
      }
      nexthop 10.0.0.254 {
        metric 200;
      }
    }
  }
}
```

zebra-rs installs each nexthop as its own kernel route at its own
metric:

```
$ ip route show
default via 192.168.1.254 dev eth0 proto zebra metric 100
default via 10.0.0.254 dev eth1 proto zebra metric 200
```

The kernel forwards along the lowest-metric route, so traffic uses the
primary ISP while it is healthy. zebra-rs tracks each nexthop's
resolvability: when eth0 goes down (or 192.168.1.254 otherwise becomes
unreachable), the metric-100 route is withdrawn from the FIB and the
metric-200 route carries the traffic. When the primary link recovers,
its route is reinstalled and preempts the backup automatically.

`show ip route` marks each nexthop on its own: `*` on the lines whose
route is in the kernel, and `?` on the backups. With the primary down
the route is still selected (`>`), and only the backup is installed:

```
S   > 0.0.0.0/0 [1/100] via 192.168.1.254, eth0, 00:10:12
   *?           [1/200] via 10.0.0.254, eth1, 00:10:12
```

The same holds for a backup that cannot be reached, at commit time or
later: the primary is installed and marked, the backup is not, and it
joins the kernel when its gateway becomes reachable.

Nexthops that share the *same* metric load-balance as ECMP instead —
metrics separate failover tiers, weights shape the split within a tier
(see the ECMP section of the [Static Route](ch-01-00-what-is-static-route.md)
chapter).

### IPv6: a nexthop at metric 0

A nexthop without a `metric` has metric 0, and is the primary. IPv6 has
no kernel priority 0, though: Linux installs a route sent without one at
1024. For a static route with a single nexthop that is only the number
`ip -6 route` shows. Between the nexthops of a floating route it would
be the wrong order, the primary behind a backup at metric 10, so there
zebra-rs installs the nexthop at metric 0 at priority 1:

```
router static {
  ipv6 {
    route 2001:db8:113::/48 {
      nexthop 2001:db8:a::1;
      nexthop 2001:db8:b::1 {
        metric 10;
      }
    }
  }
}
```

```
$ ip -6 route show 2001:db8:113::/48
2001:db8:113::/48 via 2001:db8:a::1 dev eth0 proto zebra metric 1 pref medium
2001:db8:113::/48 via 2001:db8:b::1 dev eth1 proto zebra metric 10 pref medium
```

`show ipv6 route` shows the configured metrics, `[1/0]` and `[1/10]`.
A nexthop configured at metric 1 beside one at 0 moves up to priority 2
in turn, and so on: the kernel's order is always the configured one.
IPv4 has a priority 0 and installs every metric as it is.
