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
default via 192.168.1.254 dev eth0 proto static metric 100
default via 10.0.0.254 dev eth1 proto static metric 200
```

The kernel forwards along the lowest-metric route, so traffic uses the
primary ISP while it is healthy. zebra-rs tracks each nexthop's
resolvability: when eth0 goes down (or 192.168.1.254 otherwise becomes
unreachable), the metric-100 route is withdrawn from the FIB and the
metric-200 route carries the traffic. When the primary link recovers,
its route is reinstalled and preempts the backup automatically.

Nexthops that share the *same* metric load-balance as ECMP instead —
metrics separate failover tiers, weights shape the split within a tier
(see the ECMP section of the [Static Route](ch-01-00-what-is-static-route.md)
chapter).
