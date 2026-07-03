# Minimum Working Example

OSPFv3 configuration lives under `router ospfv3` and uses the same
`area { interface }` hierarchy as OSPFv2: an interface participates
if and only if it appears under some area with `enable true`. The
smallest useful topology is two routers on a point-to-point link.

R1:
```
interface enp0s6 {
  ipv6 address 2001:db8:12::1/64;
}
router ospfv3 {
  router-id 10.0.0.1;
  area 0 {
    interface lo {
      enable true;
    }
    interface enp0s6 {
      enable true;
      network-type point-to-point;
    }
  }
}
```

R2:
```
interface enp0s6 {
  ipv6 address 2001:db8:12::2/64;
}
router ospfv3 {
  router-id 10.0.0.2;
  area 0 {
    interface lo {
      enable true;
    }
    interface enp0s6 {
      enable true;
      network-type point-to-point;
    }
  }
}
```

Hellos are sourced from the interface's IPv6 **link-local** address
— an interface with no `fe80::` address yet sends nothing — and all
protocol exchanges run over link-local unicast/multicast. The
global addresses configured above are not used for the adjacency;
they are what gets *advertised* (each enabled interface's global
prefixes enter the Intra-Area-Prefix-LSA, loopbacks at metric 0).

With matching default Hello/Dead intervals (10/40 s), the adjacency
reaches Full within roughly two hello cycles:

```
show ospfv3 neighbor
Router-ID        Iface      State      DR
10.0.0.2         enp0s6     Full       0.0.0.0
```

Note the v3 neighbor table shows the NFSM state and the DR as
separate columns (there is no combined `Full/DR` notation as in
v2), and on point-to-point links no DR is elected. `show ospfv3
route` lists the learned prefixes as `<prefix> metric <n> via …`,
and `show ospfv3 database` shows the Router, Link, and
Intra-Area-Prefix LSAs of both routers.

## Router ID

| YANG leaf | Type | Notes |
|---|---|---|
| `/router/ospfv3/router-id` | `inet:ipv4-address` | Optional; wins over the RIB-distributed value, then the constructor default `10.0.0.1`. |
| `/router/ospfv3/vrf/<name>/router-id` | `inet:ipv4-address` | Per-VRF instance override. |

The Router ID remains a 32-bit dotted-quad value even in an
IPv6-only network. **Set it explicitly on every router**: two OSPFv3
routers sharing a Router ID form no adjacency, and in an IPv6-only
deployment there may be no IPv4 address from which the RIB can
derive a unique fallback — both routers would sit on the default
`10.0.0.1`. Changing the Router ID on a live instance is supported:
the instance re-originates under the new ID and flushes the LSAs
advertised under the old one, so the neighbor's database follows
without waiting for MaxAge.

There is no `instance-id` configuration: zebra-rs always runs
Instance ID 0 (the RFC 5340 §A.3.1 default), one OSPFv3 instance
per link.
