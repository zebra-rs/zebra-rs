# Area Configuration

An OSPFv3 instance is organized exactly like an OSPFv2 one: a list
of areas, each carrying the interfaces that belong to it.

```
router ospfv3 {
  router-id 10.0.0.1;
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
    }
  }
}
```

The `area` list key is the same union of `uint32` and
`inet:ipv4-address` as in v2 — `area 1` and `area 0.0.0.1` normalize
to the same 32-bit area ID, and dotted-quad is the canonical
rendering in `show` output. The area an interface serves is implicit
from its parent list entry; re-homing an interface is a
delete-and-add across two list entries (see
[Moving an Interface Between Areas](ch-15-05-ospfv3-interface-area-move.md)).

Per-area knobs:

| YANG leaf (`/router/ospfv3/area/<id>/…`) | Purpose |
|---|---|
| `area-id` | List key — decimal or dotted-quad. |
| `area-type`, `no-summary`, `nssa-*` | Stub/NSSA machinery — see [Area Types](ch-15-03-ospfv3-area-types.md). |
| `redistribute/connected` | Per-NSSA-area Type-7 origination — see [Route Redistribution](ch-15-09-ospfv3-redistribution.md). |
| `interface/<n>/…` | Per-interface knobs — see [Per-Interface Configuration](ch-15-06-ospfv3-per-interface.md). |

Multi-area configurations form adjacencies and run per-area SPF
correctly (one Router-LSA per attached area), but note the current
ABR limitation for inter-area routing described in
[Multi-Area Topologies and the ABR](ch-15-04-ospfv3-multi-area-abr.md).

## Per-VRF instances

OSPFv3 can run per VRF: `router ospfv3 vrf <name>` opens an
independent instance with its own `router-id`, `redistribute bgp`,
and `area { interface }` tree (the interface subset: `enable`,
`network-type`, `priority`, the timers, and `mtu-ignore`).
Segment-routing, flex-algo, and fast-reroute are not available per
VRF today. Operational state is reachable via
`show ospfv3 vrf <name> [interface | neighbor | database | route]`.
