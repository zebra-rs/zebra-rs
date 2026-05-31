# OSPF BFD

OSPFv2 and OSPFv3 attach a [BFD](ch-10-00-bfd.md) session to each
neighbour on an interface so a forwarding-path failure tears the
adjacency down in sub-second time instead of waiting for the OSPF dead
interval. On a BFD `Down` event the neighbour is brought down through
the same path as a dead-timer expiry (RFC 5882 §5), which re-runs SPF.

See the [BFD overview](ch-10-00-bfd.md) for the session model and the
`show bfd` commands. OSPF neighbours are on a shared link, so their BFD
sessions are **always single-hop** (UDP 3784, GTSM = 255) — there is no
multi-hop knob.

## Enabling BFD on an interface

BFD is a flat block under the OSPF interface. The same configuration
applies to OSPFv2 (`router ospf`) and OSPFv3 (`router ospfv3`):

```
router ospf {
  area 0 {
    interface eth0 {
      bfd { enable true; }
    }
  }
}
```

No top-level `bfd { }` block is required — the BFD subsystem starts
automatically with `router ospf` / `router ospfv3`.

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enable` | boolean | `false` | Attach (or detach) BFD for neighbours on this interface. |
| `min-neighbor-state` | `two-way` \| `full` | `two-way` | Neighbour state at which the session starts / stops. |
| `profile` | string | — | Named `/bfd/profile` to apply. *Stored but not yet applied — see the overview.* |

## The `min-neighbor-state` trigger

This is the one OSPF-specific knob, and the two major implementations
disagree on its default — so zebra-rs makes it configurable:

- **`two-way`** (default) — start the session once the neighbour
  reaches the 2-Way state. This is **FRR's** behaviour, and it also
  protects DR-Other ↔ DR-Other pairs on a broadcast LAN (which never
  progress past 2-Way).
- **`full`** — start the session only at the Full state. This is
  **Cisco / IOS-XR's** behaviour, which on a broadcast LAN runs BFD
  only between a router and the DR/BDR.

On a point-to-point link the distinction is moot — the neighbour goes
straight to Full, so it is ≥ 2-Way either way.

```
router ospf {
  area 0 {
    interface eth0 {
      bfd {
        enable true;
        min-neighbor-state full;   // Cisco-style; default is two-way
      }
    }
  }
}
```

## OSPFv3 (IPv6)

OSPFv3 BFD is configured identically under `router ospfv3`. The session
runs over the interface's IPv6 **link-local** addresses (the same
addresses OSPFv3 sources its control packets from) and is demultiplexed
per interface, so overlapping `fe80::` addresses on different links do
not collide.

## Verifying

```
show bfd
show bfd peer <neighbor-address>
```

If a session stays `Down` with a remote discriminator of `0x0`, confirm
the neighbour also has `bfd enable` on its side and that UDP 3784 is not
filtered on the link. See the
[overview](ch-10-00-bfd.md#verifying-sessions) for the full command set.
