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
| `echo-mode` | `transmit` \| `receive` \| `both` | _(off)_ | Enable the [BFD Echo function](ch-10-00-bfd.md#echo-function) on this interface's single-hop IPv4 sessions, choosing which half is active. |
| `echo-transmit-interval` | uint (ms) | `50` | Rate we originate Echo at (`transmit` / `both`). |
| `echo-receive-interval` | uint (ms) | `50` | Advertised Required Min Echo RX (`receive` / `both`). |

Sessions use the BFD defaults (300 ms / ×3 ⇒ ~900 ms detection); the
timers are not currently tunable — see
[Tuning intervals](ch-10-00-bfd.md#tuning-intervals) in the overview.

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

## Echo

`echo-mode` turns on the [BFD Echo function](ch-10-00-bfd.md#echo-function) for
this interface's sessions — single-hop IPv4 only (OSPFv2; on OSPFv3 the leaf is
accepted but inert, since Echo has no IPv6 form here). The two halves are
independent (RFC 5880 §6.4), backed by the per-interface `xdp-bfd-echo` helper:

- **`receive`** — advertise a non-zero Required Min Echo RX and loop the peer's
  Echo back (the *peer* gets fast detection).
- **`transmit`** — originate our own Echo (the peer's forwarding plane loops it
  back) and drive the session Down if it stops returning; we advertise `0`, so
  we don't promise to loop the *peer's* Echo.
- **`both`** — both halves.

```
router ospf {
  area 0 {
    interface eth0 {
      bfd {
        enable true;
        echo-mode both;
        echo-transmit-interval 50;   // ms; rate we send Echo (default 50)
        echo-receive-interval 50;    // ms; advertised RX floor (default 50)
      }
    }
  }
}
```

A forwarding-path fault is then caught in sub-second time independent of the
OSPF Hello/Dead timers. The helper needs `cap_net_admin,cap_bpf,cap_net_raw`
and a kernel with XDP + `bpf_timer` support; if it can't start, the session
stays up on control packets and advertises echo-rx `0`. `show bfd peers` shows
the negotiated `Echo receive interval` / `Echo transmission interval`.

> A protocol-level `router ospf { bfd {} }` default block (inherited and
> overridden per interface) is planned; today `echo-mode` is set per interface.

## OSPFv3 (IPv6)

OSPFv3 BFD is configured identically under `router ospfv3`. The session
runs over the interface's IPv6 **link-local** addresses (the same
addresses OSPFv3 sources its control packets from) and is demultiplexed
per interface, so overlapping `fe80::` addresses on different links do
not collide.

## Verifying

```
show bfd
show bfd peers <neighbor-address>
```

If a session stays `Down` with a remote discriminator of `0x0`, confirm
the neighbour also has `bfd enable` on its side and that UDP 3784 is not
filtered on the link. See the
[overview](ch-10-00-bfd.md#verifying-sessions) for the full command set.
