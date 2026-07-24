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
      bfd { enabled true; }
    }
  }
}
```

There is no global top-level `bfd { }` block — the BFD subsystem starts
automatically with `router ospf` / `router ospfv3`.

The same `bfd {}` leaves can also be set once at the **instance level**
(`router ospf { bfd {} }`) as a default for every interface; a per-interface
`bfd {}` then overrides it *per leaf* (see
[Instance-level defaults](#instance-level-defaults)).

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `false` | Attach (or detach) BFD for neighbours on this interface. |
| `min-neighbor-state` | `two-way` \| `full` | `two-way` | Neighbour state at which the session starts / stops. |
| `echo-mode` | `transmit` \| `receive` \| `both` | _(off)_ | Enable the [BFD Echo function](ch-10-00-bfd.md#echo-function) on this interface's sessions (IPv4 on OSPFv2, IPv6 on OSPFv3), choosing which half is active. |
| `echo-transmit-interval` | uint (ms) | `50` | Rate we originate Echo at (`transmit` / `both`). |
| `echo-receive-interval` | uint (ms) | `50` | Advertised Required Min Echo RX (`receive` / `both`). |
| `detect-offload` | boolean | `false` | [Offload expiration detection](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload) to the in-kernel (XDP) watchdog once the session is Up. |

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
        enabled true;
        min-neighbor-state full;   // Cisco-style; default is two-way
      }
    }
  }
}
```

## Echo

`echo-mode` turns on the [BFD Echo function](ch-10-00-bfd.md#echo-function) for
this interface's sessions — single-hop only, both address families: IPv4 on
OSPFv2, and on OSPFv3 the Echo session runs over the same IPv6 link-local pair
as the control session. The two halves are independent (RFC 5880 §6.4), backed
by the [eBPF data plane](ch-16-00-ebpf.md), whose XDP program handles IPv4 and
IPv6 frames alike:

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
        enabled true;
        echo-mode both;
        echo-transmit-interval 50;   // ms; rate we send Echo (default 50)
        echo-receive-interval 50;    // ms; advertised RX floor (default 50)
      }
    }
  }
}
```

A forwarding-path fault is then caught in sub-second time independent of the
OSPF Hello/Dead timers. The engine needs `cap_net_admin,cap_bpf,cap_net_raw`
and a kernel with XDP + `bpf_timer` support; if it can't run, the session
stays up on control packets and advertises echo-rx `0`. `show bfd peers` shows
the negotiated `Echo receive interval` / `Echo transmission interval`.

## Offloading expiration detection

`detect-offload true` moves the RFC 5880 §6.8.4 detection timer — the
clock that drives the session `Down` when the neighbour's control
packets stop arriving — into the kernel, via the same
[eBPF data plane](ch-16-00-ebpf.md) that backs Echo. The XDP program re-arms a
per-session `bpf_timer` on every arriving control packet and the expiry
fires in softirq, so detection neither false-fires because the daemon
was busy (packets queued but unprocessed) nor waits on its event loop.
The daemon still processes every packet normally; only the liveness
timing is offloaded. See
[the overview](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload)
for the mechanism and guard-rails.

```
router ospf {
  area 0 {
    interface eth0 {
      bfd {
        enabled true;
        detect-offload true;   // expiration detection in kernel/XDP
      }
    }
  }
}
```

The watchdog arms when the session reaches `Up` (and the helper is
confirmed running) and disarms when it leaves `Up`; the ordinary
userspace timer keeps running as a stretched backstop and takes over
again if the helper dies. Works for both OSPFv2 and OSPFv3 (the
sessions are single-hop, which is the offload's scope). Unlike Echo,
it sends nothing on the wire — it only times what already arrives.

`show bfd peers` confirms where detection runs:

```
    Detection timeout: 900ms
    Detection runs in: kernel/XDP (900ms)
```

## Instance-level defaults

A `bfd {}` block directly under `router ospf` / `router ospfv3` supplies
defaults for **every** interface in the instance. Each leaf is the same as the
per-interface block, and the effective value for an interface is its own
setting if present, otherwise the instance default, otherwise the hard default.

`enabled true` at the instance level **blanket-enables** BFD on all of the
instance's interfaces; a per-interface `bfd { enabled false }` opts one out.

```
router ospf {
  bfd {
    enabled true;            // BFD on every interface…
    echo-mode receive;      // …default Echo role: reflect only
    echo-receive-interval 50;
  }
  area 0 {
    interface eth0 {
      bfd { echo-mode both; }   // eth0 also originates; inherits enable + interval
    }
    interface eth1 {
      bfd { enabled false; }     // opt eth1 out of the blanket enable
    }
  }
}
```

## OSPFv3 (IPv6)

OSPFv3 BFD is configured identically under `router ospfv3`. The session
runs over the interface's IPv6 **link-local** addresses (the same
addresses OSPFv3 sources its control packets from) and is demultiplexed
per interface, so overlapping `fe80::` addresses on different links do
not collide. The full leaf set applies: `echo-mode` runs IPv6 Echo over
the same link-local pair, and `detect-offload` arms the in-kernel
watchdog for the IPv6 control packets just as it does for IPv4.

## Verifying

```
show bfd
show bfd peers <neighbor-address>
```

If a session stays `Down` with a remote discriminator of `0x0`, confirm
the neighbour also has `bfd enabled` on its side and that UDP 3784 is not
filtered on the link. See the
[overview](ch-10-00-bfd.md#verifying-sessions) for the full command set.
