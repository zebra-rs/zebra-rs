# IS-IS BFD

IS-IS attaches a [BFD](ch-10-00-bfd.md) session to each adjacency on an
interface so a forwarding-path failure tears the adjacency down in
sub-second time instead of waiting for the IS-IS hold timer. On a BFD
`Down` event the adjacency is expired through the same path as a
hold-timer timeout (RFC 5882 §5), which re-runs SPF.

See the [BFD overview](ch-10-00-bfd.md) for the session model and the
`show bfd` commands. IS-IS adjacencies live on a shared link, so their
BFD sessions are **always single-hop** (UDP 3784, GTSM TTL = 255) —
there is no multi-hop knob.

## Enabling BFD on an interface

BFD is a flat block under the IS-IS interface:

```
router isis {
  interface eth0 {
    bfd { enable true; }
  }
}
```

There is no global top-level `bfd { }` block — the BFD subsystem starts
automatically with `router isis`. The same `bfd {}` leaves can be set once at
the **instance level** (`router isis { bfd {} }`) as a default for every
interface, overridden per interface (see
[Instance-level defaults](#instance-level-defaults)).

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enable` | boolean | _(off)_ | Attach (or detach) BFD for adjacencies on this interface. |
| `echo-mode` | `transmit` \| `receive` \| `both` | _(off)_ | Enable the [BFD Echo function](ch-10-00-bfd.md#echo-function) on this interface's single-hop adjacencies (IPv4 or IPv6). |
| `echo-transmit-interval` | uint (ms) | `50` | Rate we originate Echo at (`transmit` / `both`). |
| `echo-receive-interval` | uint (ms) | `50` | Advertised Required Min Echo RX (`receive` / `both`). |

Control-packet intervals use the BFD defaults (300 ms / ×3 ⇒ ~900 ms
detection) and are not currently tunable — see
[Tuning intervals](ch-10-00-bfd.md#tuning-intervals) in the overview.

A session is subscribed when the adjacency comes **Up** and
unsubscribed when it goes down.

## Echo

`echo-mode` turns on the [BFD Echo function](ch-10-00-bfd.md#echo-function) for
this interface's adjacencies — single-hop only. Both IPv4 and IPv6 are
supported: the Echo session is built from the interface's and neighbour's
addresses (an IPv6-only adjacency uses the two ends' link-locals). `transmit`
originates Echo + detects on the return; `receive` advertises + reflects (the
peer detects); `both` does both — backed by the per-interface `xdp-bfd-echo`
helper, whose XDP reflector handles 0x0800 and 0x86DD frames alike.

```
router isis {
  interface eth0 {
    bfd {
      enable true;
      echo-mode both;
      echo-transmit-interval 50;
      echo-receive-interval 50;
    }
  }
}
```

## Instance-level defaults

A `bfd {}` block directly under `router isis` supplies defaults for **every**
interface; each leaf's effective value is the per-interface setting if present,
else the instance default, else the hard default. `enable true` at the instance
level **blanket-enables** BFD on all IS-IS interfaces; a per-interface
`bfd { enable false }` opts one out.

```
router isis {
  bfd {
    enable true;          // BFD on every interface…
    echo-mode receive;    // …default Echo role
  }
  interface eth0 {
    bfd { echo-mode both; }   // override; inherits enable
  }
}
```

## Verifying

```
show bfd
show bfd peers <neighbor-address>
```

If a session stays `Down` with a remote discriminator of `0x0`, the
local side is transmitting but nothing is coming back — confirm the
neighbour also has `bfd enable` on its side of the link and that UDP
3784 is not filtered. See the
[overview](ch-10-00-bfd.md#verifying-sessions) for the full command set.

## Tracing BFD events

The IS-IS↔BFD interaction is silent by default. The `bfd` category under
`router isis tracing` turns on its traces at runtime — no rebuild, no
global log-level change:

```
router isis {
  tracing {
    bfd;
  }
}
```

It covers the whole BFD-driven adjacency path:

- the `Subscribe` issued when an adjacency comes **Up** (and the no-op when
  the BFD subsystem isn't wired),
- every session **state change** reported back to IS-IS,
- the RFC 5882 §5 adjacency **teardown** on a `Down` event,
- the **hold-down recovery** when the session returns and the next IIH may
  re-promote the neighbour.

`bfd` is a presence flag — name it to enable, delete it to disable — and
is part of the shared `router isis tracing` block (the same model as
[BGP conditional tracing](ch-02-10-bgp-tracing.md)), so the master `all`
switch enables it alongside every other category. Unlike the per-PDU
`packet` categories there is no `level` refinement: a BFD session is keyed
per interface and neighbour address, not per IS-IS level.

Every traced line is stamped `proto="isis"`, so the
[Protocol-Specific Logging](ch-03-03-protocol-logging.md) recipes apply —
e.g. `jq 'select(.proto=="isis" and (.message | contains("bfd")))'`.

> **Note.** This category also gates the adjacency-teardown message (the
> RFC 5882 §5 `warn`). Enable `tracing bfd` when diagnosing why an
> adjacency dropped on a BFD `Down`.
