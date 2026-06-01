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
| `echo-mode` | `transmit` \| `receive` \| `both` | _(off)_ | Enable the [BFD Echo function](ch-10-00-bfd.md#echo-function) on this interface's single-hop IPv4 adjacencies. |
| `echo-transmit-interval` | uint (ms) | `50` | Rate we originate Echo at (`transmit` / `both`). |
| `echo-receive-interval` | uint (ms) | `50` | Advertised Required Min Echo RX (`receive` / `both`). |

Control-packet intervals use the BFD defaults (300 ms / ×3 ⇒ ~900 ms
detection) and are not currently tunable — see
[Tuning intervals](ch-10-00-bfd.md#tuning-intervals) in the overview.

A session is subscribed when the adjacency comes **Up** and
unsubscribed when it goes down.

## Echo

`echo-mode` turns on the [BFD Echo function](ch-10-00-bfd.md#echo-function) for
this interface's adjacencies — single-hop **IPv4 only** (IS-IS is an L2 protocol;
the Echo session is built from the interface's and neighbour's IPv4 addresses,
so an IPv6-only adjacency is inert). `transmit` originates Echo + detects on the
return; `receive` advertises + reflects (the peer detects); `both` does both —
backed by the per-interface `xdp-bfd-echo` helper.

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
