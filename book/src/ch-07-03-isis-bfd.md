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

No top-level `bfd { }` block is required — the BFD subsystem starts
automatically with `router isis`.

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enable` | boolean | `false` | Attach (or detach) BFD for adjacencies on this interface. |
| `profile` | string | — | Named `/bfd/profile` to apply. *Stored but not yet applied — see the overview.* |

A session is subscribed when the adjacency comes **Up** and
unsubscribed when it goes down. Both IPv4 and IPv6 adjacencies are
supported; IPv6 sessions run over the interface's link-local addresses
and are demultiplexed per interface.

## Verifying

```
show bfd
show bfd peer <neighbor-address>
```

If a session stays `Down` with a remote discriminator of `0x0`, the
local side is transmitting but nothing is coming back — confirm the
neighbour also has `bfd enable` on its side of the link and that UDP
3784 is not filtered. See the
[overview](ch-10-00-bfd.md#verifying-sessions) for the full command set.
