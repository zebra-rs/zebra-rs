# BGP BFD

BGP attaches a [BFD](ch-10-00-bfd.md) session to a neighbour so that a
forwarding-path failure brings the peering down in sub-second time
rather than waiting for the BGP hold timer. When the session drops,
BGP sends the neighbour's FSM a `Stop` (RFC 5882 §5).

See the [BFD overview](ch-10-00-bfd.md) for the session model, the
single- vs multi-hop transport, and the `show bfd` commands. This
section covers only the BGP-side configuration.

## Enabling BFD on a neighbour

BFD is a flat block under the neighbour. The minimal form is just
`enable`:

```
router bgp {
  neighbor 10.0.0.2 {
    remote-as 65002;
    bfd { enable true; }
  }
}
```

No top-level `bfd { }` block is required — the BFD subsystem starts
automatically with `router bgp`.

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enable` | boolean | `false` | Attach (or, on `false` / delete, detach) a BFD session for this neighbour. |
| `multihop` | boolean | *inferred* | Force the hop mode. Unset ⇒ inferred (see below). |
| `minimum-ttl` | 1–254 | 254 | Multi-hop only: lowest accepted received TTL (RFC 5883). Ignored single-hop. |

Sessions use the BFD defaults (300 ms / ×3 ⇒ ~900 ms detection); the
timers are not currently tunable — see
[Tuning intervals](ch-10-00-bfd.md#tuning-intervals) in the overview.

## Single-hop vs multi-hop — inferred by default

BGP does **not** put a `multihop` keyword on the neighbour by default;
it infers the hop mode from the session, mirroring FRR:

- **iBGP** ⇒ multi-hop (iBGP peers are typically loopback-to-loopback).
- **Directly-connected eBGP** ⇒ single-hop.

This matches FRR's `PEER_IS_MULTIHOP` behaviour. (Cisco IOS-XR instead
keys multi-hop off the `ebgp-multihop` setting; the two agree on the
common directly-connected eBGP and iBGP cases.) On a point-to-point
link the distinction is moot — the session is single-hop either way.

zebra-rs does not yet have an `ebgp-multihop` knob, so **eBGP over
loopbacks** needs the hop mode forced explicitly:

```
router bgp {
  neighbor 10.0.0.2 {
    remote-as 65002;
    update-source 10.0.0.1;
    bfd {
      enable true;
      multihop true;       // eBGP-over-loopback; iBGP would infer this
      minimum-ttl 250;
    }
  }
}
```

The session's local address is taken from the neighbour's
`update-source` (falling back to an unspecified address of the right
family); there is no separate BFD source knob. This is the address the
BFD control packets are actually sourced from, and the one `show bfd
peers` reports as `Local address`. Changing `update-source` on a
BFD-enabled neighbour rebuilds the session with the new source.

## Verifying

```
show bfd peers 10.0.0.2
```

A multi-hop session shows `(multihop)` and its `Minimum TTL`; a
single-hop session shows `(single-hop)`. If the peer stays `Down` with
a remote discriminator of `0x0`, confirm the far end runs BFD toward
this router and that UDP 3784 (single-hop) or 4784 (multi-hop) is open
on the path. See the [overview](ch-10-00-bfd.md#verifying-sessions) for
the full command set.

Both IPv4 and IPv6 neighbours are supported.
