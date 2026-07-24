# BGP BFD

BGP attaches a [BFD](ch-10-00-bfd.md) session to a neighbour so that a
forwarding-path failure brings the peering down in sub-second time
rather than waiting for the BGP hold timer. When the session drops,
BGP sends the neighbour's FSM a `Stop` (RFC 5882 §5).

See the [BFD overview](ch-10-00-bfd.md) for the session model, the
single- vs multi-hop transport, and the `show bfd` commands. This
section covers only the BGP-side configuration.

For the special case of a directly connected eBGP peer whose
*interface* goes down, no BFD is needed:
[fast external failover](ch-02-37-bgp-fast-external-failover.md)
resets the session on the link event itself, by default. BFD earns its
keep on everything link state cannot see — forwarding failures,
switched paths, multihop and iBGP sessions.

## Enabling BFD on a neighbour

BFD is a flat block under the neighbour. The minimal form is just
`enable`:

```
router bgp {
  neighbor 10.0.0.2 {
    remote-as 65002;
    bfd { enabled true; }
  }
}
```

There is no global top-level `bfd { }` block — the BFD subsystem starts
automatically with `router bgp`. The same `bfd {}` leaves can be set once at the
**instance level** (`router bgp { bfd {} }`) as a default for every neighbour,
overridden per neighbour (see [Instance-level defaults](#instance-level-defaults)).

| Leaf | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | _(off)_ | Attach (or, on `false` / delete, detach) a BFD session for this neighbour. |
| `multihop` | boolean | *inferred* | Force the hop mode. Unset ⇒ inferred (see below). Per-neighbour only. |
| `minimum-ttl` | 1–254 | 254 | Multi-hop only: lowest accepted received TTL (RFC 5883). Ignored single-hop. Per-neighbour only. |
| `echo-mode` | `transmit` \| `receive` \| `both` | _(off)_ | [Echo function](ch-10-00-bfd.md#echo-function) role — **single-hop only** (see [Echo](#echo)). |
| `echo-transmit-interval` | uint (ms) | `50` | Echo TX rate (`transmit` / `both`). |
| `echo-receive-interval` | uint (ms) | `50` | Advertised Required Min Echo RX (`receive` / `both`). |
| `detect-offload` | boolean | `false` | [Offload expiration detection](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload) to the in-kernel (XDP) watchdog — **single-hop only** (inert on multihop). |

Control-packet intervals use the BFD defaults (300 ms / ×3 ⇒ ~900 ms
detection) and are not currently tunable — see
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

zebra-rs does have an `ebgp-multihop` transport knob (for the BGP TCP
session's TTL), but the BFD hop-mode inference does not read it — so
**eBGP over loopbacks** still needs the BFD hop mode forced explicitly:

```
router bgp {
  neighbor 10.0.0.2 {
    remote-as 65002;
    update-source 10.0.0.1;
    bfd {
      enabled true;
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

## Echo

`echo-mode` turns on the [BFD Echo function](ch-10-00-bfd.md#echo-function) —
but Echo is **single-hop only** (RFC 5883 multihop has no Echo), so it applies
**only to directly-connected eBGP** (`multihop` inferred or forced `false`). On
an iBGP or multihop-eBGP neighbour the `echo-mode` leaf is accepted but inert.
Within that constraint it works like the OSPF/IS-IS form — `transmit` originates,
`receive` advertises + reflects, `both` does both, via the
[eBPF data plane](ch-16-00-ebpf.md). IPv4 and IPv6 neighbours are covered alike (the Echo
session uses the same addresses as the control session):

```
router bgp {
  neighbor 10.0.0.2 {        // directly-connected eBGP
    remote-as 65002;
    bfd {
      enabled true;
      echo-mode both;
      echo-transmit-interval 50;
      echo-receive-interval 50;
    }
  }
}
```

## Offloading expiration detection

`detect-offload true` moves the RFC 5880 §6.8.4 detection timer into the
kernel via the [eBPF data plane](ch-16-00-ebpf.md) — **single-hop
neighbours only** (the XDP program runs on attached ports; on iBGP / multihop
eBGP the leaf is accepted but inert, like `echo-mode`). See
[the overview](ch-10-00-bfd.md#offloading-expiration-detection-detect-offload)
for the mechanism and guard-rails.

```
router bgp {
  neighbor 10.0.0.2 {        // directly-connected eBGP
    remote-as 65002;
    bfd {
      enabled true;
      detect-offload true;   // expiration detection in kernel/XDP
    }
  }
}
```

To place the helper, a single-hop session is keyed by the **connected
interface** the neighbour lives on (resolved from the interface
addresses the RIB reports). If BFD is enabled before that address is
known, the session starts un-keyed (helper-backed features off) and is
re-keyed automatically the moment the covering address is learned — the
same keying also lets the Echo helper attach for BGP neighbours.

## Instance-level defaults

A `bfd {}` block directly under `router bgp` supplies defaults for **every**
neighbour; the effective value of each leaf is the per-neighbour setting if
present, else the instance default, else the hard default. `enabled true` at the
instance level **blanket-enables** BFD on all neighbours; a per-neighbour
`bfd { enabled false }` opts one out. (`multihop` / `minimum-ttl` are
per-neighbour only — they are not inherited.)

```
router bgp {
  bfd {
    enabled true;          // BFD on every neighbour…
    echo-mode receive;    // …default Echo role (single-hop neighbours)
  }
  neighbor 10.0.0.2 {
    remote-as 65002;
    bfd { echo-mode both; }   // override; inherits enable
  }
}
```

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
