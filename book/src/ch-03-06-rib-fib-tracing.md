# RIB/FIB Tracing

The rest of this chapter covers *output* logging — where logs go
(`--log-output`), how they are formatted (`--log-format`), and how to
filter them after the fact. RIB/FIB tracing is a **content** filter
instead: a typed config block that decides, at runtime, *which* internal
RIB and FIB events are emitted in the first place — with no rebuild and
no global log-level change.

It is the runtime successor to a set of compile-time `DEBUG_*` flags that
used to gate these same diagnostic traces (you had to edit the source and
rebuild to turn them on). It mirrors the per-protocol tracing blocks
([BGP](ch-02-10-bgp-tracing.md), OSPF, IS-IS) — gated log sites consult a
config struct — but because the RIB and FIB are core infrastructure
rather than a routing protocol, the block lives under the top-level
`system` container:

```
system {
  tracing {
    rib { ... }
    fib { ... }
  }
}
```

## Two planes

The block is split into `rib` and `fib` to match the operator's mental
model and the classic Juniper `routing-options` (RIB) versus
`forwarding-options` (FIB) traceoptions split:

- **`rib`** — the control-plane RIB: route table changes, best-path
  selection, recursive nexthop resolution, redistribution, MPLS ILM,
  static routes, interface / connected-address handling, VRF lifecycle,
  and SRv6 SID resolution.
- **`fib`** — the dataplane: what is programmed into the kernel over
  netlink.

`route` and `nexthop` deliberately appear on **both** planes. That is the
single most useful split this block buys you: a route can be resolved and
best in the RIB yet never reach the kernel, and only side-by-side
`rib route` + `fib route` traces show where it stalled.

## The `all` master switch

```
system {
  tracing {
    all;
  }
}
```

`all` turns on **every** category under both planes at summary level. It
does not imply `detail` — that stays opt-in.

## RIB categories

Each leaf is a **presence flag**: name it to enable, delete it to
disable. Absence means the category is silent.

| Category | What it traces | Modifiers |
|---|---|---|
| `route` | IPv4/IPv6 route add and withdraw into the RIB, and best-path selection among competing entries (admin-distance / metric). | `detail` |
| `nexthop` | Recursive nexthop resolution and Next-Hop Tracking (NHT) register / notify. | `detail` |
| `interface` | Link up/down, MTU changes, connected-route recovery (re-installing configured addresses the kernel dropped, with external-actor flap suppression). | `detail` |
| `srv6` | SRv6 SID resolution (End / End.X / End.DT — behavior, locator, owner, SID device, nexthop) before the SID is programmed into the FIB. | `detail` |
| `redistribute` | Route exchange with protocol clients (BGP / IS-IS / OSPF) through the RIB client registry. | — |
| `label` | MPLS ILM handling: local-label allocation and label-to-nexthop bindings. | — |
| `static` | Static-route configuration processing. | — |
| `vrf` | VRF add/delete (incl. adoption of an existing kernel VRF), per-VRF table allocation, interface-to-VRF binding. | — |

## FIB categories

| Category | What it traces | Modifiers |
|---|---|---|
| `route` | Route programming to the kernel FIB over netlink. | `detail` |
| `nexthop` | Nexthop-group programming (`RTM_NEWNEXTHOP`). | `detail` |
| `srv6` | SRv6 `seg6local` SID install / uninstall and the SID device. | `detail` |
| `l2` | L2 / EVPN dataplane — a sub-tree of `bridge`, `vxlan`, `fdb`, `mdb` toggles. | (per-type) |
| `kernel` | Raw netlink messages on the southbound socket. | `detail`, `direction` |
| `label` | MPLS LFIB programming — ILM entries (swap / pop / php). | — |
| `neighbor` | ARP / ND (IPv4 / IPv6 neighbor) table programming. | — |
| `interface` | Link admin up, MTU set, dummy-device create/delete, address add/delete. | `detail` |
| `vrf` | VRF device create/delete, enslaving an interface to a VRF master. | — |

The `l2` sub-tree groups four independent toggles:

```
system tracing fib l2 bridge    # bridge device + addr-gen-mode
system tracing fib l2 vxlan     # VXLAN device + VNI registration
system tracing fib l2 fdb       # MAC / FDB entries (incl. EVPN-sourced)
system tracing fib l2 mdb       # multicast forwarding database
```

> **Instrumented vs reserved.** The full category surface is defined and
> the config round-trips for every leaf, but only the categories that
> already have trace sites emit anything today: `rib` `route` / `nexthop`
> / `interface` / `srv6`, and `fib` `route` / `nexthop` / `srv6` /
> `l2 {vxlan, fdb, mdb}`. The remaining leaves (`redistribute`, `label`,
> `static`, `vrf`, `kernel`, `neighbor`, `l2 bridge`) are accepted,
> stored, and covered by `all` — they light up once their sites are
> instrumented.

## Modifiers

**`detail`** — the verbose categories (`route`, `nexthop`, `interface`,
`srv6` on each plane, plus `fib kernel`) take an optional `detail`.
Without it, each event is a one-line summary; with it, the full record is
logged.

```
system tracing rib route          // summary
system tracing rib route detail   // fully decoded
```

**`direction`** — `fib kernel` additionally takes a `direction` of `send`
or `receive`. `send` is what zebra-rs programs into the kernel; `receive`
is what the kernel reports back (link up/down, address changes, routes
owned by other daemons). Omit it for both — there is no explicit `both`
value; absence means both.

```
system tracing fib kernel direction receive
```

> **Warnings stay on.** Tracing categories gate *diagnostic* `info` /
> `debug` detail only. Operator-facing **warnings and errors** — a route
> the kernel rejected, an MTU set that failed, a label pool exhausted,
> a malformed SID install — are always emitted regardless of the tracing
> config, so turning a category off never hides a real problem.

## Examples

Find where a route stalls between the RIB and the kernel:

```
system {
  tracing {
    rib { route; nexthop; }
    fib { route { detail; } }
  }
}
```

Watch only what the kernel reports back to us (link / address / foreign
routes), fully decoded:

```
system {
  tracing {
    fib { kernel { direction receive; } }
  }
}
```

Trace EVPN MAC programming and the SRv6 SID install path:

```
system {
  tracing {
    fib {
      l2 { fdb; }
      srv6;
    }
  }
}
```

## Interaction with `RUST_LOG`

RIB/FIB tracing is a *content* filter — it decides which sites emit — and
the lines it emits are at `info` level. It is independent of the
[`RUST_LOG`](ch-03-03-protocol-logging.md#protocol-specific-debug-levels)
*level* filter: a category produces nothing unless the module's level
admits `info` (the default does). Use tracing categories to pick *what*
to see at runtime; use `RUST_LOG` only when you need a coarser
module-level sweep.
