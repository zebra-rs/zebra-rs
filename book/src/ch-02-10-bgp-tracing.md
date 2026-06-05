# BGP Conditional Tracing

BGP carries a large amount of internal activity — FSM transitions, every
protocol message, route import/export, label allocation. Logging all of
it unconditionally would drown the log; logging none of it makes live
troubleshooting impossible. `router bgp tracing` is the middle ground: a
typed config block of per-**category** switches that turn detailed
`info`-level traces on at runtime, with no rebuild and no global log-level
change.

This mirrors the IS-IS / OSPF `tracing` model — gated log macros consult a
config struct — but with the BGP-specific category set.

Every traced line is stamped `proto="bgp"` and `category="<name>"`, so the
filtering recipes in [Protocol-Specific Logging](ch-03-03-protocol-logging.md)
apply directly (e.g. `jq 'select(.proto=="bgp" and .category=="vpn")'`).

## Two scopes, one option set

The same `tracing { ... }` block attaches at two points:

- **Instance-wide** — `router bgp { tracing { ... } }` applies to every
  peer and every instance-level activity.
- **Per-neighbour** — `router bgp { neighbor <addr> { tracing { ... } } }`
  scopes tracing to a single session.

Per-neighbour config is **additive** to the instance config: a category is
traced for a peer if either the instance block *or* that peer's block
enables it. Instance-only categories (`vpn`, `srv6`, `vrf`, `bfd`,
`label`) are most useful at the instance scope, since they are not tied to
a single session.

## The `all` master switch

```
router bgp {
  tracing {
    all;
  }
}
```

`all` turns on **every** category at summary level. It does not imply
packet `detail` — that stays opt-in (see [Packet tracing](#packet-tracing)).

## Categories

Each leaf is a **presence flag**: name it to enable, delete it to disable.
Absence means the category is silent.

| Category | Scope | What it traces |
|---|---|---|
| `fsm` | per-peer | Peer FSM state changes (Idle/Connect/Active/OpenSent/OpenConfirm/Established) and the events that drive them. |
| `packet` | per-peer | BGP protocol messages — see [Packet tracing](#packet-tracing). |
| `adj-in` | per-peer | Routes entering the inbound Adj-RIB (received NLRI and their disposition). |
| `adj-out` | per-peer | Routes leaving via the outbound Adj-RIB (what is advertised after export policy). |
| `label` | instance | MPLS label allocation / binding for labeled-unicast / L3VPN routes (dynamic label-block grants, per-VRF label assignment). |
| `vpn` | instance | L3VPN import/export — per-VRF prefixes written to the VPNv4/VPNv6 Loc-RIB and advertised to PE/CE peers, with their RD, route-targets and label. |
| `srv6` | instance | SRv6 locator resolution and per-VRF End.DT46 service-SID reconciliation (L3VPN over SRv6). |
| `vrf` | instance | Per-VRF task lifecycle — spawn / respawn / despawn / shutdown, inbound-connection routing, and the staged per-VRF config observed at commit. |
| `bfd` | instance | BGP's interaction with the BFD client — session state changes and client-readiness that drive RFC 5882 peer teardown. |

> **Warnings stay on.** Tracing categories gate *diagnostic* `info`/`debug`
> detail only. Operator-facing **warnings and errors** — missing RD,
> dropped routes, unsupported platform, setsockopt failures — are always
> emitted (tagged `proto="bgp"`) regardless of the tracing config, so
> turning a category off never hides a real problem.

## Packet tracing

`packet` is a sub-tree, not a single flag. Each message type is a presence
container; naming it enables tracing for that type in **both directions at
summary level**, and two optional children refine it:

| Child | Meaning |
|---|---|
| `detail` | Log the fully-decoded message (all attributes / NLRI / capabilities) instead of a one-line summary. |
| `direction send` \| `receive` | Restrict to one direction. Omit for both — there is no explicit `both` value; absence means both. |

The message types are `open`, `update`, `keepalive`, `notification`,
`route-refresh`, plus `all` (a catch-all applied on top of the per-type
toggles).

```
router bgp {
  tracing {
    packet {
      open;                       // both directions, summary
      notification { detail; }    // both directions, fully decoded
      update { direction receive; } // received UPDATEs only
    }
  }
}
```

## Examples

Watch FSM and label activity instance-wide:

```
router bgp {
  tracing {
    fsm;
    label;
  }
}
```

Debug a single flapping neighbour without touching the rest of the fleet:

```
router bgp {
  neighbor 10.0.0.5 {
    remote-as 65501;
    tracing {
      fsm;
      packet { update { direction receive; } }
      adj-in;
    }
  }
}
```

Trace the full L3VPN-over-SRv6 control path:

```
router bgp {
  tracing {
    vpn;
    srv6;
    label;
  }
}
```

## Interaction with `RUST_LOG`

Tracing categories are a *content* filter — they decide which sites emit —
and the lines they emit are at `info` level. They are independent of the
[`RUST_LOG`](ch-03-03-protocol-logging.md#protocol-specific-debug-levels)
*level* filter: a category produces nothing unless the BGP module's level
admits `info` (the default does). Use tracing categories to pick *what* to
see at runtime; use `RUST_LOG` only when you need a coarser module-level
sweep.
