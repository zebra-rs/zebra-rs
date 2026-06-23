# OSPFv2 Configuration

OSPFv2 configuration in zebra-rs lives under `router ospf` and is
shaped around the standard `area { interface }` hierarchy: each
participating interface is declared inside the area it belongs to.

```
router ospf {
  router-id 10.0.0.1;
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
      hello-interval 5;
      dead-interval 20;
    }
  }
}
```

There is no separate `network X area Y` table — an interface
participates in OSPF if and only if it appears under some area with
`enable true`, and the area it belongs to is implicit from the parent
list entry.

## Area identifier — decimal or dotted-quad

The `area` list key is a union of `uint32` and `inet:ipv4-address`,
so both spellings are accepted and they normalize to the same 32-bit
area ID:

```
area 0           # backbone (0.0.0.0)
area 0.0.0.0     # backbone (equivalent)
area 1           # non-backbone (0.0.0.1)
area 0.0.0.1     # non-backbone (equivalent)
```

Internally the area ID is always a 32-bit value matching the on-the-
wire `Area ID` field of OSPFv2 headers (RFC 2328 §A.3.1). Dotted-quad
is the canonical rendering in `show` output regardless of how the
operator wrote it.

| YANG leaf | Type | Notes |
|---|---|---|
| `/router/ospf/router-id` | `inet:ipv4-address` | Optional; wins over the RIB-distributed value. Deleting it falls back to the RIB-distributed router-id, then to the constructor default `10.0.0.1`. |
| `/router/ospf/vrf/<name>/router-id` | `inet:ipv4-address` | Per-VRF instance override; same precedence against the VRF's RIB-distributed router-id. |
| `/router/ospf/area/<id>/area-id` | `union { uint32; ipv4-address }` | List key — see above. |

Two routers must not share a Router ID — a neighbor advertising our
own ID looks like self-originated traffic and no adjacency forms — so
either configure it explicitly per router (recommended) or ensure each
router derives a unique value (e.g. a unique loopback address). The
same `router-id` leaf exists on `router ospfv3` (and its `vrf` list)
with identical semantics. See
[Selection of the Router-ID](ch-00-01-router-id.md) for the full
selection and precedence model.

## Per-interface knobs

Each `interface` entry under an area carries the standard set of
per-link OSPF timers and tuning parameters. All values match the
defaults from RFC 2328 Appendix C ("Configurable Parameters") except
where noted.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/ospf/area/<id>/interface/<n>/enable` | `false` | — | boolean |
| `/router/ospf/area/<id>/interface/<n>/priority` | 64 | 0..255 | (count) |
| `/router/ospf/area/<id>/interface/<n>/hello-interval` | 10 | 1..65535 | seconds |
| `/router/ospf/area/<id>/interface/<n>/dead-interval` | 40 | 1..4294967295 | seconds |
| `/router/ospf/area/<id>/interface/<n>/retransmit-interval` | 5 | 1..65535 | seconds |
| `/router/ospf/area/<id>/interface/<n>/mtu-ignore` | `false` | — | boolean |

Notes:

- **`priority`** is the DR-election priority advertised in Hellos.
  Higher wins; zero forbids the router from becoming DR or BDR on
  that segment. The zebra-rs default of 64 is the IOS-XR baseline; a
  router unconditionally configured higher than its peers becomes
  the DR on a freshly-formed broadcast segment.
- **`hello-interval`** and **`dead-interval`** must match on all
  routers on the same segment for adjacency to form. The on-the-wire
  Hello carries both; mismatches cause Hellos to be silently
  discarded and the adjacency never leaves `Down`. The conventional
  ratio is `dead = 4 × hello`; sub-second adjacency detection is
  better delegated to BFD.
- **`retransmit-interval`** governs how often unacknowledged LSAs in
  the per-neighbor `ls_rxmt` list are re-sent. The default of 5 s
  is conservative and rarely needs tuning on healthy links.
- **`mtu-ignore`** disables the MTU-mismatch check during DBD
  exchange (RFC 2328 §10.6). Default `false` matches the RFC; set
  to `true` only when intentionally peering across links with
  different MTUs and accepting the resulting black-hole risk for
  jumbo packets.

## Segment Routing extensions

OSPFv2 SR-MPLS (RFC 8665) is configured at instance and per-interface
scope:

```
router ospf {
  segment-routing mpls;
  area 0 {
    interface enp0s6 {
      enable true;
      prefix-sid {
        index 16001;
      }
    }
  }
}
```

| YANG leaf | Type | Notes |
|---|---|---|
| `/router/ospf/segment-routing` | enum `{ mpls }` | Enables Router Information LSA (RFC 7770) advertising SR capability. |
| `/router/ospf/area/<id>/interface/<n>/prefix-sid/index` | `uint32` | SID-index form (advertised as Extended Prefix LSA, RFC 7684). |
| `/router/ospf/area/<id>/interface/<n>/prefix-sid/absolute` | `uint32` | Absolute-label form (alternative to index). |

`index` and `absolute` are mutually exclusive — set one or the
other. Toggling `segment-routing mpls` originates or flushes the
Router Information LSA and all Extended Prefix LSAs for configured
interfaces in a single step.

## Tracing and diagnostics

Conditional tracing is a runtime debug switch: a category is silent
until you name it in the config, at which point the matching log
sites start emitting. It mirrors the BGP and IS-IS `tracing` model —
each toggle is a *presence* flag (name it to enable, delete it to
disable), and the gated log macros consult the live config on every
packet, transition, and event, so categories turn on and off without
a restart.

The block is identical for both versions, attached to `router ospf`
(OSPFv2) and `router ospfv3` (OSPFv3); the two emit `proto=ospf` and
`proto=ospfv3` respectively so their logs stay filterable apart.

```
router ospf {
  tracing {
    fsm { nfsm; }                    # neighbor FSM transitions
    packet {
      hello;                         # both directions, summary
      ls-update { detail; }          # both directions, full decode
      dd { direction receive; }      # received DBDs only
    }
    spf;                             # SPF calculation events
  }
}

router ospfv3 {
  tracing { all; }                   # master switch: every category
}
```

| Category | Toggles |
|---|---|
| `all` | master switch — traces every category below |
| `packet` | `hello`, `dd`, `ls-req`, `ls-update`, `ls-ack`, `all` |
| `fsm` | `ifsm`, `nfsm`, `all` |
| `spf` | SPF (shortest-path-first) calculation |
| `lsdb` | LSA origination / installation / flooding |

Each `packet` toggle is a presence container carrying two optional
refinements: `direction` (`send` or `receive`; omit for both) and
`detail` (log the fully decoded packet instead of a one-line
summary). Each `fsm` toggle carries an optional `detail` that widens
it from summary transitions to detail-level transition lines. `spf`
and `lsdb` are bare presence leaves.

Every gated line carries structured fields — `proto`, `category`
(`packet` / `fsm` / `event`), and, for packets, `packet`,
`direction`, and `detail` — so the output can be filtered downstream
by protocol and category.

## Moving an interface between areas

Because the area is part of the configuration path, moving an
interface from area 0 to area 0.0.0.1 is two operations:

```
no router ospf area 0 interface enp0s6
router ospf area 0.0.0.1 interface enp0s6 enable true
```

zebra-rs handles this internally via a `Disable → Enable` transition
pair (`Message::Disable` followed by `Message::Enable` carrying the
new area-id), which tears down the old IFSM state machine and starts
a fresh one in the new area. No daemon restart is required.

If the same interface name accidentally appears under two areas at
once, the second area's `enable true` wins (the link's
`config.area` is overwritten). This is not a supported configuration
and zebra-rs may add a validation error for it in a future release.

## Minimal worked example — two routers, one area

R1:
```
router ospf {
  router-id 10.0.0.1;
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
}
```

R2:
```
router ospf {
  router-id 10.0.0.2;
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
}
```

With matching default Hello/Dead intervals (10/40 s), adjacency
progresses Down → Init → 2-Way → ExStart → Exchange → Loading → Full
within roughly two hello cycles. `show ospf neighbor` reports
`Full/DR` and `Full/BDR` for the elected pair; `show ospf database`
lists the Router LSAs and (for broadcast segments) the Network LSA
generated by the DR.

## Cross-reference — FRR `ospfd` command mapping

| zebra-rs YANG | FRR `ospfd` command |
|---|---|
| `router-id` | `ospf router-id` |
| `area/<id>/interface/<n>/enable true` | `network <prefix> area <id>` (interface inferred from prefix) |
| `area/<id>/interface/<n>/priority` | `ip ospf priority` (interface) |
| `area/<id>/interface/<n>/hello-interval` | `ip ospf hello-interval` (interface) |
| `area/<id>/interface/<n>/dead-interval` | `ip ospf dead-interval` (interface) |
| `area/<id>/interface/<n>/retransmit-interval` | `ip ospf retransmit-interval` (interface) |
| `area/<id>/interface/<n>/mtu-ignore` | `ip ospf mtu-ignore` (interface) |
| `segment-routing mpls` | `segment-routing on` + `segment-routing mpls` |
| `area/<id>/interface/<n>/prefix-sid/index` | `ip ospf prefix-sid index` (interface) |

The shape differs: zebra-rs declares interfaces under their area
directly, while FRR uses a separate `network` statement to bind
prefix-matched interfaces to an area. The resulting on-the-wire
behaviour is the same.

## Gaps relative to FRR `ospfd`

OSPFv2 features not yet implemented in zebra-rs:

- Stub / NSSA / Totally-Stubby area types (RFC 2328 §3.6, RFC 3101).
- Virtual links across non-backbone areas.
- ABR Type 3 (Summary) and Type 4 (ASBR-Summary) origination.
- Type 5 (AS-External) origination from redistribution and Type 7
  (NSSA-External) translation.
- Per-interface authentication (none / simple-password / MD5 /
  HMAC-SHA, RFC 5709).
- Per-area `spf-interval` / `lsa-gen-interval` throttles (currently
  un-throttled — every LSDB change schedules an immediate SPF).
- Graceful Restart helper / restarter (RFC 3623).

Most of these are tracked alongside the OSPFv3 work and will land as
v2 and v3 share the same generic infrastructure.
