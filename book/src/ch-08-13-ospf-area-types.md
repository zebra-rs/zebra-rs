# Area Types: Stub and NSSA

Every area has an `area-type` — `normal` (the default), `stub`, or
`nssa` — controlling which external routing information enters it
(RFC 2328 §3.6, RFC 3101 §2):

- **`normal`** carries the full LSDB, including Type-5 AS-External
  LSAs.
- **`stub`** drops Type-5 AS-External LSAs; internal routers reach
  external destinations through the ABR. Inter-area Type-3
  summaries still flood inward.
- **`nssa`** (Not-So-Stubby Area) also drops Type-5, but allows
  ASBRs *inside* the area to inject externals as Type-7
  NSSA-External LSAs, which the NSSA ABR translates to Type-5 for
  the rest of the domain.

The type is negotiated on the wire: the E-bit (external-capable) and
N-bit (NSSA) in the Hello options follow this knob, and a mismatch
with a neighbor causes Hello rejection (RFC 3101 §2.5, RFC 2328
§10.5) — so all routers attached to an area must agree on its type
before adjacencies form. The same configuration surface exists under
`router ospf` (OSPFv2) and `router ospfv3` (OSPFv3), both validated
by BDD topologies.

| YANG leaf (`/router/ospf/area/<id>/…`) | Default | Values |
|---|---|---|
| `area-type` | `normal` | `normal` \| `stub` \| `nssa` |
| `no-summary` | `false` | boolean — totally-stubby / totally-NSSA |
| `nssa-default-originate` | `false` | boolean — ABR originates a default Type-7 |
| `nssa-suppress-fa` | `false` | boolean — zero the forwarding address on translation |
| `nssa-translator-role` | `candidate` | `candidate` \| `always` \| `never` |
| `redistribute/connected/metric` | 20 | 0..16777214 |
| `redistribute/connected/metric-type` | `type-2` | `type-1` \| `type-2` |

All the `nssa-*` leaves and the per-area `redistribute` block are
ignored unless `area-type` is `nssa`; `no-summary` applies to both
`stub` and `nssa`.

## Stub areas

On the ABR and on every internal router of the area:

```
router ospf {
  area 0.0.0.1 {
    area-type stub;
    interface enp0s7 {
      enable true;
    }
  }
}
```

Internal routers keep receiving Type-3 summaries (e.g. loopbacks of
other areas appear in `show ospf route`) but Type-5 externals do
not enter the area. Setting `no-summary true` on the **ABR**
additionally drops Type-3 summaries entering the area
(totally-stubby); internal routers then rely entirely on the
default route.

## NSSA areas

An NSSA carries its own external routes as area-scoped Type-7 LSAs.
A typical deployment has two configuration roles:

The **ABR**, translating Type-7 into Type-5 and (optionally)
originating a default Type-7 into the area (RFC 3101 §2.3):

```
router ospf {
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
  area 0.0.0.1 {
    area-type nssa;
    nssa-default-originate true;
    interface enp0s7 {
      enable true;
    }
  }
}
```

The internal **ASBR**, redistributing routes into the NSSA as
Type-7. Because Type-7 LSAs are area-scoped, the redistribute knob
sits *per area*, not at instance level — an operator may inject
`connected` into one NSSA and not another:

```
router ospf {
  area 0.0.0.1 {
    area-type nssa;
    redistribute {
      connected {
        metric 20;
        metric-type type-2;
      }
    }
    interface lo {
      enable true;
    }
    interface enp0s8 {
      enable true;
    }
  }
}
```

`metric-type` selects E1 vs E2 semantics: `type-2` (the default,
matching FRR) uses the LSA metric alone, so the route costs `[20]`
everywhere; `type-1` adds the SPF cost to the originator, so the
metric grows with distance and survives translation (a backbone
router closer to the NSSA sees a smaller total). The metric default
of 20 matches FRR.

Combining `area-type nssa` with `no-summary true` on the ABR gives
a totally-NSSA area: Type-7 machinery works as above, but Type-3
summaries no longer enter the area.

## Type-7 → Type-5 translation and the translator role

Translation runs on an NSSA **ABR** selected by
`nssa-translator-role` (RFC 3101 §2.2):

- `candidate` (default) — elect locally: the ABR with the highest
  Router ID among all ABRs visible in the NSSA's LSDB (identified
  by the B-bit in their Router-LSAs) translates.
- `always` — translate unconditionally. Multiple `always`-mode
  ABRs in one NSSA create duplicate Type-5s, an operator hazard
  called out in RFC 3101 §3.1.
- `never` — this ABR never translates. If no other translator
  exists, NSSA externals stay inside the area.

Election is computed locally with no protocol negotiation; the
Nt-bit announcement in the Router-LSA is intentionally not emitted,
matching how FRR, IOS and Junos behave in practice.

An NSSA ASBR originates its P-bit Type-7s with a **non-zero
forwarding address** — an address on one of its NSSA-connected
interfaces (RFC 3101 §2.3) — and the translator preserves it in the
Type-5, so backbone receivers route (and measure E1 metrics) to the
true AS exit rather than the translating ABR. Receivers resolve a
non-zero FA via their intra-/inter-area route to it (RFC 2328 §16.4
step 3); an FA with no such route makes the LSA unusable, as the RFC
requires.

`nssa-suppress-fa true` zeroes the forwarding address when
translating Type-7 to Type-5 (RFC 3101 §2.6), forcing traffic
through the translating ABR instead of the FA — useful when the FA
prefix is not reachable outside the NSSA. Both behaviors are
validated by `ospfv2_nssa_fa.feature`.

## Runtime transitions

All knobs apply to a live instance without restart. Changing
`area-type` updates the option bits on the next Hello — neighbors
with now-mismatched N/E bits drop out and re-form under the new
type — and resyncs the derived LSAs in the same commit: the default
Type-7 is originated or flushed, per-area redistributes re-originate
or flush their Type-7s, and the translator seeds or clears
translated Type-5s. Flipping `nssa-translator-role` (e.g.
`candidate` → `never`) likewise starts or stops translation
immediately.

## Observing area types

`show ospf neighbor` and `show ospf database` render the OSPF
options byte per adjacency/LSA — the `E` flag is clear on stub and
NSSA links and the `N/P` flag is set on NSSA links, which is the
quickest way to confirm both ends agree on the area type. Type-7
LSAs appear as `NSSA External` in `show ospf database` (v3:
`NSSA-LSA` in `show ospfv3 database`). Translator election has no
dedicated show field; whether translation is running is observable
on the backbone side, where translated Type-5s appear in
`show ospf database` and their prefixes in `show ospf route`.

## OSPFv3

`router ospfv3` accepts the identical area block — `area-type`,
`no-summary`, `nssa-default-originate`, `nssa-suppress-fa`,
`nssa-translator-role`, and per-area `redistribute connected` —
using the v3 NSSA-LSA (function code 0x2007, RFC 5340 §A.4.9) in
place of Type-7. NSSA translation and the translator roles are
BDD-validated for v3 as well.
