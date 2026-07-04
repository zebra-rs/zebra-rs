# Multi-Area Routing and the ABR

A router with enabled interfaces in two or more areas is an Area
Border Router, exactly as in OSPFv2: ABR status is derived from the
`area` list, the B-bit is set in every attached area's Router-LSA,
and inter-area origination follows automatically — there is nothing
to configure.

```
router ospfv3 {
  router-id 10.0.0.1;
  area 0 {
    interface lo {
      enabled true;
    }
    interface enp0s6 {
      enabled true;
      network-type point-to-point;
    }
  }
  area 0.0.0.1 {
    interface enp0s7 {
      enabled true;
      network-type point-to-point;
    }
  }
}
```

The instance originates one Router-LSA per attached area (RFC 5340
§3.4.3) and keeps a per-area route slice; the ABR condenses each
area's slice into the other areas using the v3 LSA equivalents of
OSPFv2's summaries:

- **Inter-Area-Prefix-LSAs** (`0x2003`, the Type-3 equivalent) carry
  the prefixes. The direction rules are the OSPFv2 ones (RFC 2328
  §12.4.3): intra-area routes of any attached area are summarized
  into every other; inter-area routes only from the backbone into
  non-backbone areas (the split-horizon that makes the backbone
  mandatory); a prefix the destination area reaches intra-area is
  skipped; the lowest metric wins; `no-summary` areas
  (totally-stubby / totally-NSSA) receive none. Origination is
  diff-gated against the LSDB, so a converged topology re-floods
  nothing.
- **Inter-Area-Router-LSAs** (`0x2004`, the Type-4 equivalent)
  advertise reachability to ASBRs whose Router-LSA E-bit the other
  areas cannot see, carrying the ABR's SPF cost to the ASBR. On the
  consuming side, AS-External route computation falls back to them
  when the ASBR is not in the local area's SPF (RFC 2328 §16.4
  step 5), using `cost-to-ABR + LSA metric` and picking the
  cheapest advertising ABR — which is what makes E1 external
  metrics and cross-area external reachability come out right.

Receivers install inter-area routes per RFC 2328 §16.2: for each
Inter-Area-Prefix-LSA whose advertising ABR is reachable in the
area's SPF, the prefix goes in at `cost-to-ABR + LSA metric` with
the ABR's nexthops, at inter-area preference (intra-area beats
inter-area beats external, §16.4.1). Self-originated LSAs are
skipped, which together with the diff-gating prevents any
SPF → summary → SPF loop.

Unlike v2's `Summary-LSA`, the v3 Link-State ID carries no
addressing semantics — zebra-rs derives it from a hash of the full
prefix (the same scheme the v3 NSSA and AS-External originators
use), and the prefix itself rides in the LSA body.

The whole path — two ABRs, three areas, cross-area reachability in
both directions, and cost-honoring metrics — is BDD-validated by
`ospfv3_multi_area.feature`, the v6 mirror of the v2 multi-area
topology. For the v2 behavior this chapter mirrors, see
[Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md).

## Area ranges

`area <id> range <prefix>` aggregates exactly as in OSPFv2 — the
area's intra-area components fold into one Inter-Area-Prefix-LSA at
the largest component metric (or a fixed `cost`), `not-advertise`
hides the whole range, and the most-specific range wins:

```
router ospfv3 {
  area 0.0.0.1 {
    range 2001:db8:1::/48;
    interface enp0s7 {
      enabled true;
    }
  }
}
```

The `not-advertise` and `cost` leaves match
[the v2 page's table](ch-08-14-ospf-multi-area-abr.md). The
loop-safety [discard route](ch-08-14-ospf-multi-area-abr.md#discard-route)
for active ranges is installed identically — a `nexthop blackhole`
covering the aggregate, withdrawn when the range empties:

```
$ ip -6 route show 2001:db8:1::/48
blackhole 2001:db8:1::/48 proto ospf
```
