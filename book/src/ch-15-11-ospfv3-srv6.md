# SRv6 (RFC 9513)

OSPFv3 can distribute SRv6 reachability natively — a capability
OSPFv2 cannot have (SRv6 is IPv6-only on the wire). zebra-rs
implements RFC 9513: the instance advertises a locator and per-
adjacency End.X SIDs, and installs remote locators learned from the
area.

## Configuration

A locator is defined globally under `segment-routing` and
referenced by name from the OSPFv3 instance:

```
segment-routing {
  locator LOC1 {
    prefix fcbb:bbbb:1::/48;
    behavior usid;
  }
}
router ospfv3 {
  router-id 10.0.0.1;
  segment-routing {
    srv6 {
      locator LOC1;
    }
  }
  area 0 {
    interface lo {
      enabled true;
    }
    interface enp0s6 {
      enabled true;
      network-type point-to-point;
    }
  }
}
```

| YANG leaf | Type | Notes |
|---|---|---|
| `/segment-routing/locator/<name>/prefix` | `inet:ipv6-prefix` | The locator block. |
| `/segment-routing/locator/<name>/behavior` | enum `{ usid }` | `usid` selects RFC 9800 NEXT-C-SID (compressed) behaviors; omit for classic RFC 8986 full-length SIDs. |
| `/router/ospfv3/segment-routing/srv6/locator` | string | Name reference. Deliberately a plain string (not a leafref) so the OSPFv3 config can be staged before the locator is committed; SRv6 activates when the named locator exists with a prefix. |

## What gets advertised

- An **SRv6 Capabilities TLV** in the SR-info E-Router-LSA.
- An **SRv6-Locator-LSA** (LS type `0xA02A`) carrying the locator
  prefix with an **End SID** sub-TLV — behavior `uN` (End with
  NEXT-C-SID) for a uSID locator, plain `End` for classic — plus
  the SID-Structure sub-TLV (`LB/LN/Fun/Arg`).
- **End.X SIDs** for every Full adjacency, carved from the locator
  and carried in the E-Router-LSA's Router-Link TLV (RFC 9513
  §9.1/§9.2) — behavior `uA` for uSID, `End.X` for classic. The
  kernel `seg6local` entries (and, for uSID, the LIB twin at
  `block:function`) are installed automatically.

One operational subtlety is worth knowing: the kernel End.X
nexthop is resolved to the **neighbor's global address**, learned
from the LA-bit /128 in its Link-LSA — a link-local nexthop would
blackhole under Linux `seg6local` semantics. Until the neighbor's
Link-LSA arrives, the entry temporarily uses the Hello link-local
and re-installs itself once the global is known.

## What gets installed

Remote locators from other routers' SRv6-Locator-LSAs are installed
as IPv6 routes at `cost(advertising router) + locator metric` with
the SPF nexthops toward that router — this is what makes the SRv6
forwarding plane converge with the IGP. Deleting the local
`segment-routing srv6 locator` reference flushes the Locator LSA
and withdraws the local SIDs.

## Observing

`show ospfv3 srv6` summarizes the local state (locator, End SID and
behavior, per-adjacency End.X SIDs); `show ospfv3 database detail`
decodes the Locator TLV, End/End.X SID sub-TLVs, and SID structure;
`show segment-routing srv6 sid` lists the installed SIDs with their
owner protocol (`ospfv3`) and behaviors (`uN`/`uA` or
`End`/`End.X`).

## TI-LFA over SRv6

`fast-reroute ti-lfa` combines with the SRv6 dataplane: the repair
path is expressed as an SRv6 SID list (H.Encaps through the
locator/End.X SIDs) instead of an MPLS label stack — no
`segment-routing mpls` or Prefix-SID needed:

```
router ospfv3 {
  segment-routing {
    srv6 {
      locator LOC1;
    }
  }
  fast-reroute {
    ti-lfa;
  }
}
```

`show ospfv3 repair-list detail` shows the repair as `srv6` with
the SID list. Both the uSID and classic-SID variants are
BDD-validated.
