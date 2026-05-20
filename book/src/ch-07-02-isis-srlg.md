# Shared Risk Link Group (SRLG)

Shared Risk Link Group (SRLG) is a Traffic Engineering attribute that
identifies a set of links that share a common failure risk — typically
a physical conduit, a piece of equipment, or a geographic region. When
a routing protocol advertises SRLG memberships for each of its links,
upstream computations (TI-LFA, RSVP-TE path placement, controller-driven
path computation) can use that information to choose paths that don't
fate-share with the protected primary.

zebra-rs models SRLG as a small per-protocol table owned by the
IS-IS instance and consumed per-interface.

## Configuration

SRLG configuration has two parts, both under `router isis`:

- An IS-IS-owned `srlg` table mapping operator-friendly names to the
  32-bit value carried on the wire.
- A per-interface `srlg` leaf-list under each IS-IS interface, naming
  the groups the link belongs to.

```text
router isis {
  srlg {
    group transit-fiber-a {
      value 100;
    }
    group transit-fiber-b {
      value 200;
    }
    group ducted-trunk {
      value 300;
    }
  }
  interface eth1 {
    srlg {
      transit-fiber-a;
      ducted-trunk;
    }
  }
  interface eth2 {
    srlg {
      transit-fiber-b;
      ducted-trunk;
    }
  }
}
```

In the example above, `eth1` and `eth2` share the `ducted-trunk` risk
even though they leave the chassis on different fibers — anything that
takes out the duct takes out both links. A computation walking the SRLG
attributes from the LSDB will see that the two links are not
fate-independent and pick an alternate accordingly.

## SRLG values

The `value` leaf is mandatory and is the 32-bit identifier advertised
on the wire. The numeric space is operator-defined; zebra-rs does not
enforce uniqueness — two group names can intentionally share a value
(as aliases) or accidentally collide. Two links are in the same shared
risk group iff they carry at least one common SRLG value.

## Staging

The per-interface `srlg` leaf-list holds plain strings, not
`leafref`s. This is intentional: a per-interface SRLG configuration
can be staged before the matching `/router/isis/srlg/group` entry is
committed (and vice versa), matching the pattern already used by
`segment-routing` `block` and `locator` references. Names that don't
resolve at LSP-build time are silently skipped — the LSP carries
whatever subset of names did resolve.

## Wire encoding

IS-IS advertises SRLG memberships in two top-level TLVs, both per-link
and bound to a specific neighbor adjacency:

| TLV | Code | RFC      | Address family |
|---  |---   |---       |---             |
| SRLG       | 138 | RFC 5307 §1   | IPv4 |
| IPv6 SRLG  | 139 | RFC 6119 §3.4 | IPv6 |

Each record carries the neighbor's System ID + pseudonode number, a
flags octet (T-bit for v4: numbered vs unnumbered link), the local and
remote interface addresses, and the list of 32-bit SRLG values. zebra-rs
emits TLV 138 for every up adjacency with at least one resolved SRLG
value, and additionally emits TLV 139 when both endpoints of the link
have IPv6 addresses. Values past the per-TLV cap (59 for v4 / 53 for
v6, derived from the on-wire one-byte length) are split across
additional TLVs of the same code.

## Architecture

The SRLG table lives inside the IS-IS instance and is staged through
the same libyang commit cycle as the rest of `router isis`. Updates
to any `/router/isis/srlg/group/*` leaf are absorbed by an in-memory
builder and applied at `CommitEnd`; if the applied snapshot actually
moved, both LSP levels are re-originated so the new name→value
mapping reaches peers without waiting for the refresh timer.
