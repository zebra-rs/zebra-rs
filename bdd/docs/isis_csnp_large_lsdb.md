# IS-IS CSNP/PSNP with a large LSDB (>15 LSP entries)

## Overview

Regression for a TLV 9 (LSP Entries) length-byte overflow. The
LspEntries TLV's Length field is a single octet and each entry is 16
bytes, so at most 255 / 16 = 15 entries fit in one TLV. The CSNP and
PSNP builders, however, sized a single TLV by the MTU budget
(available_len / 16 ≈ 90 entries at a 1500-byte MTU) rather than by
that 15-entry ceiling. Once an LSDB held 16 or more LSPs the length
byte wrapped modulo 256 (16 entries -> 256 -> length 0) while every
entry was still emitted, so the receiver mis-framed the CSNP/PSNP and
the DIS-driven database synchronisation was corrupt on the wire. The
fix caps each LspEntries TLV at MAX_ENTRIES (15); larger LSDBs simply
span more CSNP/PSNP PDUs.
This is hard to trigger with a router-per-LSP topology (16+ daemons),
so instead z1 is given a tight lsp-mtu-size and ~600 IPv4 networks: its
self-LSP fragments into ~15-20 LSP fragments, each a distinct LSP in
the LSDB. On the broadcast LAN the elected DIS must therefore list well
over 15 LSPs in its periodic CSNP. z3 is then brought up *after* z1 and
z2 have converged, so it must learn the established multi-fragment LSDB
through the DIS's CSNP (and PSNP requests) rather than from the initial
flood — making the CSNP path load-bearing.

## Test Topology

```
    z1 (10.255.0.1/32, ~600 nets, lsp-mtu 400)
    z2 (10.255.0.2/32)   -- come up together, converge --
    z3 (10.255.0.3/32)   -- joins late, syncs via the DIS CSNP --
```

## Notes

Note: the deterministic byte-level regression for the length-byte wrap
is the `isis-packet` unit test `lsp_entries_over_max_wraps_length_byte`
/ `lsp_entries_at_max_round_trips_with_exact_length`. This feature is
the live-daemon counterpart: it drives csnp_generate / the PSNP builder
with a >15-entry LSDB and proves a late joiner fully synchronises.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup — z1 (fragmented) and z2 converge on the LAN | |
| z1's self-LSP fragments into a large (>15-LSP) LSDB | |
| z2 synchronises the whole LSDB, including z1's highest fragment | |
| A late joiner learns the established large LSDB via the DIS CSNP | |
| Teardown topology | |
