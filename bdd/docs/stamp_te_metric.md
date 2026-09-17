# STAMP link-delay measurement feeding IGP TE metrics

## Overview

As a network operator running delay-based traffic engineering, I want
each P2P link's delay measured actively (STAMP, RFC 8762) and the
damped min/max/avg values advertised by the IGPs — IS-IS RFC 8570 and
OSPFv2 RFC 7471 link-delay sub-TLVs — without configuring static
te-metric values per link.

Two zebra-rs instances share one P2P link. Both run IS-IS and OSPFv2
on it with `te-metric measurement` enabled (probe interval 100 ms,
damping period 2 s — lab values; defaults are 1 s / 30 s). Each
daemon's STAMP Session-Sender probes its neighbor's implicit
Session-Reflector; both IGPs share the one measurement session per
link (multi-client). After the first damping period the measured
values appear as "Min/Max Unidirectional Link Delay" in both LSDBs
(the OSPF Extended-Link Opaque LSA is gated on segment-routing mpls).

The later scenarios drive the Anomalous (A) bit. A threshold low
enough that any real delay crosses it must raise the bit on the
configuring IGP's delay sub-TLVs and only there — the two IGPs share
one STAMP session but configure the policy separately — and raising
the bound again must clear it even though the delay values themselves
never moved.

Topology:

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the measured topology | |
| STAMP sessions form and measure the link | |
| IS-IS advertises the measured link delay | |
| OSPFv2 advertises the measured link delay | |
| An IS-IS-only threshold raises the bit on IS-IS alone | |
| Configuring OSPF's own threshold raises its bit too | |
| An unrelated timing edit must not clear a standing anomaly | |
| Raising the thresholds clears the bits again | |
| Teardown topology | |
