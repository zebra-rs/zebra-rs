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
Topology:

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the measured topology | |
| STAMP sessions form and measure the link | |
| IS-IS advertises the measured link delay | |
| OSPFv2 advertises the measured link delay | |
| Teardown topology | |
