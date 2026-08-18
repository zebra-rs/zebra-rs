# IS-IS Hello padding fills the interface MTU exactly, with padding-size and padding disable as the mismatch escape hatches

## Overview

As a network operator
I want IS-IS Hellos padded to exactly the interface MTU (and no further),
so an adjacency only forms when the link really carries full-MTU PDUs in
both directions — and when the peer's MTU accounting disagrees with mine,
I want `hello padding-size <bytes>` to pad to the exact frame length the
peer accepts (the number read straight out of a capture), or
`hello padding disable` to skip the probe entirely.

Wire arithmetic this feature pins down (the recurring interop question):
the padder fills the IIH PDU to MTU - 3, the send path prepends the
3-byte LLC header (FE FE 03), so the Ethernet payload is EXACTLY the
interface MTU, and a capture shows MTU + 14 (Ethernet header; +4 more
with FCS on a physical wire). MTU 1600 here means 1614-byte frames in
tcpdump — precisely as MTU 4096 means 4110-byte frames. That is correct
under Linux/IETF MTU semantics (MTU = max L2 payload); a peer whose
configured "MTU" counts the Ethernet header and FCS inside the number
(media-MTU semantics, 18 bytes of overhead) will both send smaller
padded Hellos and DROP ours as giants, exactly like a receiver whose
kernel MTU is simply lower — which is how the mismatch scenario below
models it.

## Test Topology

```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
```

## Notes

Both routers are level-2-only on a broadcast (LAN) circuit with 1 s
Hellos and hold-time 5 s, so MTU-change fallout lands within seconds.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Matched MTUs — Hellos are padded to exactly MTU + 14 on the wire and the adjacency forms | |
| Receiver with a smaller MTU silently drops the padded Hellos — adjacency refuses to form while ordinary traffic still flows | |
| hello padding-size pads to an explicit wire length the smaller-MTU peer accepts | |
| hello padding disable on the big-MTU side brings the adjacency back up | |
| Teardown topology | |
