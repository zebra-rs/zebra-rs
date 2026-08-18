# BGP MUP Direct segment in the N6 VRF, ST2 in the N3 VRF

## Overview

As a network operator
I want the `mup-ext-comm` correlation to work across VRFs — a Type-2
Session-Transformed (ST2) route originated by the RAN-facing N3 VRF
resolving to the Direct Segment Discovery (DSD) route originated by the
internet-facing N6 VRF — because the segment an ST2 resolves to selects
the table its uplink traffic is looked up in after GTP decap: the Direct
segment must live in the N6 routing context so internet-bound subscriber
packets never route through the RAN-facing N3 table. This is the two-VRF
example in the BGP MUP book chapter (ch-02-35).

## Test Topology

```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ UPF +    │   iBGP (mup)    │ interwork│
       │ MUP-C    │                 │  (SRGW)  │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
```

## Notes

z1 is a combined UPF + controller with the book's two-VRF split: VRF N3
(rd 65000:100, `encapsulation srv6`) holds `route st2 network-instance
core mup-ext-comm 1:2`; VRF N6 (rd 65000:200, `encapsulation srv6`)
holds `segment direct mup-ext-comm 1:2`. One `pfcp-inject` session on
Network Instance `core` originates the ST2 under N3's RD; the DSD
originates under N6's RD. z2 (`afi-safi mup segment interwork`) receives
both and resolves the ST2 to the N6 Direct segment purely by the shared
Direct-segment id 1:2 — across VRFs and RDs.

NOTE: needs `pfcp-inject` on the BDD host PATH (cargo build --release -p
pfcp-inject; copy to /usr/bin) and root netns (kernel VRF + seg6local).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and establish iBGP with the MUP capability | |
| One PFCP session originates the ST2 under N3's RD, the DSD under N6's | |
| z2 (interwork) resolves the N3 ST2 to the N6 Direct segment across RDs | |
| Teardown topology | |
