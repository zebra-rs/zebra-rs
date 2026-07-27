# EVPN over MPLS advertises a per-EVI service label (RFC 7432)

## Overview

As a network operator running EVPN's L2 services over an MPLS core
I want each PE to advertise its EVI with an MPLS service label and to
program the matching decap, so a remote PE knows what to impose on frames
toward this one — the control plane behind the eBPF data path that
forwards it.
Test topology (control plane only — no CEs, no bridges, no forwarding):
```
┌─────────────────────────────────────────┐
│                   br0                   │
└─────────────┬───────────────┬───────────┘
```
What distinguishes MPLS from the VXLAN and SRv6 encapsulations, and what
this feature pins:
- The EVI is *declared*, not inferred. VXLAN and SRv6 read a local VXLAN
- The Type-3 IMET carries an MPLS **label** in its PMSI, not a VNI, and
- The next hop and PMSI tunnel identifier are the router-id, not a VTEP.
- No Encapsulation extended community is attached: RFC 8365 section 5.1.3
- A decap ILM is programmed at the service label so a remote PE's frame
Type-2 (MAC/IP) needs a datapath MAC learn and is covered by the
cradle-rs `cradle_evpn_mpls_zebra` feature, which drives this same control
plane with a real eBPF data plane and CE-to-CE traffic.

## Notes

What distinguishes MPLS from the VXLAN and SRv6 encapsulations, and what
this feature pins:
- The EVI is *declared*, not inferred. VXLAN and SRv6 read a local VXLAN
  device's VNI; an MPLS EVI has no VNI, so `evi 100 bridge br100` is what
  tells the PE this L2 service exists at all.
- The Type-3 IMET carries an MPLS **label** in its PMSI, not a VNI, and
  the label is a different number from the EVI id (it comes from the
  dynamic block, so it is deliberately NOT asserted as a literal).
- The next hop and PMSI tunnel identifier are the router-id, not a VTEP.
- No Encapsulation extended community is attached: RFC 8365 section 5.1.3
  makes MPLS the default and signals it by that EC's *absence*, so its
  presence would be the bug.
- A decap ILM is programmed at the service label so a remote PE's frame
  pops into bridge domain 100. It is cradle-only — the kernel has no
  action that pops a label into a bridge — so `show mpls ilm` is the only
  place it is observable without a data plane.
Type-2 (MAC/IP) needs a datapath MAC learn and is covered by the
cradle-rs `cradle_evpn_mpls_zebra` feature, which drives this same control
plane with a real eBPF data plane and CE-to-CE traffic.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN session | |
| Each PE originates a Type-3 IMET for its declared EVI | |
| The IMET reaches the far PE with an MPLS label, not a VNI | |
| The route target carries the EVI and no encapsulation EC is set | |
| Each PE programs a bridge-domain decap ILM for its EVI | |
| Teardown topology | |
