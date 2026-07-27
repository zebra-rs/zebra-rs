# OSPFv3 segment-routing mpls/srv6 are mutually exclusive (YANG choice)

## Overview

As a network operator
I want `router ospfv3 segment-routing mpls` and `router ospfv3
segment-routing srv6` to be a YANG choice, so committing one
dataplane implicitly deletes the other (RFC 7950 §7.9.3) — a single
`set router ospfv3 segment-routing srv6 locator LOC1` migrates a
running RFC 8666 SR-MPLS node to RFC 9513 SRv6 without a separate
`delete`, and the implicit delete tears the old dataplane's
forwarding state down exactly as an explicit one would.
This is the OSPFv3 sibling of @isis_sr_dataplane_choice — the choice
enforcement is the same generic candidate-store purge, but the
daemon-side effects it must drive are OSPFv3's own: the Prefix-SID
sub-TLVs leave the E-LSAs and the ILM empties, while the SRv6
Locator LSA is originated and the locator's End SID installs as a
kernel seg6local route.
z1 and z2 run OSPFv3 area 0 over one point-to-point link, both
starting on SR-MPLS (Prefix-SID indexes 100/200 -> labels
16100/16200 against the default SRGB base 16000). z1 additionally
pre-provisions the global SRv6 locator LOC1 (fcbb:bbbb:1::/48,
classic full-length SIDs) without binding it to OSPFv3. The feature
flips z1's dataplane to SRv6 and back with one `set` each way and
checks three layers every time:
- config: `show running-config formal` holds exactly one dataplane
- local forwarding: the MPLS ILM empties and the locator's End SID
- the peer: z2 stays on SR-MPLS throughout; label 16100 leaves and

## Test Topology

```
   z1 ──────────────── z2
   2001:db8:12::1/64   2001:db8:12::2/64
   lo 2001:db8::1, SID 100, LOC1 fcbb:bbbb:1::/48 (unbound)
   lo 2001:db8::2, SID 200 (SR-MPLS for the whole feature)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the OSPFv3 SR-MPLS topology | |
| Setting srv6 implicitly deletes mpls and swaps the dataplane | |
| Setting mpls implicitly deletes srv6 and restores the labels | |
| Teardown topology | |
