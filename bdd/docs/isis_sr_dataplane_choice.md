# IS-IS segment-routing mpls/srv6 are mutually exclusive (YANG choice)

## Overview

As a network operator
I want `router isis segment-routing mpls` and `router isis
segment-routing srv6` to be a YANG choice, so committing one
dataplane implicitly deletes the other (RFC 7950 §7.9.3) — a single
`set router isis segment-routing srv6 locator LOC1` migrates a
running SR-MPLS node to SRv6 without a separate `delete`, and the
implicit delete tears the old dataplane's forwarding state down
exactly as an explicit one would.
z1 and z2 run dual-stack IS-IS L2 over one point-to-point link, both
starting on SR-MPLS (Prefix-SID indexes 100/200 -> labels
16100/16200 against the default SRGB base 16000). z1 additionally
pre-provisions the global SRv6 locator LOC1 (fcbb:bbbb:1::/48)
without binding it to IS-IS. The feature flips z1's dataplane to
SRv6 and back with one `set` each way and checks three layers every
time:
- config: `show running-config formal` holds exactly one dataplane
- local forwarding: the MPLS ILM empties and the locator's End SID
- the peer: z2 stays on SR-MPLS throughout, and label 16100 leaves

## Test Topology

```
   z1 ──────────────── z2
   10.0.12.1/24        10.0.12.2/24
   2001:db8:0:12::1/64 2001:db8:0:12::2/64
   lo 10.0.0.1, 2001:db8::1, SID 100, LOC1 fcbb:bbbb:1::/48 (unbound)
   lo 10.0.0.2, 2001:db8::2, SID 200 (SR-MPLS for the whole feature)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the dual-stack SR-MPLS topology | |
| Setting srv6 implicitly deletes mpls and swaps the dataplane | |
| Setting mpls implicitly deletes srv6 and restores the labels | |
| Teardown topology | |
