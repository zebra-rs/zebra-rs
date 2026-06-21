# VRF L3VPN over SRv6 (End.DT46) dataplane forwarding — v4 + v6

## Overview

Foundation for the Mirror SID live-traffic test, and the VPNv4-over-SRv6
support check: two PEs (z1, z2) run IS-IS L2 SRv6 + iBGP VPNv4/VPNv6,
each with a dual-stack VRF vrf-cust whose v4 and v6 CE prefixes are
carried with the per-VRF End.DT46 service SID (one dual-family SID for
both AFIs). Hosts behind z2 must reach hosts behind z1 over both v4 and
v6 — z2 H.Encaps CE traffic toward z1's End.DT46 SID, z1 decapsulates
into the VRF.
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and confirm IS-IS + BGP VPNv4/VPNv6 | |
| VPNv4 and VPNv6 routes carry SRv6 End.DT46 SIDs | |
| CE-to-CE traffic forwards over the VPNv4/VPNv6 SRv6 dataplane | |
| Teardown topology | |
