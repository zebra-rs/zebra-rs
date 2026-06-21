# IS-IS SRv6 Mirror SID egress protection — control plane + install

## Overview

As a network operator
I want a protector PE to advertise a Mirror SID (SRv6 End.M) for a
primary egress's locator, and a PLR to install an H.Encaps-to-the-
Mirror-SID backup, so that on egress failure traffic can be redirected
to the protector (draft-ietf-rtgwg-srv6-egress-protection).
This feature validates the control + install path that needs no BGP
L3VPN service: advertisement, reception, the protector's End.M localsid
install, and the PLR backup install. The mirror-context table
population (via-vrf) and live traffic failover need a VRF/VPN service
and are covered separately.

## Test Topology

```
    pe1 ──── p1 ──── pea
   (::1)   (::2,PLR)  (::3, protected, fcbb:bbbb:3::/48)
                \    /
                 peb           (::4, protector, fcbb:bbbb:4::/48)
                              Mirror SID fcbb:bbbb:4:1:: protects
                              fcbb:bbbb:3::/48
```

## Notes

All circuits are IS-IS Level-2, point-to-point, SRv6 uSID. p1 reaches
both pea and peb directly, so the backup to peb is valid when pea fails.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and confirm IS-IS + SRv6 convergence | |
| peb advertises the Mirror SID and p1 receives it | |
| peb installs the End.M localsid | |
| p1 installs the PLR Mirror SID backup | |
| peb withdraws the Mirror SID and the PLR backup clears | |
| Teardown topology | |
