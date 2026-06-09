# BGP IPv6 redistribute connected with SRv6 End.DT6 origination

## Overview

As a network operator
I want a connected IPv6 prefix redistributed into BGP on an
SRv6-enabled speaker to carry an SRv6 End.DT6 service SID, so a peer
configured for `encapsulation-type srv6` accepts it and the route
reaches the peer's BGP table as an SRv6 service route.

## Test Topology

```
  ┌────────┐  i1 ──────── i1  ┌────────┐
  │   z1   │──────────────────│   z2   │
  │ AS65001│  2001:db8:12::/64│ AS65002│
  │ LOC1   │                  │ encap- │
  │ fcbb:1 │                  │ srv6   │
  └────────┘                  └────────┘
   cust0: 2001:db8:cafe::1/64 (connected, redistributed)
```

## Notes

- z1 advertises SRv6 locator `LOC1` (fcbb:bbbb:1::/48) and enables
  `segment-routing srv6 ipv6-unicast`, so locally-originated IPv6
  unicast routes carry an End.DT6 SID carved from the locator.
- z1 redistributes connected; the dummy `cust0` prefix
  `2001:db8:cafe::/64` is originated into BGP with the SID stamped at
  origination (visible as a "Local SID" in `show bgp ipv6`).
- z2 peers eBGP over IPv6 and sets `encapsulation-type srv6` on the
  session, so it only accepts SID-bearing routes; the redistributed
  prefix arrives carrying the SID (shown as a "Remote SID").

## Config Files

- z1.yaml, z2.yaml

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Redistributed connected IPv6 route carries an End.DT6 Prefix-SID | |
| Teardown topology | |
