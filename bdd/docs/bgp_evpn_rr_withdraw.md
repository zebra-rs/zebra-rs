# EVPN route reflector propagates a client's withdraw

## Overview

As a network operator
I want an EVPN route reflector to forward a client's withdraw to the
other clients, so nobody keeps forwarding to a departed host's VTEP.

## Test Topology

```
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │     z1      │ EVPN │     z2      │ EVPN │     z3      │
  │  AS 65001   │◀───▶│  AS 65001   │◀───▶│  AS 65001   │
  │ vrf-blue    │ iBGP │   route     │ iBGP │  (client)   │
  │ RD 65001:100│      │  reflector  │      │             │
  │ Type-5 from │      │  (both are  │      │             │
  │ 10.1.0.0/24 │      │   clients)  │      │             │
  └─────────────┘      └─────────────┘      └─────────────┘
   192.168.0.1          192.168.0.2          192.168.0.3
```

## Notes

z1 originates an EVPN Type-5 for 10.1.0.0/24 (`evpn advertise-ipv4`);
z2 reflects it to z3. Review finding #5: a received EVPN withdraw
removed the route from the reflector's Loc-RIB but was never fanned
to other peers — z3 kept the stale route (and its VTEP forwarding
state) until its session bounced.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| The reflector reflects z1's Type-5 to z3 | |
| z1's withdraw reaches z3 through the reflector | |
| Re-advertising the network reaches z3 again | |
| Teardown topology | |
