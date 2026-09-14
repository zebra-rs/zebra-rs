# LLGR stale VPNv6 rows expire after the stale time when the peer never returns

## Overview

As a network operator
I want a peer's long-lived-graceful-restart stale routes to be swept
when the stale time elapses, so a peer that goes down for good does
not leave its routes selected, installed and advertised forever.

## Test Topology

```
  z1 (AS 64512) ──iBGP (vpnv6)── z2
  192.168.0.1/24                 192.168.0.2/24
```

## Notes

Both ends enable `long-lived-graceful-restart` for the family with a
10-second stale time. z1 originates one route. When z1's daemon is
stopped, z2 retains the route stale (RFC 9494) — and must sweep it
once the 10 seconds are up. Review finding #9: the only stale sweeper
walked the VPNv4 table, so stale VPNv6 rows never expired.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the session | |
| z2 holds z1's route | |
| z1 dies for good and its stale route is swept after the stale time | |
| Teardown topology | |
