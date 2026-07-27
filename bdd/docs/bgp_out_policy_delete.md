# Deleting an outbound route-policy re-advertises the suppressed routes

## Overview

As a network operator
I want removing a neighbor's `afi-safi ipv4 policy out` binding to
re-advertise the routes that policy was suppressing.

## Test Topology

```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
```

## Notes

z1 originates 10.0.0.1/32 and 10.0.0.2/32. With `policy out DENY-ALL`
bound toward z2, neither reaches z2. Review finding #12: deleting that
binding left z1's cached out-policy snapshot still denying everything
and never re-advertised — z2 stayed route-less until a new policy name
was bound.

## Config Files

- z1-deny.yaml: z1 with `afi-safi ipv4 policy out DENY-ALL`.
- z1-nopolicy.yaml: same, minus the policy binding (the delete diff).
- z2.yaml: plain AS65002 peer.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; the out-policy denies both routes to z2 | |
| Deleting the out-policy re-advertises both routes | |
| Re-binding the out-policy denies them again | |
| Teardown topology | |
