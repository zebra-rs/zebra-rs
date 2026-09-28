# A route-target change takes effect on the routes already held (IPv4)

## Overview

As a network operator
I want a VRF's route-target import and export changes to apply to the
VPN routes already in the table
So a VRF imports exactly what its current route-targets select, without
waiting for the routes to be re-sent.

Import route-targets were read only when a route arrived: adding one
imported none of the matching routes already held, and removing one
left the routes it had imported. An export route-target change re-tagged
the VRF's routes for the peers but never re-ran the import, so a sibling
VRF on the same PE kept a route it no longer imports, and one that now
imports it did not get it. The twin is `bgp_vrf_rt_change_v6`.

## Test Topology

```
  pe1 (AS 65000)
    red   RD 65000:1  exports 10.24.1.0/24 with RT 65000:200
    gold  RD 65000:3  exports 10.24.9.0/24 with RT 65000:100
    blue  RD 65000:2  imports 65000:100
    green RD 65000:4  imports 65000:300
```

## Config Files

- pe1.yaml: the four VRFs and their `network` statements.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; blue imports gold's route and not red's | |
| Adding an import route-target imports the matching held route | |
| Removing the import route-target withdraws what it imported | |
| Changing an export route-target moves the route between sibling VRFs | |
| Teardown topology | |
