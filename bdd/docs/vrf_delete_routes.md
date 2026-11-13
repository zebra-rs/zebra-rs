# Deleting a VRF takes its routes out of the kernel

## Overview

When a VRF device is deleted, the kernel removes the routes through
the VRF's own interfaces along with it, and no others. A route in the
VRF's table that has no interface (a static `nexthop blackhole`), or
one through an interface outside the VRF, stays in the table, and
the next VRF given that table id would inherit it. So zebra-rs
withdraws what it installed in a VRF's table before the VRF goes:
when the VRF is deleted, and when zebra-rs stops and takes the VRF
devices it created with it.

Table ids are handed out lowest first, so the VRF created after the
only one is deleted gets the id that one had: 1.

Topology: r is zebra-rs with one interface in VRF blue.

## Config Files

- r.yaml: VRF blue with lan0 in it, and in the VRF two discard routes and two routes through lan0.
- r_none.yaml: no VRF and no static route.
- r_red.yaml: another VRF, red, with nothing in it.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a router with a VRF and static routes in it | |
| The VRF goes, and its routes with it | |
| Another VRF given the table id starts with none of them | |
| The VRF comes back with its routes | |
| Stopping zebra-rs takes the VRF it created, and its routes | |
| Teardown topology | |
