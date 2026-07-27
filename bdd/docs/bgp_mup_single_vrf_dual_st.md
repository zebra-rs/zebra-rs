# One MUP VRF binds both st1 and st2 and originates both ST routes

## Overview

As a network operator running a UPF with a single N6 interface (issue
#1947), I want ONE `router bgp vrf` to bind BOTH `afi-safi mup route st1`
(downlink) and `afi-safi mup route st2` (uplink) to the same Network
Instance — so a single PFCP/N4 session originates the Type-1 ST (UE
prefix + access tunnel) AND the Type-2 ST (core endpoint + GTP TEID)
under ONE RD, instead of requiring two single-direction VRFs (and with
them two N6-facing interfaces).

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ MUP-C   │ iBGP│ receiver│
           │192.168. │◄───►│192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴──────┐
           │ pfcp-inject│  (SMF simulator, run in z1)
           └───────────┘
```

## Notes

z1 runs the controller (PFCP listener on 192.168.0.1:8805, locator LOC1)
with a SINGLE VRF `mobile` (rd 65000:1) whose `afi-safi mup` block binds
both `route st1` and `route st2` (the st2 entry carrying Direct segment
id `1:2`) to Network Instance `internet`. `pfcp-inject` plays the SMF: it
sends an Association Setup + Session Establishment for UE 192.0.2.5 with
an ACCESS-side F-TEID (gNB endpoint 10.0.0.1 / TEID 0x12345678) and a
CORE-side F-TEID (endpoint 10.9.0.1 / TEID 0x87654321), Network Instance
`internet`. z1 originates BOTH Session-Transformed routes from the one
VRF — both under rd 65000:1 — and advertises them to z2.

NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
`cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish iBGP session with MUP capability | |
| One PFCP session originates both STs from the single dual-direction VRF | |
| Teardown topology | |
