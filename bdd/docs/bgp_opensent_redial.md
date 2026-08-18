# A BGP connection lost in OpenSent redials on the idle-hold pacer

## Overview

As a network operator
I want a peer whose TCP connection dies after it has sent its OPEN to
redial on the short idle-hold pacer rather than the ConnectRetryTimer,
so a transient failure costs seconds instead of minutes.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   h1    │
           │ zebra-rs│     │ scripted│
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │ 40.1/24 │     │ 40.2/24 │
           └─────────┘     └─────────┘
```

## Notes

`fsm_conn_fail`'s OpenSent arm used to restart the full
ConnectRetryTimer, while its Connect-state sibling `fsm_dial_fail` uses
the idle-hold pacer. A peer that lost its TCP after sending OPEN
therefore sat in Active for up to a ConnectRetryTime — two minutes on
the old 120s default — before trying again. In the wild that window is
reached by an RFC 4271 §6.8 collision, where the loser's connection dies
precisely after it has sent its OPEN.

h1 runs tests/scripts/bgp_opensent_reset.py, which makes that
non-deterministic case deterministic: it accepts the DUT's first
connection, waits for the OPEN so the DUT is provably in OpenSent, then
aborts with RST; every later connection it serves as a normal speaker.
So the time from reset to Established is exactly the redial pacer.

z1.yaml pins connect-retry-time to 120s, an order of magnitude above the
5s idle-hold default, so the 30s polling assert below can only be
satisfied by the idle-hold pacer — and the test does not depend on what
the ConnectRetryTime default happens to be.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The session establishes after a reset taken in OpenSent | |
| Teardown topology | |
