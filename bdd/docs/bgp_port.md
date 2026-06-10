# BGP on a non-default TCP port

## Overview

As a network operator
I want `router bgp port <0-65535>` and `neighbor X port <1-65535>`
So sessions can run on a non-179 port, and a router can refuse all
inbound BGP by closing its listener (`port 0`).

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65003 │
   │  .0.1   │                  │.0.2 .1.2│                  │  .1.3   │
   └─────────┘                  └─────────┘                  └─────────┘
```

## Notes

z1—z2 exercises the two port knobs together: z2 listens on TCP 1790
(`port: 1790`) and z1 dials it (`neighbor 192.168.0.2 port 1790`).
Both ends pin the connection direction so the assertion on the ports
is deterministic: z1 runs `port: 0` (its dial works fine without any
listener, and z2's racing dial toward z1:179 is refused) and z2 is
passive toward z1. The only session that can exist is the one z1
opened toward 1790. z1 originates 10.10.0.1/32 to prove routes flow
over it.
z2—z3 exercises `port 0` on the accept side: z3 starts with
`port: 0` (no listener) and is passive toward z2, so z2's dials to
z3:179 are refused and the session must stay down. Re-configuring z3
to `port: 179` reopens the listener at runtime; a `clear` on z2 then
redials immediately (a refused connect otherwise parks the peer on
the 120s connect-retry timer) and the session establishes — the
close-and-reopen path of a runtime port change.
Config application order matters once: z3's `port: 0` is applied
before z2's config exists, so z2 never catches the small window
between z3's daemon start (default listener on 179) and the apply.

## Config Files

- z1.yaml: `port: 0`; neighbor z2 with `port: 1790`; originates
- z2.yaml: `port: 1790` listener; passive toward z1; active toward z3
- z3.yaml: `port: 0` (no listener); passive toward z2
- z3-listen.yaml: same as z3.yaml with `port: 179` (reopen listener)

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup line topology with custom ports | |
| Session between z1 and z2 runs on TCP 1790 | |
| port 0 closes the listener so the z2-z3 session stays down | |
| Changing the port reopens the listener and the session comes up | |
| Teardown topology | |
