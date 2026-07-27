# Graceful Restart advertises a usable Restart Time

## Overview

As a network operator
I want a graceful-restart-enabled neighbor to advertise a sane RFC
4724 Restart Time, so a helper retains routes across a real restart.

## Test Topology

```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
```

## Notes

Both enable `afi-safi ipv4 graceful-restart`. Review finding #15: the
enable marker stored `1`, advertised verbatim as the Restart Time, so
a helper flushed retained routes after ~1s — no forwarding continuity.
The default is now 120s.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup and establish the session | |
| The advertised/received Restart Time is the sane default, not 1 | |
| Teardown topology | |
