# OSPFv2 graceful restart keeps forwarding through a daemon restart

## Overview

As a network operator
I want zebra-rs to implement RFC 3623 graceful restart — the helper
holding a restarting neighbor's adjacency past the dead interval, and
the restarter checkpointing its LSDB, exiting, and resuming inside
the grace window — so that a planned restart does not disturb
forwarding.

Two routers on a point-to-point link: a is the helper, b the
restarter. The first scenario stages a restart and aborts it,
proving the Grace-LSA drives helper entry on a. The second commits
the restart: b's daemon exits, a holds the adjacency and the route
well past the 40s dead interval, and b resumes from its checkpoint.

## Test Topology

```
    a (helper, 10.0.0.1) -- 10.0.12.0/30 -- b (restarter, 10.0.0.2)

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
```

## Notes

The restarter's checkpoint lands at the fixed path
/var/lib/zebra-rs/checkpoint/ospf.cbor, which is shared by every
namespace (netns does not isolate the filesystem). The restarted
daemon deletes it after a successful load, but each scenario also
removes it defensively so an aborted run can never poison a later
zebra-rs start (any OSPF instance started within 1.5x the grace
period would replay it).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Grace-LSA from a staged restart drives helper entry; abort recovers | |
| Committed restart survives past the dead interval and resumes from the checkpoint | |
| Teardown topology | |
