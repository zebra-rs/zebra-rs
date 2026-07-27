# OSPFv3 graceful restart keeps forwarding through a daemon restart

## Overview

As a network operator
I want zebra-rs OSPFv3 to implement RFC 5187 graceful restart in
both roles — the helper holding a restarting neighbor's adjacency
past the dead interval, and the restarter checkpointing its LSDB,
exiting, and resuming inside the grace window — mirroring
ospfv2_graceful_restart over the v3 Grace-LSA (0x000B).

## Test Topology

```
    a (helper, 10.0.0.1) -- 2001:db8:12::/64 -- b (restarter, 10.0.0.2)
```

## Notes

The restarter's checkpoint lands at the fixed path
/var/lib/zebra-rs/checkpoint/ospfv3.cbor, shared by every namespace
(netns does not isolate the filesystem); each scenario removes it
defensively so an aborted run can never poison a later start.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Grace-LSA from a staged restart drives helper entry; abort recovers | |
| Committed restart survives past the dead interval and resumes from the checkpoint | |
| Teardown topology | |
