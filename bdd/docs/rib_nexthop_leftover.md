# Next-hop objects an earlier run left in the kernel

## Overview

A run of zebra-rs that stops without withdrawing its routes, a crash
say, leaves them in the kernel with the next-hop objects they forward
through. The next run keeps those objects' ids from its own (#2463) and
replaces or sweeps the routes. Once the leftover sweep is done, it
deletes the objects nothing names any more; they used to stay for good.
One a route still forwards through is kept, as deleting it would take
the route with it, and so are a kept group's members.

## Test Topology

```
   z1 (vz1ns 192.168.0.1/24) ── br0
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A crashed run's objects go once nothing forwards through them | |
| An object a route still forwards through is kept, with its group's members | |
| Teardown topology | |
