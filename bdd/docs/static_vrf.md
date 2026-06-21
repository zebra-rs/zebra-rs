# Static routes inside a VRF (router static vrf NAME)

## Overview

A static route configured under `router static vrf <name>` installs
into that VRF's kernel routing table and forwards traffic. Two hosts
hang off one router's VRF, each reached by a per-VRF static route to
its loopback; a ping between the host loopbacks proves the VRF static
routes are installed and resolving on-link (the gateway sits on a VRF
interface, whose connected route the kernel flushes on enslave — so
this exercises the on-link `ifindex_origin` resolution path).
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and confirm the VRF static routes install | |
| Traffic forwards between the hosts via the VRF static routes | |
| Teardown topology | |
