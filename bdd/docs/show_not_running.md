# A show command for a subsystem that is not running names it

## Overview

A show command goes to the task that serves it. When that task is not
running, the daemon answers "<name> is not configured or running".
The names sat in a list of their own, apart from the routing, which
missed two subsystems: `show ebpf` without the eBPF data plane, and
`show pim`, `show igmp` or `show mroute` without PIM, all read
"Unknown protocol is not configured or running". The names now come
from the routing table itself.

## Test Topology

```
   z1   (nothing configured: no protocol and no eBPF data plane runs)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Start the daemon with nothing configured | |
| show ebpf without the eBPF data plane names it | |
| show pim, igmp and mroute without PIM name it | |
| Teardown topology | |
