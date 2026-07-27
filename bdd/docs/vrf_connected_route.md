# A VRF interface's connected route lands in the VRF table

## Overview

When an interface is enslaved to a VRF and carries an IPv4 address,
the connected route derived from that address must be installed into
the VRF's routing table — not the default table. The interface is
enslaved asynchronously (the kernel acknowledges `master` via a later
RTM_NEWLINK), so the connected route is often first filed in the
default table and must be re-homed onto the VRF table once the enslave
is observed. Regression test for: connected route shown in
`show ip route` but missing from `show ip route vrf <name>`.
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Connected route of a VRF interface is in the VRF table only | |
| Teardown topology | |
