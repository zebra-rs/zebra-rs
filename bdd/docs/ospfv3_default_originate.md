# OSPFv3 default-information originate advertises an AS-External default

## Overview

As a network operator
I want `default-information originate [always]` on OSPFv3 to
advertise an AS-External default (::/0) — unconditionally with
`always`, or tracking a non-OSPF default route in the RIB without
it — mirroring ospfv2_default_originate.

## Test Topology

```
    a -- 2001:db8:12::/64 -- b (ASBR)
                             default-information originate
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| always originates unconditionally at the configured metric | |
| Without always, the default tracks a non-OSPF default route in the RIB | |
| Teardown topology | |
