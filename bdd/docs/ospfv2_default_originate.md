# OSPFv2 default-information originate advertises a Type-5 default

## Overview

As a network operator
I want `default-information originate [always]` to advertise a
Type-5 default route (0.0.0.0/0) — unconditionally with `always`,
or tracking the presence of a non-OSPF default route in the RIB
without it — so downstream routers follow the ASBR for everything
off-net.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (ASBR, 10.0.0.2)
                                    default-information originate
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| always originates unconditionally at the configured metric | |
| Without always, the default tracks a non-OSPF default route in the RIB | |
| Teardown topology | |
