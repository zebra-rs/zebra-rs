# PIM on a loopback forms no neighbors

## Overview

PIM runs on lo so that the router's own addresses, such as an RP
address, sit on a PIM interface. A loopback has no segment to speak
on: a Hello sent there comes straight back, from whatever source the
kernel picked. 127.0.0.1 is host-scope, so with no address of its own
on lo the kernel takes another interface's, and p1 listed itself as a
neighbor on lo. A configured lo address raced the same way, until its
AddrAdd reached PIM. A loopback is now passive, as in OSPF and IS-IS:
it sends and accepts no Hellos.

## Test Topology

```
    p1 (lo; eth1 10.1.12.1/24) --- veth --- p2 (eth2 10.1.12.2/24)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| p1 runs PIM on lo and meets p2 on eth1 | |
| p1 is not its own neighbor on lo | |
| Teardown topology | |
