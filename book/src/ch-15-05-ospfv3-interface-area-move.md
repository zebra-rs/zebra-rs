# Moving an Interface Between Areas

As in OSPFv2, the area is part of the configuration path, so moving
an interface from area 0 to area 0.0.0.1 is two operations:

```
no router ospfv3 area 0 interface enp0s6
router ospfv3 area 0.0.0.1 interface enp0s6 enable true
```

Internally this is the same `Disable → Enable` transition pair as
v2: the delete clears the interface's enable flag and cached
area and tears down its IFSM; the set under the new area starts a
fresh IFSM there. The v3 cascade re-originates the affected LSAs —
the old area loses the link from its Router-LSA and the prefixes
from its Intra-Area-Prefix-LSA, the new area gains them, and the
link-scoped Link-LSA re-originates on the fresh interface state. No
daemon restart is required.

The same caveat as v2 applies if one interface name accidentally
appears under two areas at once: the last-applied `enable true`
wins, because the link's cached area is a single value. This is not
a supported configuration.
