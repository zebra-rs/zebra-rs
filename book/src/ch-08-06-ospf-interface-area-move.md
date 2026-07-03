# Moving an Interface Between Areas

Because the area is part of the configuration path, moving an
interface from area 0 to area 0.0.0.1 is two operations:

```
no router ospf area 0 interface enp0s6
router ospf area 0.0.0.1 interface enp0s6 enable true
```

zebra-rs handles this internally via a `Disable → Enable` transition
pair (`Message::Disable` followed by `Message::Enable` carrying the
new area-id), which tears down the old IFSM state machine and starts
a fresh one in the new area. No daemon restart is required.

If the same interface name accidentally appears under two areas at
once, the second area's `enable true` wins (the link's
`config.area` is overwritten). This is not a supported configuration
and zebra-rs may add a validation error for it in a future release.
