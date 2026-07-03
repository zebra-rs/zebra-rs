# Area Configuration

An OSPFv2 instance is organized as a list of areas, each carrying the
list of interfaces that belong to it. A router participating in the
backbone and one non-backbone area looks like this:

```
router ospf {
  router-id 10.0.0.1;
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
  area 0.0.0.1 {
    interface enp0s7 {
      enable true;
    }
  }
}
```

Because the area is part of the configuration path, there is no
ambiguity about which area an interface serves — the parent list
entry decides it. Re-homing an interface is a delete-and-add across
two list entries; see
[Moving an Interface Between Areas](ch-08-06-ospf-interface-area-move.md).

## Area identifier — decimal or dotted-quad

The `area` list key is a union of `uint32` and `inet:ipv4-address`,
so both spellings are accepted and they normalize to the same 32-bit
area ID:

```
area 0           # backbone (0.0.0.0)
area 0.0.0.0     # backbone (equivalent)
area 1           # non-backbone (0.0.0.1)
area 0.0.0.1     # non-backbone (equivalent)
```

Internally the area ID is always a 32-bit value matching the on-the-
wire `Area ID` field of OSPFv2 headers (RFC 2328 §A.3.1). Dotted-quad
is the canonical rendering in `show` output regardless of how the
operator wrote it.

| YANG leaf | Type | Notes |
|---|---|---|
| `/router/ospf/area/<id>/area-id` | `union { uint32; ipv4-address }` | List key — see above. |
