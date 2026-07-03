# BFD

OSPFv3 attaches a [BFD](ch-10-00-bfd.md) session to each neighbor
so a forwarding-path failure tears the adjacency down in sub-second
time instead of waiting for the dead interval; on a BFD `Down`
event the neighbor is brought down through the same path as a
dead-timer expiry (RFC 5882 §5), which re-runs SPF.

The configuration is the same flat `bfd` block as OSPFv2, on the
interface entry (with instance-level defaults available under
`router ospfv3 bfd`):

```
router ospfv3 {
  area 0 {
    interface enp0s6 {
      enable true;
      network-type point-to-point;
      bfd {
        enable true;
      }
    }
  }
}
```

The knobs — `enable`, `min-neighbor-state` (default `two-way`),
`echo-mode`, `echo-transmit-interval` / `echo-receive-interval`
(default 50 ms), `detect-offload` — are shared with the v2 page;
see [OSPF BFD](ch-08-02-ospf-bfd.md) for their semantics.

The v3 specifics: sessions run over the neighbors' **IPv6
link-local addresses** (still always single-hop), and Echo mode
supports IPv6, including the XDP-offloaded echo path. Session state
is visible under `show bfd session` with the OSPFv3 client listed
as the owner.
