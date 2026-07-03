# Per-Interface Configuration

Each `interface` entry under an area carries the standard set of
per-link OSPF tuning parameters. All values match the defaults from
RFC 2328 Appendix C ("Configurable Parameters") except where noted.
The per-link timers (`hello-interval`, `dead-interval`,
`retransmit-interval`) are covered separately in
[Timer Configuration](ch-08-08-ospf-timers.md).

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/ospf/area/<id>/interface/<n>/enable` | `false` | — | boolean |
| `/router/ospf/area/<id>/interface/<n>/network-type` | `broadcast` | `broadcast` \| `point-to-point` | enum |
| `/router/ospf/area/<id>/interface/<n>/priority` | 64 | 0..255 | (count) |
| `/router/ospf/area/<id>/interface/<n>/cost` | 10 | 0..65535 | (metric) |
| `/router/ospf/area/<id>/interface/<n>/mtu-ignore` | `false` | — | boolean |
| `/router/ospf/area/<id>/interface/<n>/passive` | `false` | — | boolean |

Notes:

- **`enable`** is the participation switch: an interface runs OSPF if
  and only if it appears under some area with `enable true`. There is
  no separate `network X area Y` statement.
- **`network-type`** selects the interface's OSPF network type,
  mirroring the IS-IS knob of the same name. `broadcast` (the
  default) runs DR/BDR election through the Waiting state;
  `point-to-point` skips Waiting and DR election entirely and forms
  a single adjacency. Changing it on a live interface bounces the
  IFSM (an internal `Disable → Enable` pair) so state machine and
  neighbor list re-initialize under the new type. NBMA and
  point-to-multipoint are not supported.
- **`priority`** is the DR-election priority advertised in Hellos.
  Higher wins; zero forbids the router from becoming DR or BDR on
  that segment. The zebra-rs default of 64 is the IOS-XR baseline; a
  router unconditionally configured higher than its peers becomes
  the DR on a freshly-formed broadcast segment.
- **`cost`** is the interface output cost (RFC 2328 §C.3) — the
  link metric carried in the Router-LSA and used as the SPF edge
  weight. Changing it re-originates the Router-LSA in every
  attached area and schedules SPF, so the new metric takes effect
  immediately; deleting the leaf restores the protocol default
  of 10.
- **`mtu-ignore`** disables the MTU-mismatch check during DBD
  exchange (RFC 2328 §10.6). Default `false` matches the RFC; set
  to `true` only when intentionally peering across links with
  different MTUs and accepting the resulting black-hole risk for
  jumbo packets.
- **`passive`** keeps advertising the interface's prefix into the
  area (as a stub network in the Router-LSA) while sending and
  accepting no Hellos — no adjacency ever forms on the segment.
  Use it for user-facing networks that must be reachable without
  exposing an OSPF speaker. Loopback interfaces are implicitly
  passive regardless of this leaf. Toggling bounces the interface
  so an adjacency formed while active is dropped cleanly;
  `show ospf interface` reports `No Hellos (Passive interface)`.
