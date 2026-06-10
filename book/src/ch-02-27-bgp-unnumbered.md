# IPv6 Unnumbered (interface-neighbor)

On a point-to-point fabric link there is often nothing worth
addressing: no IPv4 subnet, no global IPv6 — just two routers and a
wire. **IPv6 unnumbered BGP** peers over the link-local addresses that
every IPv6 interface already has, so a session needs zero address
planning: you name the **interface**, not the neighbor's address.

zebra-rs surfaces this as a separate `interface-neighbor` list under
`router bgp` (the IOS-XR shape), rather than overloading `neighbor`
with interface names:

```
      (i1)                                   (i1)
  ┌────┴────┐                            ┌────┴────┐
  │   z1    │────────── P2P ─────────────│   z2    │
  │ AS65001 │       fe80:: ↔ fe80::      │ AS65001 │
  └─────────┘   no IPv4, no global v6    └─────────┘
```

How a session comes up:

1. Both ends enable **Router Advertisements** on the link. The ND
   subsystem ingests the neighbor's RA and learns its link-local
   address.
2. When an RA arrives on an interface named by an
   `interface-neighbor` entry, BGP **materializes a peer keyed by that
   interface**, with the discovered link-local as its remote address.
3. The session establishes over `fe80::%ifindex`. Both ends dial and
   accept, so a connection collision is resolved normally (RFC 4271
   §6.8).
4. IPv4 routes are carried over the IPv6-only session via **RFC 8950
   Extended Next Hop Encoding** (ENHE), which interface-keyed peers
   advertise automatically — an IPv4 NLRI travels with an IPv6
   link-local next hop. IPv6 routes use the session's link-local as
   next hop directly.

The discovered link-local is not something an operator can type, so
the interface name is the peer's CLI identity throughout:
`show ip bgp neighbors i1`, `clear bgp ipv4 neighbor i1`, and the
`Neighbor` column of `show bgp summary` all use it.

## remote-as forms

`interface-neighbor <ifname> remote-as` accepts a numeric AS or the
FRR-style shorthands:

- **`internal`** — the peer is in the local AS (iBGP).
- **`external`** — any AS other than the local one. Accepted by the
  schema today, but the OPEN-side AS learning is not wired up yet, so
  a peer configured this way stays dormant — use a numeric AS or
  `internal` for now.

Alternatively the AS can come from a referenced
[neighbor-group](ch-02-26-bgp-neighbor-group.md); a `remote-as` on the
interface-neighbor itself always wins over the group's.

## Address families come from the group

`interface-neighbor` deliberately carries no per-peer `afi-safi` list.
A bare entry negotiates the default — IPv4 unicast only. To run IPv6
(or any other family) on an unnumbered session, reference a
neighbor-group and set the families there:

```yaml
interface:
- if-name: i1
  ipv6:
    router-advertisements:
      send-advertisements: true
router:
  bgp:
    global:
      as: 65001
      router-id: 1.1.1.1
    neighbor-group:
    - name: dynamic
      afi-safi:
      - name: ipv4
        enabled: true
      - name: ipv6
        enabled: true
    interface-neighbor:
    - interface: i1
      neighbor-group: dynamic
      remote-as: internal
    afi-safi:
    - name: ipv4
      network:
      - prefix: 10.0.1.1/32
    - name: ipv6
      network:
      - prefix: 2001:db8:1::1/128
```

The mirror configuration runs on `z2` (same AS — `remote-as internal`
makes this an iBGP session — its own router-id and prefixes). The
equivalent CLI forms:

```
set interface i1 ipv6 router-advertisements send-advertisements true
set router bgp neighbor-group dynamic afi-safi ipv4 enabled true
set router bgp neighbor-group dynamic afi-safi ipv6 enabled true
set router bgp interface-neighbor i1 neighbor-group dynamic
set router bgp interface-neighbor i1 remote-as internal
```

RA send must be enabled on **both** ends — each side materializes its
peer only when it hears the other side's RA. Routers advertise RAs on
their own schedule, so allow up to ~16 seconds for first discovery.

## Verification

Once both ends have applied the configuration:

```
show ip bgp neighbors i1
BGP neighbor on i1: fe80::8080:9fff:fef9:3fa, remote AS 65001, local AS 65001, internal link
  Local host: fe80::c49d:fbff:fe08:b421, Local port: 35086
  Foreign host: fe80::8080:9fff:fef9:3fa, Foreign port: 179
  BGP version 4, remote router ID 2.2.2.2, local router ID 1.1.1.1
  BGP state = Established, up for 00:00:03
  ...
  Neighbor-group: dynamic

  Neighbor Capabilities:
    4 Octet AS: advertised and received
    IPv4 Unicast: advertised and received
    IPv6 Unicast: advertised and received
    ...
```

Both families negotiated, and both tables carry the neighbor's
prefixes — `show ip bgp` holds `10.0.1.2/32` (learned via ENHE with a
link-local next hop) and `show bgp ipv6` holds `2001:db8:1::2/128`.
The unnumbered peer appears as `i1` in `show bgp summary`, and as a
member in `show ip bgp neighbor-group dynamic`.

## Changing the family set at runtime

Capability changes apply at the next OPEN exchange, so reshaping a
running fabric is a two-step: flip the group, then clear. To take the
session above IPv6-only, change the group's IPv4 opinion on both ends:

```
set router bgp neighbor-group dynamic afi-safi ipv4 enabled false
```

The established session is deliberately left alone. Now bounce it by
interface name (one end suffices — the other end sees the connection
close and renegotiates too):

```
clear bgp ipv4 neighbor i1
```

The re-established session advertises only IPv6 unicast — the
`IPv4 Unicast:` capability line is gone from
`show ip bgp neighbors i1`, the IPv4 routes learned from the peer were
withdrawn with the old session and do not return, and the IPv6 routes
re-sync immediately:

```
show ip bgp neighbor-group dynamic
BGP neighbor-group: dynamic
  Remote-AS: (unset)
  Afi-Safi:  ipv4 disabled, ipv6 enabled
  Members (1):
    i1                       remote-as 65001 state Established
```

## Troubleshooting

- **No peer ever appears.** The peer is materialized from the
  neighbor's RA, so check `send-advertisements true` on *both* ends,
  and that the `interface-neighbor` name matches the actual interface.
  First discovery can take ~16 seconds (RA timing).
- **Peer exists but stays down with `remote-as external`.** Expected
  for now — see [remote-as forms](#remote-as-forms); configure a
  numeric AS or `internal`.
- **IPv6 routes don't flow.** The session is IPv4-unicast-only by
  default; IPv6 must be enabled through the referenced group's
  `afi-safi ipv6 enabled true` (there is no per-interface-neighbor
  afi-safi list), and a change only applies after
  `clear bgp ipv4 neighbor <ifname>`.
- **IPv4 routes still flow after disabling ipv4 in the group.** The
  running session negotiated its capabilities at establishment;
  capability changes wait for the next OPEN exchange. Clear the
  session.
