# BGP - Border Gateway Protocol

BGP (RFC 4271) is the path-vector routing protocol that connects
autonomous systems. zebra-rs implements BGP-4 with the standard
multiprotocol extensions: IPv4/IPv6 unicast, L3VPN (VPNv4/VPNv6),
EVPN, labeled unicast, route-target constraint, link-state and more —
each covered by its own chapter in this section.

## Minimal configuration

A BGP instance needs its autonomous system number; everything else
has workable defaults. The canonical two-line start plus one
neighbor:

```
set router bgp global as 65000
set router bgp global router-id 10.0.0.1
set router bgp neighbor 10.0.0.2 remote-as 65001
commit
```

`global router-id` sets the BGP Identifier carried in OPEN messages.
It is optional: when not configured, the RIB-distributed router-id
(the system-wide selection, or the configured `system router-id`)
is used, and deleting the BGP-local value falls back to it. See
[Selection of the Router-ID](ch-00-02-router-id.md) for the full
selection and precedence model. Earlier releases named this leaf
`identifier`, following the IETF BGP YANG model; it was renamed for
consistency with the rest of the configuration tree.

A neighbor whose `remote-as` differs from the local AS forms an eBGP
session; a matching AS forms iBGP. Session state is visible with:

```
> show bgp ipv4 summary
IPv4 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65000 VRF default vrf-id 0
...
```
