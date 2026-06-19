# Inter-AS Option C over SR-MPLS

Option C (RFC 4364 §10c) keeps the ASBRs out of the VPN entirely. Three
control planes cooperate so that a single MPLS LSP runs from the ingress
PE to the egress PE, with the VPN routes carried directly between the
PEs over the top:

1. **Inside each AS** — an IGP with SR-MPLS (IS-IS here) makes the local
   PE and ASBR loopbacks reachable and gives them prefix-SID labels, so
   any two routers in the AS have a transport LSP between them.
2. **Across the AS boundary** — the ASBRs run **eBGP labeled-unicast**
   (BGP-LU, SAFI 4) and exchange each other's PE loopback `/32`s *with a
   label*. No IGP and no VPN routes cross the link; the ASBRs hold no VPN
   state.
3. **Between the PEs** — a **multihop MP-eBGP VPNv4/VPNv6** session
   (loopback to loopback) carries the VPN routes. Its next-hop is the
   remote PE loopback, which the local PE reaches over the stitched
   BGP-LU LSP from step 2.

The result is an end-to-end label stack — SR transport (outer), BGP-LU
(AS crossing), VPN service label (inner) — that the ingress PE pushes in
one go.

## Reference topology

This is the topology exercised by the `@bgp_interas_option_c` BDD
feature (`bdd/tests/features/bgp_interas_option_c.feature`):

```
          AS 65000                                  AS 65001
 ce1 ── pe1 ──── p1 ──── asbr1 ═══════════ asbr2 ──── p2 ──── pe2 ── ce2
        lo        lo       lo    172.16.0.0/30  lo      lo      lo
     1.1.1.1   1.1.1.2  1.1.1.3              2.2.2.3 2.2.2.2 2.2.2.1
     (sid 1)   (sid 2)  (sid 3)              (sid 6) (sid 5) (sid 4)
  └ vrf-cust ┘                                            └ vrf-cust ┘
   10.1.0.0/30                                             10.2.0.0/30
```

With the default SRGB base of `16000`, prefix-SID index `N` becomes
label `16000+N`, so `pe2`'s loopback `2.2.2.1` is SR label `16004`,
`asbr1`'s `1.1.1.3` is `16003`, and so on. `p1` and `p2` are pure SR
transit LSRs (IS-IS only); the ASBRs hold no VPN routes; the customer
prefixes live in `vrf-cust` on each PE.

## SR-MPLS transport inside each AS

Each PE, P, and ASBR runs IS-IS Level-2 with `segment-routing mpls` and
a prefix-SID on its loopback. The inter-AS link is deliberately **not**
in the IGP — it is the BGP-LU link. A PE config's IS-IS block:

```yaml
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    is-type: level-2-only
    segment-routing: mpls
    interface:
    - if-name: lo
      ipv4: { enable: true, prefix-sid: { index: 1 } }
    - if-name: p1
      network-type: point-to-point
      metric: 10
      ipv4: { enable: true }
```

This gives `pe1` a transport LSP to `asbr1` (its BGP-LU peer's
loopback), traversing `p1` with a real SR swap / penultimate-hop pop.
See the [SRv6](ch-04-00-srv6.md) and IS-IS chapters for the segment
routing details.

## eBGP labeled-unicast between the ASBRs

The ASBRs peer over the inter-AS link with the IPv4 Labeled-Unicast
family (`label-v4`) and **originate their own AS's PE loopbacks** into
it. Because the loopback is reached over the IGP, the ASBR allocates a
*local* label for it and installs a swap entry (BGP-LU label → SR
transport toward the PE); the remote ASBR learns the `/32` with that
label.

```yaml
router:
  bgp:
    global:
      as: 65000
      router-id: 1.1.1.3
    neighbor:
    - remote-address: 172.16.0.2   # ASBR2, over the inter-AS link
      remote-as: 65001
      enabled: true
      afi-safi:
      - name: label-v4
        enabled: true
    afi-safi:
    - name: label-v4
      network:
      - prefix: 1.1.1.1/32         # advertise PE1's loopback to AS 65001
```

> Each PE typically originates its own loopback (implicit-null, since it
> is the egress), and the ASBR re-originates it across the boundary. The
> BDD has the PEs originate their loopbacks via `network` under the
> global `label-v4` family; the ASBRs simply relay.

## iBGP labeled-unicast ASBR → PE, with `next-hop-self`

The ASBR re-advertises the routes it learned across the boundary to its
own PEs over an iBGP-LU session. This leg needs **`next-hop-self`**: by
default a route learned from one peer keeps its received next-hop, which
here is the *foreign-AS* next-hop the PE cannot resolve. With
`next-hop-self`, the ASBR advertises its own loopback as the next-hop
and a fresh swap label, so the PE resolves the ASBR over the IGP and
pushes the ASBR's label.

```yaml
    neighbor:
    - remote-address: 1.1.1.1       # PE1, iBGP over loopbacks
      remote-as: 65000
      update-source: 1.1.1.3
      enabled: true
      afi-safi:
      - name: label-v4
        enabled: true
        next-hop-self: true
```

The CLI equivalent is:

```
set router bgp neighbor 1.1.1.1 afi-safi label-v4 next-hop-self true
```

`next-hop-self` is a per-neighbor, per-AFI/SAFI knob honored on the
Labeled-Unicast advertise path. Without it, the PE would see the remote
ASBR (a different AS) as the next-hop and the route would be unusable.

## Multihop eBGP VPNv4 between the PEs

The PEs run a direct MP-eBGP session between their loopbacks, carrying
only the `vpnv4` family. It is multihop (`ebgp-multihop`) and sourced
from the loopback (`update-source`); a short `connect-retry-time` lets
it come up promptly once the BGP-LU LSP to the remote loopback exists.

```yaml
    neighbor:
    - remote-address: 2.2.2.1       # PE2's loopback, several hops away
      remote-as: 65001
      ebgp-multihop: 10
      update-source: 1.1.1.1
      timers: { connect-retry-time: 3 }
      enabled: true
      afi-safi:
      - name: vpnv4
        enabled: true
    vrf:
    - name: vrf-cust
      rd: 65000:1
      afi-safi:
        ipv4:
          network:
          - prefix: 10.1.0.0/30     # the customer prefix
```

The VPN route-targets live on the top-level `vrf` block, exactly as for
intra-AS [L3VPN](ch-02-04-bgp-l3vpn.md):

```yaml
vrf:
- name: vrf-cust
  ipv4:
    route-target:
      import: [65000:100]
      export: [65000:100]
```

Because the PE *originates* its VPN route, it sets next-hop-self
(its own loopback) — which is the correct egress — so no
`next-hop-unchanged` is needed even though the session is eBGP. (A
route-reflector-based Option C, where an out-of-path RR reflects VPNv4
with `next-hop-unchanged`, is a separate design.)

## The crux: resolving the VPN next-hop over the BGP-LU LSP

When `pe1` receives `10.2.0.0/30` with next-hop `2.2.2.1`, that next-hop
is **not** in any IGP — it is only reachable over the BGP-LU LSP. The
recursive next-hop resolver therefore has to resolve a VPN next-hop
**through a labeled BGP route**, stacking that route's label(s) under
the VPN service label.

This is the one place inter-AS forwarding differs from the intra-AS
case. Ordinarily a BGP next-hop must resolve over the underlay (IGP /
connected) and resolving over another BGP route is refused — it would
risk loops. The exception is a **labeled** BGP-LU route: it *is* the
transport, so the resolver accepts it (bounded by the recursion depth
cap). The VPN next-hop then resolves to:

```
2.2.2.1  →  BGP-LU route (push the ASBR's swap label)
         →  IGP/SR route to the ASBR (push the SR prefix-SID)
         →  on-link next-hop toward P1
```

and the PE programs the VPN prefix with all three labels.

## End-to-end label stack

A packet from `ce1` to a host in `ce2`'s subnet, traced by the labels on
the wire (AS 65000 → AS 65001):

| Hop | Action | Stack leaving the hop |
|---|---|---|
| `pe1` | VRF lookup → push `[SR→asbr1, BGP-LU, VPN]` | `16003 · L_lu · L_vpn` |
| `p1` | SR penultimate-hop pop of `16003` | `L_lu · L_vpn` |
| `asbr1` | swap BGP-LU label toward `asbr2` | `L_lu' · L_vpn` |
| `asbr2` | swap → push SR transport toward `pe2` | `16004 · L_vpn` |
| `p2` | SR penultimate-hop pop of `16004` | `L_vpn` |
| `pe2` | pop VPN label → VRF lookup → to `ce2` | *(IP)* |

The transport label (SR) gets the packet to the next ASBR; the BGP-LU
label carries it across the AS boundary to the right egress PE; the VPN
label selects the customer VRF on that PE.

## Verification

**The PEs learn each other's loopback as a labeled route.** On `pe1`,
`2.2.2.1/32` arrives over BGP-LU and installs with the stacked transport
+ BGP-LU label:

```
$ show ip route 2.2.2.1
B  *> 2.2.2.1/32 [200/0] via 10.0.0.2, p1, label 16003 16

$ ip route show 2.2.2.1
2.2.2.1 nhid 3  encap mpls  16003/16 via 10.0.0.2 dev p1 proto bgp onlink
```

Here `16003` is the SR prefix-SID toward `asbr1` and `16` is `asbr1`'s
BGP-LU swap label for `2.2.2.1`.

**The ASBRs carry only labeled IPv4 — no VPN.** On `asbr1`:

```
$ show bgp labeled-unicast
    Network            Next Hop            ...  Path
 *>i 1.1.1.1/32         1.1.1.1             ...  i        # local PE, from PE1
 *>  2.2.2.1/32         172.16.0.2          ...  65001 i  # remote PE, from ASBR2
```

The `label-v4` capability is negotiated on each BGP-LU session:

```
$ show bgp neighbor 172.16.0.2
  ...
    IPv4 Labeled Unicast: advertised and received
```

**The VPN routes pass directly between the PEs.** On `pe1`, the remote
customer prefix appears under the remote PE's RD, tagged with the shared
route-target, and the multihop session is up:

```
$ show bgp vpnv4
Route Distinguisher: 65001:1
 *>  10.2.0.0/30        2.2.2.1   ...   # rt:65000:100

$ show bgp neighbor 2.2.2.1
  BGP state = Established
```

That the multihop VPNv4 session reaches `Established` at all already
proves the BGP-LU LSP forwards — its TCP rides that LSP.

**End to end.** With the customer prefix imported into `vrf-cust` on
each PE, traffic forwards across the boundary:

```
ce1$ ping <host in ce2's subnet>   # succeeds
```

## BDD coverage

`bdd/tests/features/bgp_interas_option_c.feature` builds the full
eight-namespace topology above and asserts, in order: the IS-IS SR
adjacencies, the SR-MPLS ILM entries on the P routers, the eBGP-LU and
iBGP-LU sessions, the BGP-LU loopback exchange across the ASBRs, the
multihop VPNv4 session, the VPNv4 route exchange under each RD, and
finally an end-to-end CE-to-CE ping that exercises the SR + BGP-LU + VPN
label stack in the Linux MPLS data plane.
