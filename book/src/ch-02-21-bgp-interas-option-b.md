# Inter-AS Option B (VPNv4 between ASBRs)

Option B (RFC 4364 §10b) carries the VPN across the boundary in the
control plane: the two ASBRs run an **MP-eBGP VPNv4/VPNv6 session
directly with each other** and exchange the VPN routes themselves. Unlike
Option A, an Option B ASBR holds **no VRF** — every VPN route sits in its
global VPNv4 table and is re-advertised onward. Unlike Option C, the
ASBRs *do* hold (and re-advertise) every VPN prefix, so they stay in the
VPN control plane but not in any single VPN's VRF.

The data plane is pure MPLS. When an ASBR re-advertises a received VPNv4
route it sets **next-hop-self** and allocates a **fresh local VPN label**,
installing a label-swap entry (`our label → the received label`) toward
the route's original next-hop. A customer packet therefore crosses the
inter-AS link as a single labelled MPLS packet, is label-swapped at each
ASBR, and is re-labelled onto the far AS's SR-MPLS core — the VPN label
is rewritten hop-by-hop but never stripped to plain IP.

## Reference topology

This is the topology exercised by the `@bgp_interas_option_b` BDD
feature (`bdd/tests/features/bgp_interas_option_b.feature`):

```
          AS 65000                                  AS 65001
 ce1 ── pe1 ──── p1 ──── asbr1 ═══════ asbr2 ──── p2 ──── pe2 ── ce2
        lo        lo       lo  172.16.0.0/30  lo     lo      lo
     1.1.1.1   1.1.1.2  1.1.1.3   (global)   2.2.2.3 2.2.2.2 2.2.2.1
  └ vrf-cust ┘          (no VRF)            (no VRF)        └ vrf-cust ┘
   10.1.0.0/30                                            10.2.0.0/30
```

`pe1` exchanges VPNv4 with `asbr1` over the IS-IS / SR-MPLS core (via
`p1`); likewise `pe2`/`asbr2` in AS 65001. The `asbr1`–`asbr2` link sits
in the **global** table (it is **not** in the IGP) and carries a
single-hop MP-eBGP VPNv4 session. The `═══` marks that the inter-AS link
forwards labelled MPLS, not plain IP.

## The two halves

**Intra-AS L3VPN.** Identical to a single-AS deployment (see
[L3VPN](ch-02-04-bgp-l3vpn.md)). `pe1` originates the CE1 prefix into
`vrf-cust` and advertises it as VPNv4 to `asbr1`; the next-hop is `pe1`'s
loopback, resolved by IS-IS over the SR-MPLS core. The PE is completely
unaware of the AS boundary.

**Inter-AS MP-eBGP VPNv4.** `asbr1` and `asbr2` peer over the
`172.16.0.0/30` link with a `vpnv4`-enabled eBGP session. The ASBR has no
VRF, so a received VPNv4 route is held in the global VPNv4 Loc-RIB and
re-advertised:

* over the eBGP session to the other ASBR (eBGP rewrites the next-hop to
  self automatically); and
* over the iBGP session to its own PE, where **`next-hop-self` must be
  set** — by default an iBGP speaker keeps the eBGP route's received
  next-hop (the far ASBR's inter-AS address), which the PE cannot
  resolve. Next-hop-self replaces it with the ASBR's IGP-reachable
  loopback.

In both cases the ASBR allocates a new local VPN label and swaps it to
the received label (see *Transit label swap* below). The route-targets
are carried transparently end to end; the PEs filter on import exactly as
in a single-AS L3VPN (a shared `65000:100` in the BDD).

## Configuration

A PE (`pe1`) is an ordinary intra-AS L3VPN PE — byte-for-byte the same as
the Option A PE; it never knows the boundary exists:

```yaml
vrf:
- name: vrf-cust
  ipv4:
    route-target:
      import: [65000:100]
      export: [65000:100]
interface:
- if-name: ce1
  vrf: vrf-cust
  ipv4: { address: 10.1.0.1/30 }
router:
  bgp:
    global: { as: 65000, identifier: 1.1.1.1 }
    neighbor:
    - remote-address: 1.1.1.3        # ASBR1, intra-AS VPNv4
      remote-as: 65000
      update-source: 1.1.1.1
      enabled: true
      afi-safi:
      - { name: vpnv4, enabled: true }
    vrf:
    - name: vrf-cust
      rd: 65000:1
      afi-safi:
        ipv4:
          network: [ { prefix: 10.1.0.0/30 } ]
```

An ASBR (`asbr1`) has **no VRF**. The inter-AS link is a plain global
interface, and the eBGP neighbour carries `vpnv4`. The iBGP neighbour to
the PE sets `next-hop-self`:

```yaml
interface:
- if-name: asbr2
  ipv4: { address: 172.16.0.1/30 }   # inter-AS link, GLOBAL table
router:
  bgp:
    global: { as: 65000, identifier: 1.1.1.3 }
    neighbor:
    - remote-address: 1.1.1.1          # PE1, intra-AS VPNv4
      remote-as: 65000
      update-source: 1.1.1.3
      enabled: true
      afi-safi:
      - name: vpnv4
        enabled: true
        next-hop-self: true            # rewrite NH for re-advertised eBGP routes
    - remote-address: 172.16.0.2       # ASBR2, single-hop eBGP VPNv4
      remote-as: 65001
      enabled: true
      afi-safi:
      - { name: vpnv4, enabled: true }
```

No MPLS knob is needed on the inter-AS link: zebra-rs enables
`net.mpls.conf.<if>.input` on every interface it discovers (and sets
`net.mpls.platform_labels` at startup), so the link forwards labelled
packets out of the box.

## Next-hop-self on the VPNv4 advertise path

`afi-safi <name> next-hop-self` is the same per-neighbour knob introduced
for the Inter-AS Option C ASBR→PE Labeled-Unicast session; for Option B it
is honoured on the **VPNv4** advertise path. By default the VPNv4
next-hop is rewritten to self only for eBGP and locally-originated routes;
an eBGP route reflected onward to an iBGP PE keeps its received next-hop.
Setting the knob forces self on that forwarded route, so the PE always
sees an IGP-reachable next-hop and resolves the transport over its
SR-MPLS core.

## Transit label swap

Because the ASBR rewrites the next-hop, it can no longer advertise the
*received* VPN label — a peer that sends traffic to it would arrive with a
label the ASBR has no forwarding entry for. Instead, for each received
VPNv4 route the ASBR:

1. **allocates a per-`(RD, prefix)` local label** from the dynamic label
   block (the same pool used for per-VRF and Labeled-Unicast labels);
2. **advertises that local label** in the VPNv4 NLRI to any peer it
   rewrites the next-hop toward; and
3. **installs a swap ILM**: `local label → [transport…, received label]`,
   where the transport stack is the SR-MPLS path to the route's original
   next-hop (empty when that next-hop is directly connected, as on the
   inter-AS link).

The dynamic label block is requested as soon as a `vpnv4`/`vpnv6` family
is enabled on any neighbour — a transit ASBR has no VRF to trigger it
otherwise. This is the same swap machinery the Labeled-Unicast transit
path uses; here it is keyed by `(RD, prefix)` because the same IP prefix
can appear in many VPNs.

> **MPLS label-stack encoding fix.** The kernel ILM encoder previously
> emitted one `RTA_NEWDST` netlink attribute per outgoing label, so a
> duplicate attribute overwrote the earlier one and only the last label
> survived. A swap-and-push (`local → [SR-transport, VPN]`) therefore lost
> its transport label and the packet was dropped at the next P router.
> The encoder now packs the whole stack into a single `RTA_NEWDST` with
> the bottom-of-stack bit set only on the innermost label — matching the
> IP-route encap path. This fix is required for any multi-label swap ILM,
> not just Option B.

## Forwarding

Every hop carries an MPLS label; the VPN label is swapped at each ASBR. A
packet from `ce1` to a host in `ce2`'s subnet (a route originated by
`pe2`):

| Hop | Action |
|---|---|
| `pe1` | VRF lookup → push `[SR→asbr1, ASBR1-VPN]`, send over the core |
| `p1` | SR penultimate-hop pop → `[ASBR1-VPN]` |
| `asbr1` | swap `ASBR1-VPN → ASBR2-VPN`, send the **single** label to `asbr2` over the inter-AS link |
| `asbr2` | swap `ASBR2-VPN → [SR→pe2, PE2-VPN]` onto the AS 65001 core |
| `p2` | SR penultimate-hop pop → `[PE2-VPN]` |
| `pe2` | pop the VPN label → VRF lookup → to `ce2` |

The inter-AS link carries exactly one label (the ASBRs are directly
connected, so no transport label is needed there); the intra-AS legs
carry two (SR transport + VPN).

## Verification

Each ASBR holds every VPN prefix in its **global** VPNv4 table — the
local-AS one learned from its PE, the remote-AS one from the other ASBR
(note the AS path):

```
asbr1$ show ip bgp vpnv4
Route Distinguisher: 65000:1
 *>i 10.1.0.0/30   1.1.1.1      ...   i        # from PE1 (intra-AS VPNv4)
Route Distinguisher: 65001:1
 *>  10.2.0.0/30   172.16.0.2   ...   65001 i  # from ASBR2 (inter-AS eBGP)
```

The swap ILM shows the local label switching to the next label, with the
SR transport pushed on the multi-hop leg:

```
asbr2$ ip -f mpls route
17 as to 16004/16 via inet 10.0.1.2 dev p2     # 10.2 → SR→pe2 + VPN label
16 as to 16        via inet 172.16.0.1 dev asbr1 # 10.1 → asbr1 (direct, 1 label)
```

The remote-AS prefix reaches the far PE's VRF (with `next-hop-self` the
next-hop is the ASBR loopback, resolved by the IGP), and CE-to-CE traffic
forwards:

```
pe1$  show ip route vrf vrf-cust    # B *> 10.2.0.0/30 via … label <SR→asbr1> <VPN>
ce1$  ping <host in ce2's subnet>   # succeeds
```

## BDD coverage

`bdd/tests/features/bgp_interas_option_b.feature` builds the eight-
namespace topology above and asserts the IS-IS SR adjacencies, the
SR-MPLS ILM entries, the intra-AS VPNv4 sessions, the single-hop inter-AS
eBGP VPNv4 sessions, every VPN prefix in both ASBRs' global VPNv4 tables,
the far-PE VRF import, and an end-to-end CE-to-CE ping in both directions.
The ASBRs lower their MRAI so the four-hop VPNv4 propagation converges
promptly.
