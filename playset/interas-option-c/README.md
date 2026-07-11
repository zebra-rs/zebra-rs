# Inter-AS L3VPN Option C — labeled loopbacks between the ASBRs, VPNv4 PE-to-PE

The last of RFC 4364 §10's multi-AS methods, and the trilogy's finale —
**Option C (§10c)**: the ASes exchange, via BGP labeled unicast (BGP-LU,
RFC 8277), nothing but **labeled routes to their PE loopbacks**. The VPN
routes themselves never touch the border routers: the PEs of the two
providers peer **VPNv4 directly with each other** over a multihop eBGP
session, and a VPN packet rides a **three-label stack** from ingress PE
to egress PE — the border ASBRs just switch the middle label.

This playset completes the arc begun by
[interas-option-a](../interas-option-a/README.md) and
[interas-option-b](../interas-option-b/README.md) — the same pared
ten-router lab as Option B (one PE and two customers per side, with the
same overlapping addressing), and only the border model changed a third
time. The headline numbers to watch:

|                                | Option A | Option B | Option C |
|:-------------------------------|:---------|:---------|:---------|
| MPLS labels crossing the border | **0** (plain IP) | **1** (VPN) | **2** (LU + VPN) |
| VPN routes held by the ASBR     | all (in VRFs) | all (global VPNv4) | **none** |
| ASBR BGP state scales with      | customers | VPN routes | **PEs** |

<img src="../images/InterASOptionC.svg" alt="Inter-AS Option C topology">

Deliberate choices carried over from A and B:

* **Two customers, overlapping addressing** (both use site A loopback
  `172.16.1.1/32`, site B `172.16.2.1/32`) — this time to show the border
  carrying them with *zero* per-customer state of any kind.
* **Coordinated route-targets, AS-local RDs** — like Option B: the VPNv4
  session (now PE-to-PE) carries attributes intact, so the providers
  agree on `65501:100` / `65501:200`; the RDs stay `65501:x` vs `65502:x`.

## Bring up all nodes

``` shell
$ ./up.sh
bring up
...
apply config: ce3
applied
apply config: ce4
applied
```

Same ten namespaces as Options A and B — bring up only one Inter-AS lab
at a time. Convergence is layered by design: the LU exchange must
complete before the multihop VPNv4 session can even establish, so allow
an extra beat.

## The control plane, from the border inward

### ASBR — nothing but labeled loopbacks

`asbr1.yaml` in full BGP shape — note what is *absent*: no `vrf:` block
(like B), and now **no `vpnv4` either**:

``` yaml
router:
  bgp:
    global:
      as: 65501
      router-id: 1.1.1.3
    neighbor:
    - remote-address: 1.1.1.1        # iBGP labeled-unicast to PE1
      remote-as: 65501
      update-source: 1.1.1.3
      afi-safi:
      - name: label-v4
        enabled: true
        next-hop-self: true          # <- THE Option C knob
    - remote-address: 192.168.100.2  # eBGP labeled-unicast to ASBR2
      remote-as: 65502
      afi-safi:
      - name: label-v4
        enabled: true
```

The `next-hop-self` sits on the **iBGP labeled-unicast** leg: the remote
PE loopback learned from ASBR2 must be re-advertised into AS 65501
carrying ASBR1's IGP-reachable loopback and ASBR1's own swap label — not
the foreign inter-AS address nobody inside can resolve.

In classic Cisco IOS terms the same node is:

```
router bgp 65501
 neighbor 1.1.1.1 remote-as 65501
 neighbor 192.168.100.2 remote-as 65502
 address-family ipv4
  neighbor 1.1.1.1 activate
  neighbor 1.1.1.1 send-label          ! iBGP + labels (RFC 8277)
  neighbor 1.1.1.1 next-hop-self
  neighbor 192.168.100.2 activate
  neighbor 192.168.100.2 send-label    ! eBGP + labels
! no "ip vrf", no vpnv4 address-family at all
```

### PE — originate your loopback, peer VPNv4 with the far PE

`pe1.yaml` gains two things over its Option B version. It originates its
own loopback into labeled unicast, and its VPNv4 session now runs
**multihop, straight to pe2's loopback** — a router two IGPs away:

``` yaml
  bgp:
    global:
      as: 65501
      router-id: 1.1.1.1
    neighbor:
    - remote-address: 1.1.1.3        # iBGP labeled-unicast to ASBR1
      remote-as: 65501
      update-source: 1.1.1.1
      afi-safi:
      - name: label-v4
        enabled: true
    - remote-address: 2.2.2.3        # eBGP VPNv4 DIRECT to PE2 (AS 65502)
      remote-as: 65502
      ebgp-multihop: 10
      update-source: 1.1.1.1
      afi-safi:
      - name: vpnv4
        enabled: true
    afi-safi:
    - name: label-v4
      network:
      - prefix: 1.1.1.1/32           # my loopback, into BGP-LU
```

The loopback's journey: `pe1` originates `1.1.1.1/32` into label-v4 →
`asbr1` re-advertises it to `asbr2` over eBGP-LU (with a label) →
`asbr2` re-advertises it to `pe2` over iBGP-LU with next-hop-self (and
its own swap label). Four routers each hold exactly one extra labeled
route per PE — that is the *entire* footprint the VPN service leaves on
the border.

## What the border holds — and what it doesn't

``` shell
asbr1>show bgp summary
IPv4 Unicast Summary:
...
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
1.1.1.1         4      65501         4         2        0    0    0 00:00:56 Established        0/0 s
192.168.100.2   4      65502         4         3        0    0    0 00:00:57 Established        0/0 s

IPv4 Labeled Unicast Summary:
BGP router identifier 1.1.1.3, local AS number 65501 VRF default vrf-id 0
RIB entries 2

asbr1>show bgp vpnv4
     Network          Next Hop            Metric LocPrf Weight Path
```

**The VPNv4 table is empty.** Two labeled-unicast RIB entries — the two
PE loopbacks — are all the BGP state this border router carries for the
service. Its kernel MPLS table tells the same story in two lines of
`proto bgp`:

``` shell
asbr1>ip -f mpls route
16 as to 16011 via inet 10.1.0.5 dev asbr1-p1 proto bgp
17 as to 17 via inet 192.168.100.2 dev asbr1-asbr2 proto bgp
15000 via inet 10.1.0.5 dev asbr1-p1 proto isis
16011 as to 16011 via inet 10.1.0.5 dev asbr1-p1 proto isis
16012 via inet 10.1.0.5 dev asbr1-p1 proto isis
16013 via inet 1.1.1.3 dev lo proto isis
```

* `16` — ASBR1's LU label for **pe1's loopback** (advertised to ASBR2):
  swaps to the SR transport label `16011` toward pe1.
* `17` — ASBR1's LU label for **pe2's loopback** (advertised to pe1):
  swaps to ASBR2's LU label across the border.

Compare Option B's eight per-VPN-route swap entries at the same spot —
and imagine both at a thousand customer routes. Here the count is *one
per PE*, and it would not change if the customers advertised a million
prefixes.

## The PEs talk over everyone's heads

``` shell
pe1>show bgp summary
...
IPv4 Labeled Unicast Summary:
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
1.1.1.3         4      65501         5         3        0    0    0 00:01:12 Established        1/1 s

VPNv4 Unicast Summary:
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
2.2.2.3         4      65502         7         3        0    0    0 00:01:10 Established        4/4 s
```

A VPNv4 session Established with `2.2.2.3` — a loopback in another
provider's IGP. It works because the LU machinery delivered that loopback
as a *labeled route*:

``` shell
pe1>show ip route
...
B  *> 2.2.2.3/32 [200/0] via 10.1.0.2, pe1-p1, label 16013 17, 00:01:11
```

(`16013` = SR transport to ASBR1, `17` = ASBR1's LU label for pe2 — the
multihop TCP session and every VPN next-hop resolution ride this entry.)

The VPN routes arrive with the **remote PE itself as next hop** and the
remote PE's own VRF label — no ASBR ever rewrote them:

``` shell
pe1>show bgp vpnv4
Route Distinguisher: 65502:1
 *>  [1] 10.13.0.0/30       2.2.2.3                  0             0 65502 65513 i
     rt:65501:100 label=16,
 *>  [1] 172.16.2.1/32      2.2.2.3                  0             0 65502 65513 i
     rt:65501:100 label=16,
```

Note `label=16` on *both* prefixes: that is pe2's per-VRF label, end to
end — contrast Option B, where the same routes carried per-prefix transit
labels re-allocated at the ASBR hop. Resolving the next hop through the
LU route composes the final answer, and the VRF table shows the whole
program in one line:

``` shell
pe1>show ip route vrf cust1
...
B  *> 10.13.0.0/30 [200/0] via 10.1.0.2, pe1-p1, label 16013 17 16, 00:01:10
B  *> 172.16.2.1/32 [200/0] via 10.1.0.2, pe1-p1, label 16013 17 16, 00:01:10
```

**`label 16013 17 16`** — a three-label stack: SR transport to the
border, BGP-LU across it, VPN label for the far PE's VRF.

## Data plane: three labels, two labels, one label

``` shell
$ sudo ip netns exec ce1 vty
ce1>ping 172.16.2.1
PING 172.16.2.1 (172.16.2.1) 56(84) bytes of data.
64 bytes from 172.16.2.1: icmp_seq=1 ttl=62 time=0.082 ms
64 bytes from 172.16.2.1: icmp_seq=2 ttl=62 time=0.087 ms
```

`ttl=62` — two higher than Options A and B on the identical topology: the
packet is label-switched from PE to PE, and the border routers stopped
costing IP hops. On the wire, the stack sheds one label per segment:

``` shell
p1>tcpdump -nli p1-pe1 'mpls 16013'              # pe1 -> p1: THREE labels
MPLS (label 16013, tc 0, ttl 63) (label 17, tc 0, ttl 63) (label 16, tc 0, [S], ttl 63)
  IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...

asbr1>tcpdump -nli asbr1-asbr2 mpls              # between the ASes: TWO labels
MPLS (label 17, tc 0, ttl 62) (label 16, tc 0, [S], ttl 63) IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...
MPLS (label 16, tc 0, ttl 62) (label 16, tc 0, [S], ttl 63) IP 172.16.2.1 > 10.11.0.1: ICMP echo reply ...

p2>tcpdump -nli p2-pe2 'mpls and ip proto 1'     # p2 -> pe2: ONE label
MPLS (label 16, tc 0, [S], ttl 63) IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...
```

Following the request: pe1 imposes `[16013 | 17 | 16]`; p1 PHPs the SR
transport; asbr1 swaps the LU label (`17 as to 17` — its label for pe2's
loopback becomes asbr2's) and **two labels cross the provider boundary**;
asbr2 terminates the LU path into its own SR core; p2 PHPs; pe2 receives
its VRF label `16`, pops it, and routes the inner packet to ce3. The
**inner VPN label was imposed by pe1 and popped by pe2** — no router in
between ever looked at it. The overlap proof from A and B holds verbatim
(ce1's and ce2's pings to the same `172.16.2.1` land on ce3 and ce4, zero
leakage), selected by RD on the PE-to-PE session.

## The trade, completed

What Option C buys over B:

* **The border forgets the VPNs entirely.** ASBR state is one labeled
  loopback per PE — independent of customers, of VPN route count, of
  churn. This is why Option C is the model for large interconnects (and,
  intra-provider, the same construction underlies BGP-LU "seamless
  MPLS" designs).
* **End-to-end service semantics.** The VPN label is allocated by the
  egress PE and interpreted by nobody else; per-prefix transit label
  state disappears.

What it costs:

* **The deepest trust of the three.** Provider 1's PE loopbacks are
  reachable — as labeled destinations — from inside provider 2. The
  borders exchange infrastructure routes, not customer routes; exposing
  PE addresses to another operator is exactly what security policy
  usually forbids, which is why C is typically deployed between ASes of
  the *same* operator and B between different ones.
* **Multihop eBGP mesh among PEs.** Every PE pair (or, in production, a
  route-reflector pair per AS with `next-hop-unchanged`) must peer
  across the boundary. This lab wires the two PEs directly; Cisco's
  reference design uses the RR form — built as the sibling playset
  [interas-option-c-rr](../interas-option-c-rr/README.md).
* Route-target coordination, as in B.

## Tear down

``` shell
$ ./down.sh
```

## Appendix: Addressing & sessions

Nodes, AS numbers, loopbacks, SR SIDs, PE-CE links, and customer
addressing are identical to
[interas-option-b](../interas-option-b/README.md#appendix-addressing--sessions),
including the one global-table border link `asbr1-asbr2` =
`192.168.100.0/30`.

| VPN   | RT (coordinated)  | RD on pe1 | RD on pe2 |
|:------|:------------------|:----------|:----------|
| cust1 | 65501:100         | 65501:1   | 65502:1   |
| cust2 | 65501:200         | 65501:2   | 65502:2   |

BGP sessions: 4× PE-CE eBGP IPv4 (in VRF), 2× iBGP **labeled-unicast**
over loopbacks (pe1–asbr1, asbr2–pe2; ASBR side with `next-hop-self`),
1× ASBR-ASBR eBGP **labeled-unicast**, and 1× **multihop eBGP VPNv4
directly between pe1 and pe2** — the Option C control plane.

## Sources

* RFC 4364, *BGP/MPLS IP Virtual Private Networks*, §10 — "Multi-AS
  Backbones", method (c); RFC 8277, *Using BGP to Bind MPLS Labels to
  Address Prefixes*.
* Cisco, *MPLS VPN Inter-AS with ASBRs Exchanging IPv4 Routes and MPLS
  Labels* (the Option C configuration guide):
  <https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/mpls/b-mpls/m_mp-vpn-connect-ipv4.html>
* Cisco, *Configuring MPLS VPN Inter-AS Options*:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/17-16/configuration_guide/mpls/b_1716_mpls_9400_cg/configuring_mpls_vpn_interas_options.html>
* netquirks, *Inter-AS Option C*:
  <https://netquirks.co.uk/ios-vs-xr/option-c/>
* QuistED, *Inter-AS MPLS L3VPN Options (A, B, C)*:
  <https://www.quisted.net/index.php/2025/09/12/inter-as-mpls-l3vpn-options-a-b-c/>
* Juniper, *Interprovider VPNs*:
  <https://www.juniper.net/documentation/us/en/software/junos/vpn-l3/topics/topic-map/l3-vpns-interprovider.html>
