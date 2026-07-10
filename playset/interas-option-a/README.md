# Inter-AS L3VPN Option A — back-to-back VRFs

MPLS L3VPN normally lives inside one provider. When a VPN has sites behind
**two different autonomous systems**, RFC 4364 §10 defines three ways to
hand VPN routes across the AS boundary. This playset builds the first and
simplest one — **Option A (§10a)**, the *back-to-back VRF* model, in
Cisco's words:

> ASBR peers are connected by multiple (sub)interfaces with at least one
> interface per VPN that spans the two autonomous systems. Each ASBR
> associates the (sub)interface with a VRF and a BGP session that signals
> **unlabeled IP prefixes** — so the traffic between the back-to-back
> VRFs is plain IP.

Each AS runs its own complete, independent MPLS L3VPN. At the border, the
ASBR terminates the VPN exactly like a PE — and treats the *other* AS's
ASBR as if it were a directly attached customer. MPLS stops at the
boundary; one dedicated link (or VLAN subinterface) and one plain eBGP
IPv4 session cross it **per customer**. Nothing VPN-flavored — no VPN
label, no RD, no route-target agreement — is exchanged between the
providers.

```
      customer cust1                                       customer cust1
  ce1 ─────────┐                                            ┌───────── ce3
  lo 172.16.1.1│                                            │ lo 172.16.2.1
               pe1 ─── p1 ─── asbr1 ═══════════ asbr2 ─── p2 ─── pe2
  lo 172.16.1.1│    MPLS (SR)      cust1: 192.168.1.0/30    │ lo 172.16.2.1
  ce2 ─────────┘                   cust2: 192.168.2.0/30    └───────── ce4
      customer cust2               (two links, plain IP!)  customer cust2

  └────────── AS 65501 ──────────┘          └────────── AS 65502 ─────────┘
```

Two things are deliberate in this lab:

* **Two customers** (`cust1`: ce1↔ce3, `cust2`: ce2↔ce4) — Option A's
  defining property (and its scalability limit) is *one inter-AS link and
  one BGP session per VPN*, which you can only see with more than one VPN.
* **Overlapping customer addressing** — both customers use the *same*
  address plan (site A loopback `172.16.1.1/32`, site B loopback
  `172.16.2.1/32`). Both providers carry both plans simultaneously, and
  the walkthrough proves a ping to `172.16.2.1` lands on the right
  customer's router.

Inside each AS the transport is IS-IS + SR-MPLS (zebra-rs's label
distribution; classic Cisco documents use LDP here — the role is
identical: a labeled path between the PE and ASBR loopbacks).

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

Ten namespaces: `ce1 ce2 pe1 p1 asbr1` + `asbr2 p2 pe2 ce3 ce4`. Give the
BGP chain a minute — a route crosses five BGP sessions each way
(CE→PE eBGP, PE→ASBR iBGP VPNv4, ASBR→ASBR per-VRF eBGP, then the mirror
of the same in the far AS).

## The roles, from the outside in

### CE — the customer has no idea any of this is happening

`ce1.yaml` is a plain eBGP speaker: one session to its PE, `redistribute
connected` to originate its loopback. No VRF, no MPLS, no VPN anywhere:

``` yaml
interface:
- if-name: lo
  ipv4:
    address: 172.16.1.1/32
- if-name: ce1-pe1
  ipv4:
    address: 10.11.0.1/30
router:
  bgp:
    global:
      as: 65511
      router-id: 10.11.0.1
    neighbor:
    - remote-address: 10.11.0.2
      remote-as: 65501
      afi-safi:
      - name: ipv4
        enabled: true
    afi-safi:
    - name: ipv4
      redistribute:
        connected: {}
```

(`ce2.yaml` is the same router for customer cust2 — with the **same
loopback address**. The lab's YAML also trims BGP timers,
`adv-interval`/`connect-retry-time`, so the demo converges in seconds
instead of minutes; elided here for clarity.)

### PE — one VRF per customer, VPNv4 toward the core

`pe1.yaml` is a textbook L3VPN provider edge. Each customer gets a VRF
with a route-target; the CE-facing interface is bound into the VRF; the
PE-CE eBGP session lives under the VRF; and one iBGP **VPNv4** session
runs to ASBR1 over the loopbacks, riding the SR-MPLS LSP:

``` yaml
vrf:
- name: cust1
  ipv4:
    route-target:
      import:
      - 65501:100
      export:
      - 65501:100
- name: cust2
  ipv4:
    route-target:
      import:
      - 65501:200
      export:
      - 65501:200
interface:
- if-name: lo
  ipv4:
    address: 1.1.1.1/32
- if-name: pe1-ce1
  vrf: cust1
  ipv4:
    address: 10.11.0.2/30
- if-name: pe1-ce2
  vrf: cust2
  ipv4:
    address: 10.12.0.2/30
- if-name: pe1-p1
  ipv4:
    address: 10.1.0.1/30
router:
  isis:
    net: 49.0001.0000.0000.0001.00
    is-type: level-2-only
    segment-routing: mpls
    te-router-id: 1.1.1.1
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 11        # loopback 1.1.1.1 -> label 16011
    - if-name: pe1-p1
      network-type: point-to-point
      ipv4:
        enabled: true
  bgp:
    global:
      as: 65501
      router-id: 1.1.1.1
    neighbor:
    - remote-address: 1.1.1.3      # ASBR1 loopback
      remote-as: 65501
      update-source: 1.1.1.1
      afi-safi:
      - name: vpnv4
        enabled: true
    vrf:
    - name: cust1
      rd: 65501:1
      neighbor:
      - remote-address: 10.11.0.1  # CE1, eBGP inside the VRF
        remote-as: 65511
        afi-safi:
        - name: ipv4
          enabled: true
    - name: cust2
      rd: 65501:2
      neighbor:
      - remote-address: 10.12.0.1
        remote-as: 65512
        afi-safi:
        - name: ipv4
          enabled: true
```

### P — label switching only, no BGP, no VPN state

`p1.yaml` runs nothing but IS-IS with SR-MPLS. It never learns a customer
prefix; it only swaps transport labels between the PE and ASBR loopbacks:

``` shell
p1>show isis route
Area 49.0001:
...
 asbr1                  TE-IS         10      asbr1     p1-asbr1   p1
 pe1                    TE-IS         10      pe1       p1-pe1     p1
 1.1.1.1/32             IP TE         20      pe1       p1-pe1     pe1
 1.1.1.3/32             IP TE         20      asbr1     p1-asbr1   asbr1
```

### ASBR — the Option A node

`asbr1.yaml` is where the model lives. Read it as *a PE whose "customers"
are the other provider's ASBR*: the same `vrf` blocks as PE1, one
**dedicated interface per VRF** toward AS 65502, and one **plain eBGP
IPv4 session per VRF** across it. Toward the inside it is an ordinary
VPNv4 iBGP speaker:

``` yaml
vrf:
- name: cust1
  ipv4:
    route-target:
      import:
      - 65501:100
      export:
      - 65501:100
- name: cust2
  ipv4:
    route-target:
      import:
      - 65501:200
      export:
      - 65501:200
interface:
- if-name: lo
  ipv4:
    address: 1.1.1.3/32
- if-name: asbr1-p1
  ipv4:
    address: 10.1.0.6/30
- if-name: asbr1-cust1          # dedicated inter-AS link for cust1
  vrf: cust1
  ipv4:
    address: 192.168.1.1/30
- if-name: asbr1-cust2          # dedicated inter-AS link for cust2
  vrf: cust2
  ipv4:
    address: 192.168.2.1/30
router:
  isis:
    net: 49.0001.0000.0000.0003.00
    is-type: level-2-only
    segment-routing: mpls
    te-router-id: 1.1.1.3
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 13        # loopback 1.1.1.3 -> label 16013
    - if-name: asbr1-p1
      network-type: point-to-point
      ipv4:
        enabled: true
  bgp:
    global:
      as: 65501
      router-id: 1.1.1.3
    neighbor:
    - remote-address: 1.1.1.1      # PE1: iBGP VPNv4 into the AS core
      remote-as: 65501
      update-source: 1.1.1.3
      afi-safi:
      - name: vpnv4
        enabled: true
    vrf:
    - name: cust1
      rd: 65501:1
      neighbor:
      - remote-address: 192.168.1.2   # ASBR2, plain eBGP IPv4 in the VRF
        remote-as: 65502
        afi-safi:
        - name: ipv4
          enabled: true
    - name: cust2
      rd: 65501:2
      neighbor:
      - remote-address: 192.168.2.2
        remote-as: 65502
        afi-safi:
        - name: ipv4
          enabled: true
```

Note the IS-IS section does **not** include the inter-AS links: the IGP —
and with it MPLS — ends at the boundary.

For orientation, the same node in classic Cisco IOS terms (the shape used
in Cisco's Inter-AS documentation and countless deployment guides):

```
ip vrf cust1
 rd 65501:1
 route-target both 65501:100
!
interface GigabitEthernet0/1.10       ! subinterface toward ASBR2
 ip vrf forwarding cust1
 ip address 192.168.1.1 255.255.255.252
!
router bgp 65501
 neighbor 1.1.1.1 remote-as 65501     ! iBGP to PE1
 address-family vpnv4
  neighbor 1.1.1.1 activate
  neighbor 1.1.1.1 send-community extended
 address-family ipv4 vrf cust1
  neighbor 192.168.1.2 remote-as 65502   ! eBGP to ASBR2, unlabeled IPv4
  neighbor 192.168.1.2 activate
```

One structural difference is worth calling out: this lab uses two
physical (veth) links, one per VRF, where a real deployment typically
uses **802.1Q subinterfaces of one physical link** — the model is
identical either way: *some* dedicated L3 interface per VPN must cross
the boundary.

`asbr2.yaml` mirrors ASBR1 with one deliberate asymmetry: AS 65502 uses
**different RD and RT values** (`65502:1`/`65502:100`, …). In Options B
and C the providers must coordinate route-targets; in Option A nothing
VPN-flavored crosses the boundary, so each AS numbers its own VPN space
independently. The lab encodes that independence.

## Control plane: following 172.16.2.1/32 home

ce3 originates `172.16.2.1/32` into eBGP. pe2 receives it in VRF cust1,
exports it to VPNv4 (RD `65502:1`, RT `65502:100`, a VPN label), and iBGP
carries it to asbr2. asbr2 *imports* it back into VRF cust1 — and from
there it is just an IPv4 route, advertised over the cust1 inter-AS
session. On asbr1:

``` shell
asbr1>show bgp vpnv4
     Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 65501:1
 *>i [1] 10.11.0.0/30       1.1.1.1                  0    100      0 65511 i
     rt:65501:100 label=16,
 *>  [1] 10.13.0.0/30       1.1.1.3                  0             0 65502 65513 i
     rt:65501:100 rt:65502:100 label=16,
 *>i [1] 172.16.1.1/32      1.1.1.1                  0    100      0 65511 i
     rt:65501:100 label=16,
 *>  [1] 172.16.2.1/32      1.1.1.3                  0             0 65502 65513 i
     rt:65501:100 rt:65502:100 label=16,
Route Distinguisher: 65501:2
 *>i [1] 10.12.0.0/30       1.1.1.1                  0    100      0 65512 i
     rt:65501:200 label=17,
 *>  [1] 10.14.0.0/30       1.1.1.3                  0             0 65502 65514 i
     rt:65501:200 rt:65502:200 label=17,
 *>i [1] 172.16.1.1/32      1.1.1.1                  0    100      0 65512 i
     rt:65501:200 label=17,
 *>  [1] 172.16.2.1/32      1.1.1.3                  0             0 65502 65514 i
     rt:65501:200 rt:65502:200 label=17,
```

This one table tells most of the Option A story:

* **`*>i` rows** came from PE1 over iBGP VPNv4 (next hop `1.1.1.1`,
  LocPrf 100) — the local AS's own customer routes.
* **`*>` rows with next hop `1.1.1.3` (self)** are the far-AS routes:
  asbr1 learned them as *plain IPv4* over the per-VRF eBGP session and
  **re-originated** them into VPNv4 itself — it stamps its own RD, its
  own export RT, allocates a VPN label, and sets itself as next hop.
  This is the ASBR "acting as the PE" for the neighbor provider.
* The **AS path `65502 65513`** records the plain eBGP crossing: the
  neighbor provider's AS, then the far customer site — inter-AS route
  distribution with ordinary BGP loop protection.
* `label=16` / `label=17` are per-VRF VPN labels (aggregate, one per VRF)
  — the egress router only needs the label to pick the right VRF for the
  IP lookup.
* The far-AS rows carry **two route-targets** (`rt:65501:100
  rt:65502:100`): RTs are transitive extended communities, so AS 65502's
  RT survived the plain eBGP hop and AS 65501's export RT was added next
  to it. It is inert here — but it quietly leaks one AS's VPN numbering
  into the other, which is why production Option A borders commonly strip
  or filter extended communities on the inter-AS session.
* Both customers' `172.16.1.1/32` and `172.16.2.1/32` coexist —
  distinguished **only by the RD**. Overlapping customer addressing is
  business as usual.

The resulting VRF routing table on asbr1 shows the boundary in two
adjacent lines — toward the core the route carries a two-label stack,
toward the neighbor AS it is a naked IP next hop:

``` shell
asbr1>show ip route vrf cust1
...
B  *> 10.11.0.0/30 [200/0] via 10.1.0.5, asbr1-p1, label 16011 16, 00:01:47
B  *> 10.13.0.0/30 [20/0] via 192.168.1.2, asbr1-cust1, 00:01:12
B  *> 172.16.1.1/32 [200/0] via 10.1.0.5, asbr1-p1, label 16011 16, 00:01:47
B  *> 172.16.2.1/32 [20/0] via 192.168.1.2, asbr1-cust1, 00:01:12
C  *> 192.168.1.0/30 is directly connected, asbr1-cust1, 00:01:52
```

(`label 16011 16` = transport label to PE1's loopback SID + PE1's VPN
label; `[200/0]`/`[20/0]` are iBGP/eBGP distances.)

One more iBGP hop and PE1 has the far site in VRF cust1 with the mirror
image of that stack — transport `16013` to asbr1 plus asbr1's VPN label:

``` shell
pe1>show bgp vpnv4
Route Distinguisher: 65501:1
...
 *>i [1] 172.16.2.1/32      1.1.1.3                  0    100      0 65502 65513 i
     rt:65501:100 rt:65502:100 label=16,

pe1>show ip route vrf cust1
...
B  *> 172.16.2.1/32 [200/0] via 10.1.0.2, pe1-p1, label 16013 16, 00:01:35
```

And the customer end sees ordinary BGP — no labels, no RDs:

``` shell
ce1>show ip route
...
B  *> 10.13.0.0/30 [20/0] via 10.11.0.2, ce1-pe1, 00:00:37
C  *> 172.16.1.1/32 is directly connected, lo, 00:01:52
B  *> 172.16.2.1/32 [20/0] via 10.11.0.2, ce1-pe1, 00:00:37
```

## Data plane: MPLS, then IP, then MPLS again

``` shell
$ sudo ip netns exec ce1 vty
ce1>ping 172.16.2.1
PING 172.16.2.1 (172.16.2.1) 56(84) bytes of data.
64 bytes from 172.16.2.1: icmp_seq=1 ttl=60 time=0.076 ms
64 bytes from 172.16.2.1: icmp_seq=2 ttl=60 time=0.134 ms
```

`ttl=60`: four IP routing decisions (pe1, asbr1, asbr2, pe2). The P
routers only switch labels. Capturing the *same ping* at three points
shows Option A's signature — the VPN is labeled inside each provider and
naked in between:

``` shell
p1>tcpdump -nli p1-asbr1 mpls                    # inside AS 65501
MPLS (label 16, tc 0, [S], ttl 63) IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...
MPLS (label 16011, tc 0, ttl 61) (label 16, tc 0, [S], ttl 61) IP 172.16.2.1 > 10.11.0.1: ICMP echo reply ...

asbr1>tcpdump -nli asbr1-cust1 icmp              # between the ASes
IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...
IP 172.16.2.1 > 10.11.0.1: ICMP echo reply ...

p2>tcpdump -nli p2-pe2 mpls                      # inside AS 65502
MPLS (label 16, tc 0, [S], ttl 61) IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...
MPLS (label 16021, tc 0, ttl 63) (label 16, tc 0, [S], ttl 63) IP 172.16.2.1 > 10.11.0.1: ICMP echo reply ...
```

Reading the stacks: the reply direction shows the full two-label stack
(`16011` transport toward pe1 + `16` VPN), while the request direction
shows only the VPN label — the capture points are each AS's *penultimate*
link, where PHP has already popped the transport label. And on the
inter-AS link there is no MPLS at all: asbr1 popped everything, made an
IP routing decision in VRF cust1, and forwarded a plain IP packet; asbr2
then re-imposed a fresh two-label stack from its own AS's label space.
The two providers share no label state whatsoever.

## Overlapping addresses, proven

Both customers' site-B routers answer to `172.16.2.1`. Ping it from each
customer's site A and watch where the echo lands:

``` shell
# ce1 (cust1) pings 172.16.2.1
ce3>tcpdump -nli ce3-pe2 icmp
IP 10.11.0.1 > 172.16.2.1: ICMP echo request ...     <- arrives at ce3
ce4>tcpdump -nli ce4-pe2 icmp
0 packets captured                                    <- nothing at ce4

# ce2 (cust2) pings 172.16.2.1
ce4>tcpdump -nli ce4-pe2 icmp
IP 10.12.0.1 > 172.16.2.1: ICMP echo request ...     <- arrives at ce4
ce3>tcpdump -nli ce3-pe2 icmp
0 packets captured                                    <- nothing at ce3
```

Same destination address, zero leakage. Each customer's traffic stays
pinned to its own chain of VRFs and its own inter-AS link end to end —
in Option A there is no shared table anywhere that could even *express* a
cross-customer route.

## Why this is "Option A" — and what it costs

What this model buys (and why it is still deployed):

* **Simplicity and isolation.** Each AS runs a completely independent
  L3VPN; the border is ordinary eBGP over ordinary interfaces. No label
  exchange with, and no label trust in, the neighbor provider — the most
  contained failure and security model of the three options.
* **Per-VPN policy and QoS.** Because inter-AS traffic is plain IP on a
  dedicated interface per VPN, per-customer QoS, policing, ACLs, and
  billing attach naturally at the boundary.
* **No coordination.** RDs, RTs, label spaces, even the IGP/label
  protocol inside each AS (this lab: SR-MPLS both sides — it could be
  LDP on one side and SR on the other) are all private per provider.

What it costs — visible directly in this lab:

* **One interface + one BGP session + one VRF per customer, per border.**
  Adding customer N means touching both ASBRs with a new subinterface,
  VRF, and session. The two `asbr1-cust*` links here become hundreds of
  subinterfaces in production.
* **The ASBR holds every customer's routes as plain IP** — it is a PE for
  every VPN crossing the border, with the FIB and RIB burden that
  implies.

That trade is exactly what Options B and C renegotiate: **Option B**
replaces the per-VRF links and sessions with a single MP-eBGP VPNv4
session between the ASBRs (labeled traffic crosses the boundary);
**Option C** goes further and keeps PE-to-PE label switching end to end,
with the ASBRs only exchanging labeled PE loopbacks. See the sibling
playsets [interas-option-b](../interas-option-b/README.md) and
[interas-option-c](../interas-option-c/README.md).

## Tear down

``` shell
$ ./down.sh
```

## Appendix: Addressing & sessions

| node  | role            | AS    | loopback     | SR SID (label)  |
|:------|:----------------|:------|:-------------|:----------------|
| ce1   | CE, cust1 site A | 65511 | 172.16.1.1/32 | —              |
| ce2   | CE, cust2 site A | 65512 | 172.16.1.1/32 | —              |
| pe1   | PE              | 65501 | 1.1.1.1/32   | 11 (16011)      |
| p1    | P               | 65501 | 1.1.1.2/32   | 12 (16012)      |
| asbr1 | ASBR            | 65501 | 1.1.1.3/32   | 13 (16013)      |
| asbr2 | ASBR            | 65502 | 2.2.2.1/32   | 21 (16021)      |
| p2    | P               | 65502 | 2.2.2.2/32   | 22 (16022)      |
| pe2   | PE              | 65502 | 2.2.2.3/32   | 23 (16023)      |
| ce3   | CE, cust1 site B | 65513 | 172.16.2.1/32 | —              |
| ce4   | CE, cust2 site B | 65514 | 172.16.2.1/32 | —              |

Links: ce1–pe1 `10.11.0.0/30`, ce2–pe1 `10.12.0.0/30`, pe1–p1
`10.1.0.0/30`, p1–asbr1 `10.1.0.4/30`, asbr1–asbr2 cust1
`192.168.1.0/30`, asbr1–asbr2 cust2 `192.168.2.0/30`, asbr2–p2
`10.2.0.0/30`, p2–pe2 `10.2.0.4/30`, pe2–ce3 `10.13.0.0/30`, pe2–ce4
`10.14.0.0/30`.

| VPN   | AS 65501 RD / RT     | AS 65502 RD / RT     |
|:------|:---------------------|:---------------------|
| cust1 | 65501:1 / 65501:100  | 65502:1 / 65502:100  |
| cust2 | 65501:2 / 65501:200  | 65502:2 / 65502:200  |

BGP sessions: 4× PE-CE eBGP IPv4 (in VRF), 2× iBGP VPNv4 over loopbacks
(pe1–asbr1, asbr2–pe2), 2× ASBR-ASBR eBGP IPv4 (one per VRF — the
Option A boundary).

## Sources

* Cisco, *MPLS VPN Inter-AS Option AB* (defines Options A/B/AB and the
  back-to-back VRF model):
  <https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/mpls/b-mpls/m_mp-vpn-ias-optab.html>
* Cisco, *Configuring MPLS VPN Inter-AS Options* (Catalyst switch
  configuration guide):
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/17-16/configuration_guide/mpls/b_1716_mpls_9400_cg/configuring_mpls_vpn_interas_options.html>
* netquirks, *Inter-AS Option A* (IOS vs IOS-XR configuration
  walkthrough): <https://netquirks.co.uk/ios-vs-xr/inter-as-option-a/>
* QuistED, *Inter-AS MPLS L3VPN Options (A, B, C)*:
  <https://www.quisted.net/index.php/2025/09/12/inter-as-mpls-l3vpn-options-a-b-c/>
* Juniper, *Interprovider VPNs* (the same options from the Junos angle):
  <https://www.juniper.net/documentation/us/en/software/junos/vpn-l3/topics/topic-map/l3-vpns-interprovider.html>
* RFC 4364, *BGP/MPLS IP Virtual Private Networks*, §10 —
  "Multi-AS Backbones", method (a).
