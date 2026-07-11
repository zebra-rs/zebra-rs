# Inter-AS L3VPN Option AB — per-VPN VRFs, one VPNv4 session

Options A and B renegotiated one trade: A gave every customer its own
border interface, session, and VRF (perfect isolation, painful scaling);
B collapsed the border to one MP-BGP session (one session forever, but
the per-customer policy point disappeared). Cisco's **Option AB** — a
vendor hybrid beyond RFC 4364 §10's three letters — recombines them:

> The MPLS VPN Inter-AS Option AB feature combines the best functionality
> of an Inter-AS Option (10) A and Option (10) B network […]
> the different autonomous systems interconnect by using a single MP-BGP
> session in the global routing table to carry control plane traffic,
> [while the network] maintains IP quality of service functions between
> ASBR peers.

The ASBR keeps a **VRF per customer, like A** — but with no interface,
no CE, and no per-VRF session: a pure *transit* VRF that exists to be the
per-VPN forwarding and policy point. Route exchange runs over a **single
eBGP VPNv4 session, like B**. Each hybrid VRF re-originates what it
imports — under the ASBR's own RD, with itself as next hop, a fresh
per-VRF label, and its own export RT replacing whatever arrived — which
is, line for line, Cisco's Option AB route-distribution procedure:

> ASBR1 imports the prefix into VPN 1 and creates a prefix RD 5:N […]
> sets itself as the next hop […] and allocates a local label that is
> signaled with this prefix. ASBR2 receives the prefix RD 5:N and imports
> it into VPN 1 as RD 7:N [and] advertises the route with the export RT
> configured on the VRF rather than the originally received RTs.

<img src="../images/InterASOptionAB.svg" alt="Inter-AS Option AB topology">

The lab is the Option A/B reference topology — three customers with
overlapping addressing, two PEs in AS 65501, one PE serving all three in
AS 65502 — with only the ASBRs changed. One honest note: classic Cisco
AB forwards the customer *data* unlabeled over per-VRF subinterfaces
(that is where the per-customer QoS attaches), with only the control
session shared. This lab implements the labeled-data-path flavor (Cisco
documents it as Option AB+): data rides the same shared link as the
session, one label deep — but each ASBR still terminates the VPN into
the customer's own VRF, makes an IP routing decision there, and
re-imposes; the per-VPN state and policy point that Option B lost is
restored at both borders.

## Bring up all nodes

``` shell
$ ./up.sh
bring up
...
apply config: ce5
applied
apply config: ce6
applied
```

Same thirteen namespaces as the A/B labs — bring up only one Inter-AS
lab at a time.

## The ASBR: three VRFs, no VRF anything else

`asbr1.yaml`'s BGP shape — compare all three siblings at the same spot:
Option A had per-VRF *sessions*, B had *no VRFs at all*, AB has VRFs
with nothing in them but policy:

``` yaml
vrf:
- name: cust1
  ipv4:
    route-target:
      import:
      - 65501:100
      export:
      - 65501:100
# ... cust2 (65501:200) and cust3 (65501:300) repeat the pattern
router:
  bgp:
    global:
      as: 65501
      router-id: 1.1.1.3
    neighbor:
    - remote-address: 1.1.1.1        # PE1 — iBGP VPNv4 (no next-hop-self!)
      remote-as: 65501
      update-source: 1.1.1.3
      afi-safi:
      - name: vpnv4
        enabled: true
    - remote-address: 1.1.1.4        # PE2 — same, one session per PE
      remote-as: 65501
      update-source: 1.1.1.3
      afi-safi:
      - name: vpnv4
        enabled: true
    - remote-address: 192.168.100.2  # ASBR2 — ONE eBGP VPNv4, all customers
      remote-as: 65502
      afi-safi:
      - name: vpnv4
        enabled: true
    vrf:
    - name: cust1
      rd: 65501:11
      inter-as-hybrid: true          # <- THE Option AB knob
    - name: cust2
      rd: 65501:12
      inter-as-hybrid: true
    - name: cust3
      rd: 65501:13
      inter-as-hybrid: true
```

* **`inter-as-hybrid: true`** turns each VRF into the AB relay: the
  VPNv4 routes its RT imports are re-exported — re-originated under the
  VRF's own RD (`65501:11`/`12`/`13`, deliberately distinct from the
  PEs' `65501:1`/`2`/`3`), next-hop-self, the VRF's per-VRF label,
  single clean RT. The transparent Option-B-style relay of the received
  route is suppressed; each router sees every prefix under exactly one
  RD.
* **No `next-hop-self` knob anywhere** — Option B needed it on both
  iBGP legs; here the re-export is a local origination, so every leg
  (toward PE1, PE2, and ASBR2 alike) gets self as next hop for free.
* The top-level `vrf:` block alone creates the kernel VRF devices, which
  is what the data path hangs off (below).

## Control plane: the RD chain

``` shell
asbr1>show bgp vrf
VRF                  RD                Label  TableID  Peers State
cust1                65501:11             16        1      0 running
cust2                65501:12             17        2      0 running
cust3                65501:13             18        3      0 running
```

Three customers, three labels, **zero peers** — the VRFs are pure policy
anchors (Option A showed `1` in that Peers column per VRF, and its label
terminated into a session; B showed `(no VRFs configured)`). The border
sessions:

``` shell
asbr1>show bgp summary
...
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State       PfxRcd/Snt Hostname
1.1.1.1         4      65501         6         2        0    0    0 00:00:53 Established       4/12 s
1.1.1.4         4      65501         5         2        0    0    0 00:00:53 Established       2/12 s
192.168.100.2   4      65502        10         3        0    0    0 00:00:55 Established       6/12 s
```

One iBGP session per PE, one eBGP session for every customer — and
twelve sent everywhere, because the hybrid VRFs re-export all they
import to every peer. Follow cust3 through the table (its PE is `pe2`,
so the chain starts at `1.1.1.4`):

``` shell
asbr1>show bgp vpnv4
...
Route Distinguisher: 65501:3
 *>i [1] 10.13.0.0/30       1.1.1.4                  0    100      0 65513 i
     rt:65501:300 label=16,
 *>i [1] 172.16.1.1/32      1.1.1.4                  0    100      0 65513 i
     rt:65501:300 label=16,
Route Distinguisher: 65501:13
 *>  [1] 10.13.0.0/30       1.1.1.3                  0    100      0 65513 i
     rt:65501:300 label=18,
 *>  [1] 10.16.0.0/30       1.1.1.3                  0             0 65502 65516 i
     rt:65501:300 label=18,
 *>  [1] 172.16.1.1/32      1.1.1.3                  0    100      0 65513 i
     rt:65501:300 label=18,
 *>  [1] 172.16.2.1/32      1.1.1.3                  0             0 65502 65516 i
     rt:65501:300 label=18,
```

Read it as Cisco's procedure executing: PE2's originals under
`65501:3`, next hop `1.1.1.4`; the hybrid VRF's re-originations under
**`65501:13`** — next hop rewritten to `1.1.1.3` (self), the VRF's own
label `18`, one clean `rt:65501:300` whether the source was PE2 (iBGP)
or ASBR2 (the `65502:13` rows, kept for import but never transparently
relayed). A prefix's RD changes at every border — unlike B, where RDs
crossed untouched — and cust1/cust2 run the same chain from PE1
(`65501:1`/`2` → `65501:11`/`12` → …).

## Data plane: label in, IP lookup, label out — per customer

``` shell
asbr1>ip -f mpls route | grep "dev cust"
16 dev cust1 proto bgp
17 dev cust2 proto bgp
18 dev cust3 proto bgp

asbr1>show ip route vrf cust1
...
B  *> 172.16.1.1/32 [200/0] via 10.1.0.5, asbr1-p1, label 16011 16, 00:00:53
B  *> 172.16.2.1/32 [20/0] via 192.168.100.2, asbr1-asbr2, label 16, 00:00:53

asbr1>show ip route vrf cust3
...
B  *> 172.16.1.1/32 [200/0] via 10.1.0.5, asbr1-p1, label 16014 16, 00:00:53
B  *> 172.16.2.1/32 [20/0] via 192.168.100.2, asbr1-asbr2, label 18, 00:00:53
```

`18 dev cust3` is the whole Option AB data plane in one line: MPLS label
18 arrives → **deliver into the cust3 VRF** for an IP routing decision.
The VRF's table then re-imposes — and the transport label names the
owning PE: cust1 rides `16011` back to pe1, cust3 rides `16014` to pe2.
Contrast the same spot in Option B — a flat list of per-prefix
`X as to Y` label swaps with no IP lookup and no per-customer anything.

``` shell
$ sudo ip netns exec ce1 vty
ce1>ping 172.16.2.1
64 bytes from 172.16.2.1: icmp_seq=1 ttl=60 time=0.044 ms
```

`ttl=60` — four IP routing decisions: the ingress PE, **asbr1 (in the
customer's VRF)**, **asbr2 (likewise)**, pe3. Option B also showed 60,
but its border decrements came from MPLS TTL on label swaps; here they
are genuine per-customer IP lookups (Option C, which does neither,
shows 62). On the wire — cust3's ping captured entering and leaving
asbr1:

``` shell
asbr1>tcpdump -nli asbr1-p1 mpls        # arriving from the core
MPLS (label 18, tc 0, [S], ttl 63) IP 10.13.0.1 > 172.16.2.1: ICMP echo request ...
asbr1>tcpdump -nli asbr1-asbr2 mpls     # leaving across the border
MPLS (label 18, tc 0, [S], ttl 62) IP 10.13.0.1 > 172.16.2.1: ICMP echo request ...
```

The label value happens to be 18 on both sides (each router's cust3
label), but they are different labels from different spaces — and the
decremented TTL between them is the IP lookup in `cust3` happening. The
overlap proof runs three customers deep, each ping to the shared
`172.16.2.1` landing only on its own site-B router:

|                  | arrives at ce4 | arrives at ce5 | arrives at ce6 |
|:-----------------|:---------------|:---------------|:---------------|
| ce1 (cust1) pings | **yes**       | —              | —              |
| ce2 (cust2) pings | —             | **yes**        | —              |
| ce3 (cust3) pings | —             | —              | **yes**        |

— here because each customer's traffic threads its own VRF at both
borders.

## A best-path fix this lab flushed out

Option AB's hybrid re-export has an echo: ASBR2 re-originates everything
its VRFs import — *including the PEs' own prefixes* — and each PE
imports the echo back (the RTs match; iBGP carries no AS-path loop
protection for it). Building this playset exposed a zebra-rs best-path
bug: VRF rows imported from the VPN table carried the locally-originated
route type (the tunnel FIB-install path keys on it), so at the PEs the
echo **beat the CE's direct eBGP route** at the locally-originated
tiebreak, and customer traffic looped back into the core.

The fix (in this playset's original PR) marks imported rows
`vrf_imported` and teaches best-path two things: an import is not a
local origination, and it ranks as iBGP — so RFC 4271's prefer-external
step picks the direct CE route. The result is visible on every PE: the
CE route stays best (`*>`), the echo stays in the table, valid but not
best (`*`) — present, harmless, and a nice fingerprint of how AB's
re-origination machinery works.

## The quadrant, completed

| | per-customer state at the border | sessions crossing the border |
|:--|:--|:--|
| **Option A** | VRFs + interfaces + sessions | one per customer |
| **Option B** | none | one |
| **Option AB** | VRFs (policy/forwarding only) | **one** |
| **Option C** | none — not even VPN routes | one (+ PE/RR multihop VPNv4) |

Option AB is what you pick when you want B's single-session border but
cannot give up the per-customer enforcement point: per-VPN QoS,
policing, per-customer route limits and RT policy all get a VRF to
attach to at the boundary, without a single per-customer session or
subinterface. The cost is Option A's state (a VRF and label per customer
per ASBR — the border scales with customers again) plus B's coordination
(RTs must still be agreed across the ASes).

## Tear down

``` shell
$ ./down.sh
```

## Appendix: Addressing & sessions

Identical to the [Option B playset](../interas-option-b/README.md#appendix-addressing--sessions)
(the A/B reference topology with the single global inter-AS link
`192.168.100.0/30`) except the ASBRs' hybrid VRFs:

| VPN   | RT (coordinated) | RD at origin       | RD on asbr1 | RD on asbr2 | RD on pe3 |
|:------|:-----------------|:-------------------|:------------|:------------|:----------|
| cust1 | 65501:100        | 65501:1 (pe1)      | 65501:11    | 65502:11    | 65502:1   |
| cust2 | 65501:200        | 65501:2 (pe1)      | 65501:12    | 65502:12    | 65502:2   |
| cust3 | 65501:300        | 65501:3 (pe2)      | 65501:13    | 65502:13    | 65502:3   |

BGP sessions: 6× PE-CE eBGP IPv4 (in VRF), 3× iBGP VPNv4 over loopbacks
(pe1–asbr1, pe2–asbr1, asbr2–pe3 — no next-hop-self needed), and **one**
ASBR-ASBR eBGP VPNv4 session — with the per-customer VRFs riding on
`inter-as-hybrid` at both borders.

## Sources

* Cisco, *MPLS VPN—Inter-AS Option AB* (the feature guide; Cisco has
  removed the live pages, archived copy):
  <https://web.archive.org/web/2024/https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mp_ias_and_csc/configuration/xe-16/mp-ias-and-csc-xe-16-book/mpls-vpn-inter-as-option-ab.html>
* Cisco, *Configuring MPLS VPN Inter-AS Options*:
  <https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9400/software/release/17-16/configuration_guide/mpls/b_1716_mpls_9400_cg/configuring_mpls_vpn_interas_options.html>
* RFC 4364, *BGP/MPLS IP Virtual Private Networks*, §10 — Options A/B/C
  (AB is a Cisco-documented hybrid of (a) and (b)).
* QuistED, *Inter-AS MPLS L3VPN Options (A, B, C)* (for the base options
  AB recombines):
  <https://www.quisted.net/index.php/2025/09/12/inter-as-mpls-l3vpn-options-a-b-c/>
