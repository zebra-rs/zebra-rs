# Inter-AS Option A (back-to-back VRFs)

Option A (RFC 4364 §10a) is the simplest of the three inter-AS schemes
and the only one with no MPLS on the inter-AS link. Each ASBR is itself
a PE: for every VPN that must cross the boundary it holds a VRF, and the
two ASBRs are joined by a per-VPN interface placed in that VRF. Over
that interface they run an ordinary **PE-CE session inside the VRF** —
each ASBR treats the other as a CE. The VPN label terminates at each
ASBR: a packet is decapsulated to plain IP, looked up in the VRF, and
handed to the other ASBR over the VRF interface, where the far AS
re-imposes its own VPN label.

So Option A is just two ordinary intra-AS L3VPNs stitched together by a
plain-IP PE-CE hop. Nothing inter-AS-specific runs on the wire between
the ASBRs.

## Reference topology

This is the topology exercised by the `@bgp_interas_option_a` BDD
feature (`bdd/tests/features/bgp_interas_option_a.feature`):

```
          AS 65000                                  AS 65001
 ce1 ── pe1 ──── p1 ──── asbr1 ─────── asbr2 ──── p2 ──── pe2 ── ce2
        lo        lo       lo  172.16.0.0/30  lo     lo      lo
     1.1.1.1   1.1.1.2  1.1.1.3  (in vrf-cust) 2.2.2.3 2.2.2.2 2.2.2.1
  └ vrf-cust ┘          └ vrf-cust ┘      └ vrf-cust ┘    └ vrf-cust ┘
   10.1.0.0/30                                            10.2.0.0/30
```

`pe1` and `asbr1` are both PEs of AS 65000 and exchange VPNv4 over the
IS-IS / SR-MPLS core (via `p1`); likewise `asbr2`/`pe2` in AS 65001. The
`asbr1`–`asbr2` link sits in `vrf-cust` on both sides (and is **not** in
the IGP) and carries the inter-AS PE-CE eBGP session.

## The two halves

**Intra-AS L3VPN.** Identical to a single-AS deployment (see
[L3VPN](ch-02-04-bgp-l3vpn.md)). `pe1` originates the CE1 prefix into
`vrf-cust` and advertises it as VPNv4 to `asbr1`; the next-hop is `pe1`'s
loopback, resolved by IS-IS over the SR-MPLS core (no BGP-LU is involved
— both PEs are in the same AS). `asbr1` imports it into `vrf-cust`.

**Inter-AS PE-CE eBGP inside the VRF.** `asbr1` and `asbr2` peer over the
`172.16.0.0/30` link, which lives in `vrf-cust`. The session is a plain
IPv4-unicast eBGP session, sourced and bound inside the VRF
(`SO_BINDTODEVICE` to the VRF master, so its TCP rides the VRF table).
Each ASBR:

* **re-advertises** the routes it imported from its AS's VPNv4 over the
  PE-CE session (with next-hop-self — the connected VRF-interface
  address — and its AS prepended); and
* **re-exports** the routes it learns over the PE-CE session back into
  VPNv4 toward its own PEs.

The route-targets live on the top-level `vrf` block exactly as for
intra-AS L3VPN; a single shared RT (`65000:100` in the BDD) ties the four
`vrf-cust` instances together.

## Configuration

A PE (`pe1`) is an ordinary intra-AS L3VPN PE:

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

An ASBR (`asbr1`) adds the inter-AS link to the VRF and runs the PE-CE
eBGP **inside the VRF block**:

```yaml
interface:
- if-name: asbr2
  vrf: vrf-cust
  ipv4: { address: 172.16.0.1/30 }   # inter-AS link, in the VRF
router:
  bgp:
    global: { as: 65000, identifier: 1.1.1.3 }
    neighbor:
    - remote-address: 1.1.1.1         # PE1, intra-AS VPNv4
      remote-as: 65000
      update-source: 1.1.1.3
      enabled: true
      afi-safi:
      - { name: vpnv4, enabled: true }
    vrf:
    - name: vrf-cust
      rd: 65000:2
      neighbor:
      - remote-address: 172.16.0.2    # ASBR2, PE-CE eBGP inside the VRF
        remote-as: 65001              # the other AS
        enabled: true
```

A per-VRF neighbor needs no `afi-safi` block — it defaults to IPv4
unicast, which is what a PE-CE session carries. The per-VRF BGP router-id
defaults to the global identifier.

## What makes the per-VRF session work

A BGP session inside a VRF needs two kernel/runtime pieces that the
single-AS L3VPN never exercised:

* **`net.ipv4.tcp_l3mdev_accept = 1`** — zebra-rs runs one global,
  unbound `:179` listener and routes each accepted connection to the
  owning VRF task by source IP. Without this sysctl the kernel drops a
  SYN that arrives on a VRF (l3mdev) interface (there is no listener in
  the VRF table), and the session stays stuck in `Active`. zebra-rs now
  sets it at startup alongside `net.vrf.strict_mode`.
* **Per-VRF passive accept** — the per-VRF task drives both the active
  connect and, now, the passive accept, so two per-VRF speakers (the two
  ASBRs) resolve an RFC 4271 §6.8 collision into `Established`.

## Forwarding

The VPN label terminates at each ASBR; the inter-AS link carries plain
IP inside the VRF. A packet from `ce1` to a host in `ce2`'s subnet:

| Hop | Action |
|---|---|
| `pe1` | VRF lookup → push `[SR→asbr1, VPN]`, send over the core |
| `p1` | SR penultimate-hop pop |
| `asbr1` | pop the VPN label → VRF lookup → forward **plain IP** to `asbr2` over the inter-AS VRF link |
| `asbr2` | receive plain IP in `vrf-cust` → VRF lookup → push `[SR→pe2, VPN]` |
| `p2` | SR penultimate-hop pop |
| `pe2` | pop the VPN label → VRF lookup → to `ce2` |

## Verification

The inter-AS PE-CE session is a VRF session, shown under
`show ip bgp vrf vrf-cust summary`:

```
asbr1$ show ip bgp vrf vrf-cust summary
Neighbor    V    AS  MsgRcvd MsgSent ... State/PfxRcd
172.16.0.2  4 65001        3       3 ... Established 1
```

The customer prefixes appear in each `vrf-cust` table — the local-AS one
labeled (imported from intra-AS VPNv4), the remote-AS one plain (learned
over the PE-CE eBGP):

```
asbr1$ show ip route vrf vrf-cust
B *> 10.1.0.0/30 [200/0] via 10.0.0.5, p1, label 16001 16   # from PE1 (VPNv4)
B *> 10.2.0.0/30 [20/0]  via 172.16.0.2, asbr2              # from ASBR2 (PE-CE)
C *> 172.16.0.0/30 is directly connected, asbr2
```

The remote-AS prefix reaches the far PE's VRF too, and CE-to-CE traffic
forwards:

```
pe1$  show ip route vrf vrf-cust   # contains 10.2.0.0/30
ce1$  ping <host in ce2's subnet>  # succeeds
```

## BDD coverage

`bdd/tests/features/bgp_interas_option_a.feature` builds the eight-
namespace topology above and asserts the IS-IS SR adjacencies, the
SR-MPLS ILM entries, the intra-AS VPNv4 sessions, the customer prefixes
crossing the boundary over the per-VRF PE-CE eBGP, the far-PE VRF import,
and an end-to-end CE-to-CE ping.
