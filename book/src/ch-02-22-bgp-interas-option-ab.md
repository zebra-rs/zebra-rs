# Inter-AS Option AB (VPNv4 between ASBRs, per-VRF forwarding)

Option AB is a vendor hybrid (not an RFC 4364 §10 sub-option) that
combines the two trade-offs of Option A and Option B:

- like **Option B**, a *single* MP-eBGP VPNv4/VPNv6 session between the
  ASBRs carries every VPN over one labelled link — no per-VPN interface;
- like **Option A**, each ASBR keeps a per-VPN **VRF** and forwards
  through it (the VPN label terminates at the ASBR → VRF lookup →
  re-impose), so per-VPN policy, filtering and accounting still apply.

So Option AB gives the scaling of B with the per-VPN control of A. The
ASBR imports the VPNv4 routes it receives into a VRF (for forwarding and
RT policy) and **re-exports** them — relaying a remote AS's prefixes to
its own PEs, and its PEs' prefixes to the other ASBR — all over the one
session. In zebra-rs this is enabled per VRF with `inter-as-hybrid`.

## Reference topology

This is the topology exercised by the `@bgp_interas_option_ab` BDD
feature (`bdd/tests/features/bgp_interas_option_ab.feature`):

```
          AS 65000                                  AS 65001
 ce1 ── pe1 ──── p1 ──── asbr1 ════════ asbr2 ──── p2 ──── pe2 ── ce2
        lo        lo       lo  172.16.0.0/30  lo     lo      lo
     1.1.1.1   1.1.1.2  1.1.1.3  (global)    2.2.2.3 2.2.2.2 2.2.2.1
  └ vrf-cust ┘      └ vrf-cust ┘        └ vrf-cust ┘    └ vrf-cust ┘
   10.1.0.0/30      (transit, no CE)   (transit, no CE)  10.2.0.0/30
```

`pe1` exchanges VPNv4 with `asbr1` over the IS-IS / SR-MPLS core; likewise
`pe2`/`asbr2`. The `asbr1`–`asbr2` link is in the **global** table and
carries a single-hop MP-eBGP VPNv4 session. Each ASBR holds `vrf-cust`
(with `inter-as-hybrid`) — but with **no interface and no CE**: it is a
pure transit VRF, present only to provide per-VPN forwarding and policy.

## How it differs from A and B

| | Option A | Option B | **Option AB** |
|---|---|---|---|
| Inter-AS sessions | one eBGP **per VRF** (PE-CE in the VRF) | one eBGP VPNv4 (global) | one eBGP VPNv4 (global) |
| ASBR VPN state | VRF per VPN | global VPNv4 table | **VRF per VPN** |
| Inter-AS link carries | plain IP (in the VRF) | labelled VPNv4 | labelled VPNv4 |
| ASBR data path | pop → VRF lookup → plain IP | label **swap** | pop → **VRF lookup** → re-impose |

## Configuration

PEs are ordinary intra-AS L3VPN PEs — identical to Options A/B and unaware
of the boundary. The ASBR holds a transit VRF and a single eBGP VPNv4
peer. The only Option-AB-specific knob is `inter-as-hybrid` on the VRF:

```yaml
# Top-level VRF: RT policy only (no interface — a pure transit VRF).
vrf:
- name: vrf-cust
  ipv4:
    route-target:
      import: [65000:100]
      export: [65000:100]
interface:
- if-name: asbr2
  ipv4: { address: 172.16.0.1/30 }   # inter-AS link, GLOBAL table
router:
  bgp:
    global: { as: 65000, router-id: 1.1.1.3 }
    neighbor:
    - remote-address: 1.1.1.1          # PE1, intra-AS VPNv4 iBGP
      remote-as: 65000
      update-source: 1.1.1.3
      enabled: true
      afi-safi:
      - { name: vpnv4, enabled: true }
    - remote-address: 172.16.0.2       # ASBR2, single-hop inter-AS eBGP VPNv4
      remote-as: 65001
      enabled: true
      afi-safi:
      - { name: vpnv4, enabled: true }
    vrf:
    - name: vrf-cust
      rd: 65000:2
      inter-as-hybrid: true            # re-export imported VPNv4 routes
```

No `next-hop-self` knob is needed: re-exported routes are *originated*
from the VRF, so the next-hop is rewritten to self automatically — to the
inter-AS link address on the eBGP leg, and to the ASBR loopback on the
iBGP leg (both resolvable by the receiver). MPLS input is auto-enabled on
every link, so the global inter-AS link forwards labelled packets with no
extra config.

## Re-exporting imported routes

An ordinary L3VPN VRF re-exports only the routes it *originates*
(`network` / redistribute / CE-learned). Option AB additionally
re-exports the routes it **imports** from VPNv4 — that is what lets an
ASBR relay AS 65001's prefixes to its own PEs. zebra-rs gates this on the
per-VRF `inter-as-hybrid` flag, so a normal VRF is unchanged.

Crucially, the ASBR **re-originates** each route from the VRF (a new RD,
the VRF's export RTs, next-hop-self) rather than *also* transparently
relaying the one it received: a received VPNv4 route an `inter-as-hybrid`
VRF imports is marked transit-only and is **not** advertised directly to
peers. Otherwise the same prefix would reach the next node under two RDs
(the relayed one and the re-originated one), and because a VRF's IP table
is keyed by prefix, the two would collide and the import would thrash.
Each node therefore sees the prefix under exactly one RD.

The obvious risk — a route imported from VPNv4, re-exported as VPNv4, then
re-imported into the same VRF — is already handled:

- the VRF that originated an export is **excluded from its own import
  fan-out** (the import dispatcher's skip-self), so a re-export never
  loops back into the VRF it came from; and
- the inter-AS leg is **eBGP**, so the AS-path loop check drops a route
  that returns to the AS that emitted it.

## Forwarding

Every hop carries an MPLS label; at each ASBR the label terminates into
the VRF and a new one is imposed. A packet from `ce1` to a host in `ce2`'s
subnet (a route originated by `pe2`):

| Hop | Action |
|---|---|
| `pe1` | VRF lookup → push `[SR→asbr1, ASBR1-VRF]`, send over the core |
| `p1` | SR penultimate-hop pop → `[ASBR1-VRF]` |
| `asbr1` | pop the VRF label → **vrf-cust lookup** → push `[ASBR2-VRF]`, send the **single** label to `asbr2` |
| `asbr2` | pop the VRF label → **vrf-cust lookup** → push `[SR→pe2, PE2-VRF]` onto the AS 65001 core |
| `p2` | SR penultimate-hop pop → `[PE2-VRF]` |
| `pe2` | pop the VRF label → vrf-cust lookup → to `ce2` |

Each ASBR uses one per-VRF label (one decap entry per VRF); the inner IP
lookup in the VRF disambiguates the many prefixes that share it. The
inter-AS link carries a single label (the ASBRs are directly connected,
so no transport label is needed there); the intra-AS legs carry two.

## Verification

Unlike Option B (prefixes in the global VPNv4 table), an Option AB ASBR
holds both prefixes in its **VRF** — the local-AS one from its PE, the
remote-AS one from the single inter-AS session:

```
asbr1$ show ip route vrf vrf-cust
B *> 10.1.0.0/30  via … p1            label <SR→pe1> <PE1-VRF>   # from PE1
B *> 10.2.0.0/30  via 172.16.0.2, asbr2  label <ASBR2-VRF>      # from ASBR2 (eBGP)
```

The remote-AS prefix reaches the far PE's VRF, and CE-to-CE traffic
forwards:

```
pe1$  show ip route vrf vrf-cust    # contains 10.2.0.0/30
ce1$  ping <host in ce2's subnet>   # succeeds
```

## BDD coverage

`bdd/tests/features/bgp_interas_option_ab.feature` builds the eight-
namespace topology above and asserts the IS-IS SR adjacencies, the
SR-MPLS ILM entries, the intra-AS VPNv4 sessions, the single-hop inter-AS
eBGP VPNv4 sessions, **every VPN prefix in both ASBRs' `vrf-cust` tables**
(the per-VRF state that distinguishes AB from B), the far-PE VRF import,
and an end-to-end CE-to-CE ping in both directions. The ASBRs lower their
MRAI so the inter-AS VPNv4 relay converges promptly.
