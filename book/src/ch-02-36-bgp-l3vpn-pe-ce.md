# L3VPN PE-CE Routing Protocols

The [MPLS](ch-02-04-bgp-l3vpn.md) and [SRv6](ch-02-05-bgp-l3vpn-srv6.md)
L3VPN chapters describe how a VRF's routes cross the provider core as
VPNv4 / VPNv6. This chapter is about the **other** edge: how customer
routes get *into* a VRF at the ingress PE and *back out* to the customer
at the egress PE — the PE-CE routing protocol and the redistribution
that bridges it to the VPN.

The reference topology is a customer with two sites joined across the
provider core:

```
[C1] --- [CE1] --- [PE1] --- [P] --- [PE2] --- [CE2] --- [C2]
       C-CE       PE-CE     core     PE-CE      C-CE
```

`C1` and `C2` are customer routers that each originate a loopback; the
goal is `C1 ↔ C2` reachability. `CE` is the customer edge, `PE` the
provider edge, `P` a core transport router. The provider core runs an
SR-MPLS or SRv6 IGP (IS-IS / OSPF) and iBGP VPNv4 / VPNv6 between the
PEs, exactly as the previous two chapters describe. What this chapter
adds is the PE-CE span.

## The two directions

A PE-CE deployment always has two redistribution directions, and it is
worth naming them explicitly because the config knobs differ:

* **up** (customer → VPN): the PE learns the customer's routes from the
  PE-CE protocol and originates them into VPNv4 / VPNv6 for the remote
  PE. This is `router bgp vrf <name> afi-safi <af> redistribute <proto>`
  (or a BGP PE-CE session, whose routes import automatically, or a
  static `network`).
* **down** (VPN → customer): the PE takes the VPN routes it imported
  into the VRF and hands them to the customer over the PE-CE protocol.
  For a BGP PE-CE session this is automatic (the imported routes are
  advertised to the CE). For an **IGP** PE-CE protocol the PE must
  redistribute BGP into the IGP: `router {ospf|ospfv3|isis} vrf <name>
  redistribute bgp`.

The `redistribute bgp` knob on the per-VRF IGP is the piece that closes
the loop for an IGP PE-CE: without it, the VPN routes would reach the
VRF but never be told to the customer.

## Supported PE-CE protocols

| PE-CE protocol | up (→ VPN) | down (VPN →) | Notes |
|---|---|---|---|
| **BGP** (eBGP in the VRF) | session import | session advertise | `router bgp vrf <name> neighbor` |
| **Static** | `redistribute static` | n/a (host points default at PE) | per-VRF static routes |
| **OSPFv2** (IPv4) | `redistribute ospf` | `redistribute bgp` → Type-5 | `router ospf vrf <name>` |
| **OSPFv3** (IPv6) | `redistribute ospf` | `redistribute bgp` → Type-5 | `router ospfv3 vrf <name>` |
| **IS-IS** (v4 + v6) | `redistribute isis` | `redistribute bgp` | `router isis vrf <name>` |

The transport split from the SRv6 chapter applies here too: IPv4 PE-CE
rides **MPLS** VPNv4, IPv6 PE-CE rides **SRv6** VPNv6 (zebra-rs has no
6VPE, so VPNv6 needs an IPv6 / SRv6 transport). A dual-stack site runs
the v4 protocol over the MPLS VPN and the v6 protocol over the SRv6 VPN.

## BGP PE-CE

The simplest case, and the one the previous two chapters already show: a
per-VRF eBGP session to the CE. Customer routes arrive as eBGP NLRI and
import into VPNv4 / VPNv6 automatically; VPN routes imported into the VRF
are advertised back to the CE automatically. No redistribute knob is
needed in either direction.

```
router bgp {
  vrf vrf-cust {
    rd 65000:1;
    neighbor 10.1.0.5 {
      remote-as 65001;
    }
  }
}
```

A v6 PE-CE neighbor activates `afi-safi ipv6` on the per-VRF neighbor;
a v4 neighbor activates `afi-safi ipv4`.

## IGP PE-CE — two deployment variants

When the customer runs an IGP, there are two ways to wire it, and
zebra-rs supports both.

### Variant 1 — IGP on both the C-CE and PE-CE segments

The customer's IGP extends all the way to the PE: `C`, `CE`, and the
PE's VRF all speak the same IGP. The PE runs **two** IGP instances — the
global one for the SR core, and a **per-VRF** one facing the CE — and
bridges the per-VRF IGP to BGP in both directions:

```
router isis {
  vrf vrf-cust {
    net 49.0001.0000.0000.0001.00;
    afi-safi ipv4 {
      redistribute bgp;          # down: VPN routes → IS-IS toward CE
    }
    interface ce1 { ipv4 { enable; } }
  }
}

router bgp {
  vrf vrf-cust {
    rd 65000:1;
    afi-safi ipv4 {
      redistribute isis;         # up: CE's IS-IS routes → VPNv4
    }
  }
}
```

The customer router `C` originates its loopback into the IGP (with
`redistribute connected` for IS-IS / OSPFv2, or by enabling the loopback
in the area for OSPFv3, which has no instance-level
redistribute-connected). `CE` is a plain transit IGP router. The mutual
redistribution does **not** loop: a router never installs a RIB route
for an external it self-originated, so the PE's `redistribute isis` only
picks up the CE's routes, not the ones it injected with `redistribute
bgp`.

### Variant 2 — IGP on C-CE, BGP on PE-CE

Only the `C-CE` segment runs the IGP; the `CE-PE` link is eBGP. Here the
**CE** is the router that bridges, and the PE is a plain BGP PE-CE edge
(Variant-2 reuses the BGP PE-CE config above unchanged). The CE
redistributes in both directions:

```
router ospf {
  redistribute bgp { metric 20; }   # down: eBGP routes → OSPF toward C
  area 0.0.0.0 { interface c1 { enable; network-type point-to-point; } }
}

router bgp {
  global { as 65001; }
  neighbor 10.1.0.6 { remote-as 65000; }   # eBGP to PE
  afi-safi ipv4 {
    redistribute ospf;              # up: C's OSPF routes → eBGP to PE
    redistribute connected;         # see note below
  }
}
```

> **CE `redistribute connected` is required.** The C-CE link subnet is a
> *connected* route on the CE, not an IGP route, so `redistribute ospf`
> alone does not carry it into BGP. If a customer ping is sourced from
> that link address (rather than the loopback), the reply has no return
> path across the VPN. Adding `redistribute connected` on the CE's BGP
> advertises the link and closes the gap. (In Variant 1 the PE's
> `redistribute isis`/`ospf` already picks the link up, because there the
> link is an IGP route on the PE, not a connected one.)

## ASBR semantics (OSPF)

A router that runs `redistribute bgp` into OSPF is an AS Boundary Router:
the injected VPN routes become **Type-5 AS-External** LSAs (OSPFv2) or
AS-External LSAs (OSPFv3), and the router sets the E-bit in its
Router-LSA. OSPFv3 instance-level AS-External origination from
`redistribute bgp` is supported in both the global instance (Variant 2,
on the CE) and the per-VRF instance (Variant 1, on the PE).

## Convergence

An IGP-bridged PE-CE path has a longer convergence tail than a pure-BGP
one, because route information crosses an extra protocol boundary (and,
in Variant 2, the eBGP → iBGP → eBGP advertisement chain compounds the
per-hop BGP advertisement delay). A route is never advertised or
installed until its next-hop resolves, so a slow tail never black-holes;
it only delays first reachability.

## Validation

The full matrix — both variants × {BGP, static, OSPFv2/v3, IS-IS} ×
{IPv4/MPLS, IPv6/SRv6} — is exercised end-to-end (C1 ↔ C2 loopback ping
across the provider core) by the `l3vpn_*` BDD features under
`bdd/tests/features/`:

| Feature | PE-CE | AF / transport |
|---|---|---|
| `l3vpn_bgp_v4` / `_v6` | BGP | MPLS / SRv6 |
| `l3vpn_static_v4` / `_v6` | static | MPLS / SRv6 |
| `l3vpn_ospf_v4` / `_v6` | OSPF, both segments | MPLS / SRv6 |
| `l3vpn_isis_v4` / `_v6` | IS-IS, both segments | MPLS / SRv6 |
| `l3vpn_ospf_bgppe_v4` / `_v6` | OSPF C-CE + BGP PE-CE | MPLS / SRv6 |
| `l3vpn_isis_bgppe_v4` / `_v6` | IS-IS C-CE + BGP PE-CE | MPLS / SRv6 |
