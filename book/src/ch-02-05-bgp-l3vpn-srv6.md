# BGP L3VPN over an SRv6 Underlay

zebra-rs implements BGP/MPLS IP VPNs over an **SRv6** data plane as
specified in RFC 9252. It is the SRv6 variant of the
[per-VRF-label L3VPN](ch-02-04-bgp-l3vpn.md): the control plane is the
same — VPNv4 / VPNv6 routes with a Route Distinguisher, route-target
import/export, recursive next-hop resolution, per-VRF FIB arbitration —
but the per-VRF MPLS service label is replaced by an **SRv6 End.DT46
SID**, and the transport tunnel is native IPv6 with a Segment Routing
Header instead of an MPLS label stack.

The two ends of a VPN flow map as follows:

* the **egress PE** binds one **End.DT46** SID to each VRF, carved from a
  Segment Routing **locator**, and programs a `seg6local` decap that
  pops the outer IPv6 / SRH and looks the inner packet up in the VRF
  table;
* the **ingress PE** learns that SID from the advertising PE's BGP
  Prefix-SID attribute and installs imported routes with an **H.Encap**
  next-hop — outer IPv6 destination = the remote SID, forwarded
  natively over the IPv6 underlay.

One End.DT46 SID serves both address families (`DT46` = the dual-family
decap), so a single per-VRF SID terminates VPNv4 and VPNv6 alike.

## The moving parts

An SRv6 L3VPN PE on zebra-rs touches three configuration trees:

* the global **`segment-routing` locator** supplies the IPv6 prefix that
  per-VRF service SIDs are carved from (the same locators IS-IS
  advertises into the SR domain);
* the **`router bgp segment-routing srv6 locator`** names which locator
  BGP draws its service SIDs from (mirrors `router isis segment-routing
  srv6 locator`; BGP has no SR-MPLS sibling);
* the per-VRF **`encapsulation srv6`** opts a VRF into the SRv6 data
  plane (the default is `mpls`).

```
segment-routing {
  locator LOC1 {
    prefix 2001:db8:1::/48;
  }
}

router bgp {
  global {
    as 65000;
  }
  segment-routing {
    srv6 {
      locator LOC1;
    }
  }
  vrf vrf1 {
    rd 65000:1;
    encapsulation srv6;
    neighbor 10.100.0.2 {
      remote-as 65001;
    }
    afi-safi ipv4 {
      network 192.168.5.0/24;
    }
  }
}

vrf vrf1 {
  ipv4 {
    route-target {
      import 65000:1;
      export 65000:1;
    }
  }
}
```

| Config | Meaning |
|---|---|
| `segment-routing locator <name> prefix <p>` | An IPv6 locator prefix SIDs are carved from |
| `router bgp segment-routing srv6 locator <name>` | The locator BGP carves per-VRF End.DT46 SIDs from |
| `router bgp vrf <name> encapsulation srv6` | Use the SRv6 data plane for this VRF (default `mpls`) |
| `router bgp vrf <name> rd <RD>` | Route Distinguisher for this VRF's VPN NLRI |
| `vrf <name> {ipv4,ipv6} route-target import/export <RT>` | Which VPN routes land in / leave the VRF |

The RD and route-target machinery are unchanged from the MPLS chapter —
only the data-plane encapsulation differs. A VRF left at the default
`encapsulation mpls` keeps the RFC 4364 per-VRF label and an AF_MPLS
decap; flipping it to `srv6` swaps both the advertised forwarding token
and the kernel programming.

## Per-VRF service SID allocation

Each `encapsulation srv6` VRF that BGP runs gets one **End.DT46** SID,
allocated when its per-VRF task spawns and reclaimed when the VRF is
removed. The SID address is the locator prefix with a per-VRF *function*
appended:

* BGP subscribes to the named locator through the RIB's Segment Routing
  manager. The locator resolves asynchronously (its prefix is published
  once committed), so a VRF configured before the locator lands spawns
  SID-less and is reconciled — given a SID and re-advertised — the
  moment the locator resolves. A locator prefix change re-seeds every
  srv6 VRF's SID.
* The function is drawn from a BGP-specific band (`0x0040`–`0xDFFF`),
  kept **below** the IS-IS adjacency-SID (End.X) range so that BGP and
  IS-IS can safely draw service SIDs from the *same* locator without
  colliding.
* The resulting SID — e.g. `2001:db8:1:40::` for function `0x40` under
  `2001:db8:1::/48` — is what the egress PE programs as a decap and what
  it advertises to remote PEs.

Because the SID carries the forwarding semantics, an `encapsulation
srv6` VRF advertises **no MPLS service label** (the label field of the
VPN NLRI is zero) and installs no AF_MPLS decap.

## Control plane

Every VPNv4 / VPNv6 route an srv6 VRF originates carries two extra
pieces relative to the MPLS case:

* a **BGP Prefix-SID attribute** (RFC 8669) with an **SRv6 L3 Service
  TLV** (RFC 9252) holding the VRF's End.DT46 SID and its endpoint
  behavior. The full SID is in the TLV (no label transposition).
* an **IPv6 next-hop** — the PE's locator address — instead of
  next-hop-self with the session's local address. For VPNv4 NLRI this
  uses the RFC 8950 encoding (a VPN-IPv4 route reachable via an IPv6
  next-hop); VPNv6 carries it natively.

A remote PE resolves the IPv6 next-hop through its IGP to reach the
advertising PE, and reads the End.DT46 SID from the Prefix-SID
attribute to build the encapsulation. The next-hop is preserved
end-to-end (not rewritten next-hop-self) so the locator stays
resolvable.

## Forwarding plane

**Egress decap (this PE terminates its own SID).** For each srv6 VRF,
the End.DT46 SID is programmed as a `seg6local` route that pops the
outer IPv6 / SRH and looks the decapsulated inner IPv4 *or* IPv6 packet
up in the VRF's kernel table:

```
$ ip -6 route show
...
2001:db8:1:40:: encap seg6local action End.DT46 vrftable 10 dev lo proto bgp
```

`End.DT46` is the dual-family decap, and `vrftable 10` is `vrf1`'s
kernel table — the kernel resolves both inner families there. (Contrast
the MPLS PE, whose decap is an `ip -f mpls route` pop-to-`dev vrf1`
entry.)

**Imported remote-PE routes (this PE is the ingress).** A VPN route
imported into the VRF installs into the VRF table with an SRv6 H.Encap
next-hop: the matched packet is wrapped in an outer IPv6 header (and
SRH) whose destination is the remote PE's End.DT46 SID, then forwarded
to the resolved underlay next-hop. CE-learned routes in the same VRF
install as plain next-hop entries:

```
$ ip route show table 10
9.9.9.9  encap seg6 mode encap segs 1 2001:db8:2:40:: via fe80::5 dev enp0s6 proto bgp
192.168.6.0/24  encap seg6 mode encap segs 1 2001:db8:2:40:: via fe80::5 dev enp0s6 proto bgp
1.2.3.4 nhid 7 via 10.100.0.2 dev enp0s8 proto bgp onlink
```

* `9.9.9.9` and `192.168.6.0/24` are **imported** VPN routes:
  `encap seg6 mode encap segs 1 2001:db8:2:40::` H.Encaps to the remote
  PE's End.DT46 SID, forwarded via the resolved IPv6 underlay next-hop
  `fe80::5 dev enp0s6`. The kernel routes the encapped packet by its
  outer destination (the SID's locator, learned from the IGP).
* `1.2.3.4` is **CE-learned** inside the VRF — a plain next-hop entry,
  no encap — installed alongside the imported routes by the per-VRF FIB
  arbitration (whichever path wins best-path in the VRF's Loc-RIB is the
  one programmed).

As in the MPLS case, a route is only advertised and installed once its
next-hop resolves, so an unreachable underlay never produces a
black-holing FIB entry; when the underlay reroutes, the H.Encap entry
is re-resolved and re-installed.

## Relationship to the MPLS path

The SRv6 underlay reuses the entire MPLS L3VPN control plane — RD/RT
handling, the per-VRF task model, best-path and FIB arbitration,
next-hop tracking. The differences are localized to the forwarding
token:

| | MPLS (RFC 4364) | SRv6 (RFC 9252) |
|---|---|---|
| Per-VRF token | Dynamic MPLS label | End.DT46 SID from a locator |
| Advertised next-hop | Next-hop-self (IPv4/IPv6) | PE locator (IPv6) |
| Service signalling | NLRI label field | Prefix-SID SRv6 L3 Service TLV |
| Egress decap | AF_MPLS pop → VRF device | `seg6local End.DT46 vrftable` |
| Ingress encap | `encap mpls <transport>/<service>` | `encap seg6 segs <SID>` |

Selecting between them is per VRF: `encapsulation mpls` (the default) or
`encapsulation srv6`.
