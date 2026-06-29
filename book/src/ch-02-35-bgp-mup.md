# BGP Mobile User Plane (MUP) and the MUP Controller

zebra-rs implements **BGP Mobile User Plane** (BGP-MUP, SAFI 85) as
specified in RFC 9833 / `draft-mpmz-bess-mup-safi`. BGP-MUP carries 5G
mobile-backhaul session state in BGP so that a GTP-U tunnel between a
mobile gateway and the radio access network can be stitched into an
**SRv6** transport network — the GTP encap/decap happens at the SRv6
edge instead of on a dedicated mobile gateway.

There are four MUP route types:

| Type | Name | Originated by |
|---|---|---|
| 1 | Interwork Segment Discovery (ISD) | MUP-GW / PE |
| 2 | Direct Segment Discovery (DSD) | MUP-GW / PE |
| 3 | Type-1 Session Transformed (T1ST) | **MUP Controller** |
| 4 | Type-2 Session Transformed (T2ST) | **MUP Controller** |

The **MUP Controller (MUP-C)** is the node that learns per-session
mobile state — the UE address, the GTP-U TEID, the tunnel endpoint, the
QoS flow — and turns each session into a **Session-Transformed** route
(T1ST for the access/downlink side, T2ST for the core/uplink side). The
draft leaves the controller's session source as an out-of-scope
"northbound API"; zebra-rs uses **PFCP / N4** (3GPP TS 29.244) as that
northbound and terminates it as a UP-node — an external SMF programs the
controller exactly as it would a UPF.

```
   SMF ──PFCP/N4──▶ zebra-rs MUP-C ──BGP MUP (SAFI 85)──▶ SRv6 PEs
 (sessions)            learns UE/TEID/NI,                (resolve the
                       originates T1ST/T2ST               segment, install
                       (no SID — see below)               End.DT46 forwarding)
```

The PEs originate the **segment** routes — DSD (`segment direct`) and ISD
(`segment interwork`) — that advertise their per-VRF **End.DT46** SID; the
controller's ST routes carry no SID and a receiving PE derives forwarding by
resolving each ST route against the matching segment (the
draft-ietf-bess-mup-safi default).

The MUP control plane (capability negotiation, Loc-RIB, receive, and
re-advertisement) is always present once the `mup` AFI/SAFI is
negotiated. The **controller** — the PFCP listener and route origination
— is what the `mup-c` block below turns on.

## Enabling the MUP capability

`mup` is a single AFI/SAFI knob that negotiates **both**
IPv4-MUP (AFI 1) and IPv6-MUP (AFI 2). Enable it per neighbor like any
other family:

```
router bgp {
  global {
    as 65001;
    router-id 192.168.0.1;
  }
  neighbor 192.168.0.2 {
    remote-as 65001;
    afi-safi ipv4 {
      enabled true;
    }
    afi-safi mup {
      enabled true;
    }
  }
}
```

## Configuring the controller

The controller's `mup-c` block sits **directly under the BGP instance**
(`router bgp { mup-c { … } }`). It needs three things: a per-VRF `mup`
service that maps a PFCP Network Instance to a Route Distinguisher /
route-targets, the `mup-c` block itself, and — only for the non-default
explicit-SID mode — an SRv6 locator.

```
segment-routing {
  locator LOC1 {
    prefix fcbb:bb01::/48;
  }
}
router bgp {
  global {
    as 65001;
    router-id 192.168.0.1;
  }
  segment-routing {
    srv6 {
      locator LOC1;
    }
  }

  # Map the PFCP Network Instance "access" to a VPN service: the RD
  # stamped on the ST route and the ST route type it originates.
  vrf mobile-up {
    rd 65000:100;
    afi-safi mup {
      route st1 {
        network-instance access;
      }
    }
  }

  # Turn on the controller: the PFCP/N4 listener + route origination.
  # The `mup-c` block sits directly under the BGP instance.
  mup-c {
    enable true;
    controller-address fcbb:bb01::1;
    pfcp {
      listen-address 192.168.0.1;
      port 8805;
    }
    srv6 {
      locator LOC1;
    }
  }
}

# The route-targets MUP routes carry (export) and pull in (import) live on
# the top-level VRF, the same `route-target {import|export}` framework as
# ipv4 / ipv6.
vrf mobile-up {
  mup {
    route-target {
      export 65000:200;   # stamp this RT on every MUP route this VRF originates
      import 65000:200;   # pull in any MUP route carrying this RT
    }
  }
}
```

* **`enable true`** spawns the in-process controller. It is configured
  under the BGP instance (not as a separate daemon) so that it is handed
  the BGP instance's own channel, the same way a per-VRF BGP instance is
  — route origination is a direct in-process call, not a cross-process
  hop.
* **`controller-address`** is the IPv6 address advertised as the next
  hop on every originated ST route.
* **`pfcp`** sets the N4 listener bind address and port (default
  `[::]:8805`).
* **`srv6 locator`** is **reserved** for the non-default mode where the
  controller pushes an explicit SID; in the default mode it is unused.
  Per draft-ietf-bess-mup-safi the controller originates ST routes
  **without** a service SID — the receiving PE derives forwarding from
  its own ISD/DSD routes — so no per-session SID is allocated.

A VRF binds one ST direction to a PFCP Network Instance under `afi-safi
mup route {st1|st2}`; the two read identically:

* **Downlink (Type-1 ST).** `afi-safi mup route st1 { network-instance
  <ni>; }` — the N6 VRF originates a **Type-1 ST** route carrying the UE
  prefix (ingress GTP encapsulation).
* **Uplink (Type-2 ST).** `afi-safi mup route st2 { network-instance <ni>;
  mup-ext-comm <2:4>; }` — the N3 VRF originates a **Type-2 ST** route
  carrying the core endpoint and the GTP TEID (egress GTP decapsulation).
  The optional `mup-ext-comm` is the BGP MUP Extended Community
  (Direct-segment id in RD/RT 2:4 form, e.g. `1:2`) the ST2 resolves to.

The configured network-instance is matched exactly against the PFCP
session's Network Instance. The export route-targets the ST route carries
come from the top-level `vrf <name> mup route-target export` — the same
`route-target` framework as `ipv4` / `ipv6`.

A single PFCP session originates **every** matching ST route: if both an
st1 VRF and an st2 VRF bind the same Network Instance, one session
originates both the Type-1 and the Type-2 ST.

For example, an uplink VRF that also originates the Direct segment it
resolves to:

```
vrf N3 {
  rd 65000:100;
  encapsulation srv6;
  afi-safi mup {
    route st2 {
      network-instance core;   # originate an ST2 for PFCP sessions on NI "core"
      mup-ext-comm 1:2;        # the Direct segment id it resolves to
    }
    segment direct {
      mup-ext-comm 1:2;        # originate the End.DT46 DSD with the same id
    }
  }
}
```

### Segment Discovery routes (`segment direct` / `segment interwork`)

A PE VRF with `encapsulation srv6` carves a per-VRF **End.DT46** SID from
the locator and installs the `seg6local` decap. `afi-safi mup segment`
advertises that segment so a receiving PE can resolve matching ST routes to
it:

* **`segment direct { mup-ext-comm <2:4>; }`** originates a **Direct
  Segment Discovery (DSD, type 2)** route — NLRI = RD + router-id — carrying
  the End.DT46 SID and the Direct-segment id (`mup-ext-comm`). A receiving
  *interwork* node (`segment interwork`) matches each received ST2 to the
  DSD by this id and `show bgp mup` prints the resolution.
* **`segment interwork { prefix <p>; }`** originates an **Interwork Segment
  Discovery (ISD, type 1)** route — NLRI = RD + the configured `prefix`
  (typically the locally connected gNodeB N3 prefix; its family selects the
  AFI) — carrying the End.DT46 SID. The ISD does not originate until the
  prefix is set, and carries no `mup-ext-comm` (an ISD is resolved by
  endpoint-address lookup).

```
vrf N6 {
  rd 65501:10;
  encapsulation srv6;
  afi-safi mup {
    segment interwork {
      prefix 10.60.0.0/16;     # originate the End.DT46 ISD under this prefix
    }
  }
}
```

zebra-rs uses **End.DT46** for both Direct and Interwork segments; the
draft's GTP-interwork behaviours (GTP4.E / GTP6.E / H.M.GTP4.D) are
VPP/eBPF and not yet implemented.

## From PFCP session to ST route

When an SMF establishes a session, the controller:

1. extracts the UE IP address, the access-side F-TEID (TEID + GTP
   endpoint), and the Network Instance from the PFCP Session
   Establishment Request;
2. correlates the Network Instance against the per-VRF `mup` config to
   find the RD and the ST route type (`st1` / `st2`), and the VRF's
   export route-targets from the top-level VRF;
3. originates the ST route into the MUP Loc-RIB with the
   controller-address as next hop and the VRF's export route-targets —
   and **no** service SID (PE-derived forwarding, the draft default);
4. advertises it to every `mup` peer.

A Session Deletion withdraws the route. For an IPv6 UE whose GTP
endpoint is IPv4 (IPv4 N3 transport), the endpoint/source address family
is taken from its own length octet, so the route rides the IPv6-MUP AFI
while carrying the IPv4 endpoint.

## Route-target import and cross-VRF import

Per-VRF MUP follows the **same route-target import model as VPNv4/v6**: a
MUP route lands in a VRF when the route's route-targets overlap that VRF's
`mup route-target import` set — **not** when the route's RD matches the
VRF's `rd`. The RD on a MUP NLRI is just an identifier; which VRFs a route
reaches is driven entirely by route-targets.

This makes **cross-VRF import** work exactly as it does for L3VPN: a route
originated under one RD can be imported into a VRF whose own `rd` is
different, purely because the importing VRF's `import` RT matches an RT the
route carries.

```
vrf N6 {                      # rd 65501:20 — originates the ISD
  mup {
    route-target {
      export 65501:10;        # the ISD it originates carries RT 65501:10
      import 65501:10;        # …and N6 self-imports it, so it shows its own ISD
    }
  }
}
vrf N3 {                      # rd 65501:10 — a different VRF
  mup {
    route-target {
      export 65501:20;
      import 65501:10;        # N3 imports RT 65501:10 → pulls in N6's ISD
    }
  }
}
```

Here VRF N6 originates an ISD (`segment interwork`) whose NLRI carries RD
`65501:20` and RT `65501:10`. VRF N3's `rd` is `65501:10`, which does **not**
match the ISD's RD — yet because N3 imports RT `65501:10`, the ISD appears in
`show bgp vrf N3 mup`. N6 also imports `65501:10`, so it still shows its own
originated ISD.

Note the consequence: origination is **global**, while the per-VRF view is
**import-only**. A VRF therefore shows a route it originated in
`show bgp vrf <name> mup` only if it also imports that route's RT (as N6 does
above). The `@bgp_mup_vrf_import` BDD feature exercises exactly this cross-RD
import.

## Showing MUP state

`show bgp mup` renders the configured per-VRF services and the
MUP Loc-RIB:

```
# show bgp mup
MUP VRFs:
  mobile-up: rd=65000:100 encap/ST1 ni=access route-targets=1

   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:100][ue=192.0.2.5/32][teid=305419896][qfi=0][ep=10.0.0.1]
       next-hop fcbb:bb01::1  weight 32768
       rt:65000:200
```

`show bgp vrf <name> mup` renders the MUP routes that VRF imports — every
route whose route-targets overlap the VRF's `mup route-target import` set
(see [Route-target import and cross-VRF import](#route-target-import-and-cross-vrf-import) above), which may include routes
originated under a different RD. The authoritative MUP Loc-RIB and the
advertiser stay on the global instance; the RT-matched best-paths are
mirrored into the per-VRF task so the per-VRF view renders them:

```
# show bgp vrf mobile-up mup
   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:100][ue=192.0.2.5/32][teid=305419896][qfi=0][ep=10.0.0.1]
       next-hop fcbb:bb01::1  weight 32768
       rt:65000:200
```

`show bgp mup mup-c` shows the controller status, and the
`session` / `association` sub-commands show the learned PFCP state:

```
# show bgp mup mup-c
MUP controller (MUP-C)
  Admin state : enabled
  PFCP listen : 192.168.0.1:8805
  Associations: 1
  Sessions    : 1

# show bgp mup mup-c session
SEID       UE address     TEID         Endpoint     QFI   Network-Instance
1          192.0.2.5      0x12345678   10.0.0.1     -     access
```

`show bgp neighbor <addr>` reports the negotiated MUP capability:

```
  IPv4 MUP: advertised and received
  IPv6 MUP: advertised and received
```

## Testing with `pfcp-inject`

`tools/pfcp-inject` is a tiny PFCP/N4 SMF simulator used by the
`@bgp_mup_e2e` BDD feature and for manual validation. It sends an
Association Setup followed by a Session Establishment (and, with
`--delete`, a Session Deletion) describing one mobile session:

```
pfcp-inject --target 192.168.0.1 --port 8805 \
            --ue-ipv4 192.0.2.5 --teid 0x12345678 \
            --endpoint 10.0.0.1 --network-instance access
```

After it runs, the session appears under `show bgp mup mup-c
session` and the controller's ST route appears in `show bgp
mup` on both the controller and its peers.

## Scope and limitations

The control plane is complete: capability negotiation, ISD/DSD/T1ST/T2ST
codec, Loc-RIB receive/store/show, controller ST origination, PE-side
Segment Discovery origination (DSD and ISD, each with the per-VRF End.DT46
SID + `seg6local` decap installed into the kernel FIB), and the interwork
node's control-plane resolution of received ST2 routes to the matching
Direct segment.

The **GTP-interwork forwarding plane** is **not** implemented: the
End.DT46 decap that the segment routes advertise is installed, but the
GTP-U SRv6 endpoint behaviours themselves (GTP4.E / GTP6.E / H.M.GTP4.D)
have no stock-Linux `seg6local` action, so the actual GTP encap/decap is
left to a VPP/eBPF-based forwarder. The controller's PFCP northbound
currently handles Association and Session lifecycle messages;
heartbeat-driven eviction of idle associations is a follow-up.
