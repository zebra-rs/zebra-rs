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
 (sessions)          │ learns UE/TEID/NI                 (install
                     │ originates T1ST/T2ST               forwarding)
                     ▼
             SRv6 End.DT4/DT6 SID  (from a locator)
```

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

The controller lives under the **global** `mup` AFI/SAFI. It
needs three things: an SRv6 locator to carve per-session SIDs from, a
per-VRF `mup` service that maps a PFCP Network Instance to a
Route Distinguisher / route-targets, and the `mup-c` block itself.

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
    mup {
      route st1 {
        dest-network-instance access {
          exact access;
        }
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

# The export route-targets the ST routes carry live on the top-level VRF,
# the same `route-target {import|export}` framework as ipv4 / ipv6.
vrf mobile-up {
  mup {
    route-target {
      export 65000:200;
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

The VRF binds each direction to a PFCP Network Instance:

* **Downlink (Type-1 ST).** `mup route st1 dest-network-instance access
  exact <ni>` — the N6 VRF originates a **Type-1 ST** route carrying the
  UE prefix (ingress GTP encapsulation).
* **Uplink (Type-2 ST).** `afi-safi mup segment direct network-instance
  <ni>` — the N3 VRF originates a **Type-2 ST** route carrying the core
  endpoint and the GTP TEID (egress GTP decapsulation into the VRF's
  End.DT46 Direct segment). The ST2 NI binding lives next to `segment
  direct` because the ST2 resolves to that Direct segment; the route also
  carries the segment's BGP MUP Extended Community (`mup-ext-comm`, a
  Direct-segment id in RD/RT 2:4 form, e.g. `1:2`).

In both cases the configured network-instance is matched exactly against
the PFCP session's Network Instance. The export route-targets the ST route
carries come from the top-level `vrf <name> mup route-target export` — the
same `route-target` framework as `ipv4` / `ipv6`.

For example, an uplink VRF:

```
vrf N3 {
  rd 65000:100;
  encapsulation srv6;
  afi-safi mup {
    segment direct;          # originate the End.DT46 Direct Segment Discovery route
    mup-ext-comm 1:2;        # the Direct segment id (BGP MUP Ext-Comm 0x0c/0x00)
    network-instance core;   # originate an ST2 for PFCP sessions on NI "core"
  }
}
```

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
       RT:65000:200
```

`show bgp vrf <name> mup` renders just the ST routes belonging to one
VRF (those whose RD matches that VRF's `rd`). The authoritative MUP
Loc-RIB stays on the global instance; the matching best-paths are
mirrored into the per-VRF task so the per-VRF view renders them:

```
# show bgp vrf mobile-up mup
   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:100][ue=192.0.2.5/32][teid=305419896][qfi=0][ep=10.0.0.1]
       next-hop fcbb:bb01::1  weight 32768
       RT:65000:200
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

The control plane — capability negotiation, ISD/DSD/T1ST/T2ST codec,
Loc-RIB receive/store/show, and controller origination + advertisement —
is complete. The forwarding plane (programming GTP4.E / GTP6.E
behaviours into the kernel) is **not** implemented: stock Linux has no
GTP-U SRv6 endpoint behaviour, so the data plane is left to a
VPP/eBPF-based forwarder. The controller's PFCP northbound currently
handles Association and Session lifecycle messages; heartbeat-driven
eviction of idle associations is a follow-up.
