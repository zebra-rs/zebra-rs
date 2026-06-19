# Egress Protection (Mirror SID)

[TI-LFA](ch-12-00-nexthop-protect.md) protects the path *through* the
network — transit nodes and links — but it cannot protect the **egress
PE itself**. The egress is the endpoint of the SR path; when it fails the
destination becomes unreachable on that path, and there is no transit
node to bypass. **Mirror SID** egress protection closes that gap: a
backup PE takes over forwarding for a failed primary egress **without
changing the service SID inside the packet**.

The mechanism (RFC 8402 Mirror Context segment; RFC 8667 for SR-MPLS;
`draft-ietf-rtgwg-srv6-egress-protection` for SRv6 End.M) has three
roles:

| Role | Who | Does what |
|---|---|---|
| **PEA** | primary egress (protected) | normal egress forwarding |
| **PEB** | protector / backup egress | advertises a **Mirror SID** for PEA and reproduces PEA's service forwarding in a *mirror-context* table |
| **PLR** | upstream node (or PEA itself, for link protection) | on failure, pushes the Mirror SID and steers traffic to PEB |

The customer edge (CE) is typically **dual-homed** to PEA and PEB. On
egress failure the PLR redirects traffic to PEB, which processes the
inner packet *as if it were PEA* — for SRv6 this is the **End.M**
behavior (decapsulate, then look the inner packet up in the
mirror-context FIB). The protected egress's service SIDs are learned at
PEB out of band (BGP L3VPN or local configuration), not flooded
per-service in the IGP.

`egress-protection` is configured on the **protector (PEB)**: each
`protect` entry names one egress this node backs up.

## Configuration

A `protect` entry is keyed by the **SRv6 locator of the protected
egress** and lives under `router isis`:

```text
router isis {
  net 49.0000.0000.0000.0004.00;        // this node = PE4 (the protector, PEB)
  segment-routing {
    srv6 {
      locator PE4;                        // local locator, e.g. 2001:db8:a4:1::/64
    }
  }
  egress-protection {
    protect 2001:db8:a3:1::/64 {          // back up PE3 (PEA), whose locator is a3:1::/64
      mirror-sid 2001:db8:a4:1::3;        // End.M SID — must lie inside PE4's own locator
      via-vrf cust;                        // local VRF whose forwarding reaches the dual-homed CE
      dataplane srv6;                      // srv6 (default) | mpls
    }
  }
}
```

The same configuration in YAML:

```yaml
router:
  isis:
    egress-protection:
      protect:
      - protected-locator: 2001:db8:a3:1::/64
        mirror-sid: 2001:db8:a4:1::3
        via-vrf: cust
        dataplane: srv6
```

### The leaves

- **`protected-locator`** (key, `ipv6-prefix`) — the SRv6 locator of the
  protected egress PE. This is what gets advertised in the Protected
  Locators sub-sub-TLV of the Mirror SID advertisement and what the PLR
  matches traffic against. One `protect` entry protects one locator;
  configure several entries to protect several egresses.

- **`mirror-sid`** (`ipv6-address`, optional) — the Mirror SID (End.M)
  this node advertises on behalf of the protected egress. It **must lie
  within this node's own SRv6 `locator`**, because the protector owns and
  instantiates it. When omitted, a SID is auto-allocated from the local
  locator.

- **`via-vrf`** (`string`, optional) — the name of the local VRF whose
  forwarding reaches the dual-homed CE. The mirror-context FIB resolves
  the protected egress's service SIDs in this VRF. This is the
  configuration-driven way to populate the context; learning the service
  behavior from BGP L3VPN is the alternative (and is added later).

- **`dataplane`** (`srv6` | `mpls`, default `srv6`) — which dataplane the
  Mirror SID protects. `srv6` advertises the End.M Mirror SID sub-TLV
  inside the SRv6 Locator TLV; `mpls` advertises the SID/Label Binding
  TLV (RFC 8667) with the Mirror (M) flag set. SRv6 is the primary
  target; SR-MPLS is wired in a later stage.

## Scope and guidance

Mirror SID egress protection is, by the IETF draft's own guidance,
intended for **structured dual-homing and modest service counts within a
single IS-IS level/area**. Prefer a single protector (PEB) per protected
egress (PEA). It is *not* meant for large VPN cardinality or arbitrary
multi-homing — the IGP only ever carries the locator-level
`<PEB, PEA, Mirror SID>` binding, never per-service state.

## Verification

`show isis egress-protection` lists the configured entries and, per
entry, whether it is currently advertised. An entry is advertised when it
is on the SRv6 dataplane, has an explicit `mirror-sid`, and that SID falls
inside this node's own SRv6 locator:

```text
> show isis egress-protection
Protected-Locator      Mirror-SID               DP    Via-VRF    Advertised
2001:db8:a3:1::/64     2001:db8:a4:1::3         srv6  cust       yes
```

When advertised, the Mirror SID rides in the SRv6 Locator TLV of this
node's LSP, alongside the node's own End SID, and is visible in the
database on the protector and on every peer:

```text
> show isis database detail
...
  SRv6 Locator: 2001:db8:a4:1::/64 (Metric: 0)
    SRv6 End SID: Behavior: uN, SID value: 2001:db8:a4:1::, ...
    SRv6 Mirror SID: Behavior: End.M, SID value: 2001:db8:a4:1::3, Flags: 0
      Protected Locator: 2001:db8:a3:1::/64
```

The protector also installs the **End.M localsid** in the kernel — a
`seg6local` decap that looks the inner packet up in a dedicated
mirror-context routing table:

```text
> ip -6 route show 2001:db8:a4:1::3
2001:db8:a4:1::3  encap seg6local action End.DT6 table 1291845632 dev sr0
```

(`End.DT6` is the kernel action End.M reuses; the high table id is the
shared mirror-context table.)

When `via-vrf` is configured, the protector also populates the
mirror-context table: the protected locator is routed to a second
`seg6local End.DT46` that decapsulates into the named local VRF, so the
End.M lookup of the protected egress's service SID resolves through to
the CE:

```text
> ip -6 route show table 1291845632
2001:db8:a3:1::/64  encap seg6local action End.DT46 vrftable <cust-table> dev sr0
```

## Current status

The configuration, the IS-IS **advertisement** of the Mirror SID (SRv6
End.M sub-TLV with the Protected Locators sub-sub-TLV), the `show isis
egress-protection` view, the protector's **End.M localsid install**, and
the **static `via-vrf` mirror-context population** are implemented. Still
landing in later stages: auto-allocation of the Mirror SID when
`mirror-sid` is omitted, learning the context population from **BGP
L3VPN** (the alternative to static `via-vrf`), and the **PLR-side
repair** that pushes the Mirror SID on egress failure. So today a
configured entry is advertised and the full protector decap chain is in
place, but traffic is only redirected once a PLR steers it (the next
stage); SR-MPLS (`dataplane mpls`) is also a later stage.
