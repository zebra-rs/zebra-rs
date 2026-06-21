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
mirror-context FIB); for SR-MPLS it is a single **context-label** pop
into PEB's VRF (RFC 8679). The protected egress's service SIDs/labels are
learned at PEB out of band (BGP L3VPN or local configuration), not
flooded per-service in the IGP.

### Two protection models

| Model | PLR | Failure it covers | Status |
|---|---|---|---|
| **Node protection** | an upstream node | PEA's **node** fails (router down) | SRv6: the PLR repair plus stale-route retention keep the protected locator pointed at the protector across reconvergence (a service ping additionally needs ingress BGP-PIC) |
| **Link protection** | **PEA itself** | PEA's **PE–CE link** fails (PEA stays up) | implemented and validated end-to-end |

zebra-rs implements **egress link protection** as the validated path. PEA
stays fully up (IGP and BGP intact, still advertising the CE prefix), so
the ingress keeps forwarding to PEA; when PEA's PE–CE link fails, **PEA
acts as its own PLR** and redirects its own service traffic to PEB, which
delivers it over its own link to the dual-homed CE. This sidesteps the
harder node-protection pop (Linux has no per-context label table) while
covering the common dual-homing failure.

Both dataplanes are implemented:

| Dataplane | Mirror advertisement | What PEB installs |
|---|---|---|
| **SRv6** (`dataplane srv6`, default) | End.M Mirror SID sub-TLV inside the SRv6 Locator TLV (`draft-ietf-rtgwg-srv6-egress-protection`) | a `seg6local End.DT46` mirror-context decap |
| **SR-MPLS** (`dataplane mpls`) | SID/Label Binding TLV (149) with the **M-flag**, carrying a context label (RFC 8667 §2.4 + RFC 8679) | a context-label ILM (pop + decap into the VRF) |

> **SR-MPLS uses an IPv4 FEC.** IS-IS in zebra-rs has no IPv6 prefix-SID
> yet (it is deferred until SRv6-over-IS-IS lands), so the SR-MPLS
> transport — and therefore the protected egress's identity — is an
> **IPv4 loopback**. For `dataplane mpls`, the `protected-locator` is
> PEA's IPv4 IGP loopback (e.g. `1.1.1.3/32`); for `dataplane srv6` it is
> PEA's IPv6 SRv6 locator.

`egress-protection` is configured on the **protector (PEB)**: each
`protect` entry names one egress this node backs up.

## Configuration

`egress-protection` lives under `router isis` on the protector (PEB).
Each `protect` entry is keyed by the **prefix that identifies the
protected egress** — its SRv6 locator (SRv6) or its IPv4 loopback
(SR-MPLS).

### SRv6 (`dataplane srv6`)

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

### SR-MPLS (`dataplane mpls`)

The protected egress is identified by its **IPv4 loopback**, and the
context label is auto-allocated from the SRLB — there is **no
`mirror-sid`** for SR-MPLS:

```text
router isis {
  net 49.0000.0000.0000.0004.00;        // this node = PE4 (the protector, PEB)
  segment-routing mpls;
  te-router-id 1.1.1.4;                  // PEB's loopback (the transport identity)
  egress-protection {
    protect 1.1.1.3/32 {                  // back up PEA, whose IGP loopback is 1.1.1.3
      via-vrf cust;
      dataplane mpls;
    }
  }
}
```

```yaml
router:
  isis:
    segment-routing: mpls
    te-router-id: 1.1.1.4
    egress-protection:
      protect:
      - protected-locator: 1.1.1.3/32
        via-vrf: cust
        dataplane: mpls
```

For SR-MPLS, the protected egress (PEA) also needs nothing extra beyond a
normal SR-MPLS L3VPN setup: it carries the CE prefix in BGP L3VPN with a
per-VRF VPN label over the IS-IS Prefix-SID transport, and PEA learns the
protector's context binding from the IGP. On a PE–CE link failure PEA
rewrites its own VPN-label ILM to push the context label toward PEB — no
PEA-side egress-protection configuration is required.

### The leaves

- **`protected-locator`** (key, `ip-prefix`) — the prefix identifying the
  protected egress PE. For `dataplane srv6` it is PEA's **IPv6 SRv6
  locator** (advertised in the Protected Locators sub-sub-TLV of the
  Mirror SID); for `dataplane mpls` it is PEA's **IPv4 IGP loopback**
  (the FEC of the SID/Label Binding TLV). It is what the PLR / the
  protected egress matches traffic against. One `protect` entry protects
  one prefix; configure several entries to protect several egresses.

- **`mirror-sid`** (`ipv6-address`, optional, **SRv6 only**) — the Mirror
  SID (End.M) this node advertises on behalf of the protected egress. It
  **must lie within this node's own SRv6 `locator`**, because the
  protector owns and instantiates it. When omitted, a SID is
  auto-allocated from the local locator. Ignored for `dataplane mpls`,
  where the context label is auto-allocated from the SRLB.

- **`via-vrf`** (`string`, optional) — the name of the local VRF whose
  forwarding reaches the dual-homed CE. The mirror-context FIB (SRv6) or
  the context-label decap (SR-MPLS) routes the inner packet into this
  VRF. This is the configuration-driven way to populate the context;
  learning the service behavior from BGP L3VPN is the alternative.

- **`dataplane`** (`srv6` | `mpls`, default `srv6`) — which dataplane the
  Mirror context protects. `srv6` advertises the End.M Mirror SID sub-TLV
  inside the SRv6 Locator TLV; `mpls` advertises the SID/Label Binding
  TLV (149) with the Mirror (M) flag set, carrying a context label. Both
  are implemented for egress link protection.

One leaf sits beside `protect` (not inside it), governing node protection:

- **`hold-down`** (`uint32` seconds, under `egress-protection`) — bounds
  node-protection stale-route retention. After a protected egress's *node*
  fails, the PLR keeps its locator alive as a seg6 H.Encaps backup to the
  protector's Mirror SID (so the failover survives reconvergence); this
  caps how long that backup forwards before it is withdrawn, so a
  genuinely-decommissioned egress is not redirected to the protector
  forever. `0`/unset = no hold-down (the backup floats for as long as the
  protector advertises). Configured on the PLR, e.g. `router isis
  egress-protection hold-down 120`.

## Configuration guidelines

Mirror SID egress protection is, by the IETF draft's own guidance,
intended for **structured dual-homing and modest service counts within a
single IS-IS level/area**. Prefer a single protector (PEB) per protected
egress (PEA). It is *not* meant for large VPN cardinality or arbitrary
multi-homing — the IGP only ever carries the locator-level
`<PEB, PEA, Mirror SID/context label>` binding, never per-service state.

To stand up egress link protection, set up the two PEs and the CE so the
following hold:

1. **Dual-home the CE to both PEs in the same VRF.** PEA and PEB each have
   a PE–CE link in the protected VRF and each can reach the CE prefix
   inside it (a connected route, or `router static vrf` — see
   [Static Routes](ch-01-00-what-is-static-route.md)). PEB's link is the
   delivery path after failover.

2. **Let PEA be the sole BGP advertiser of the CE prefix.** PEA originates
   the CE prefix into BGP L3VPN with its per-VRF VPN label; PEB is a
   *pure protector* and does **not** originate it. Because PEA stays up on
   a PE–CE link failure, the ingress keeps its single route via PEA — PEA
   then redirects. (PEB still imports the *other* side's routes so the
   return path resolves.)

3. **Match the dataplane to the transport.** Use `dataplane srv6` with an
   SRv6 locator key when the L3VPN rides SRv6, and `dataplane mpls` with
   PEA's IPv4 loopback key when it rides SR-MPLS (IS-IS Prefix-SID
   transport + per-VRF MPLS VPN labels). The `protected-locator` family
   must match: IPv6 for SRv6, IPv4 for SR-MPLS.

4. **Set `via-vrf` to the protected VRF on PEB.** This is what lets the
   Mirror context / context label decapsulate into the VRF that reaches
   the CE. Without it the binding is held but the decap is not installed
   (it installs automatically once the VRF appears, so ordering is safe).

5. **Configure `egress-protection` only on PEB.** PEA needs *no*
   egress-protection stanza — it learns the protector's offer from the
   IGP and redirects its own forwarding. One `protect` entry per protected
   egress.

## Verification

### SRv6

`show isis egress-protection` lists the configured entries and, per
entry, whether it is currently advertised. An entry is advertised when it
is on the SRv6 dataplane, has an explicit `mirror-sid`, and that SID falls
inside this node's own SRv6 locator:

```text
> show isis egress-protection
Local egress-protection:
Protected-Locator      Mirror-SID               DP    Via-VRF    Advertised
2001:db8:a3:1::/64     2001:db8:a4:1::3         srv6  cust       yes
```

The same command on any node also lists the Mirror SIDs it has **received**
from peers — the PLR's view — so an upstream router can confirm it has
learned the protector's offer before relying on it:

```text
> show isis egress-protection
Received Mirror SIDs:
Protector          Mirror-SID               Protected-Locator
0000.0000.0004     2001:db8:a4:1::3         2001:db8:a3:1::/64
```

When advertised, the Mirror SID rides in the SRv6 Locator TLV of the
protector's LSP, alongside its own End SID, and is visible in the
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

While a redirect is **active** (the protected egress's PE–CE link is down
and it has steered its own service SID to the protector), the SID is
surfaced in `show segment-routing srv6 sid` — its canonical behavior plus
the live H.Encaps redirect target — so you don't have to read the kernel
LFIB to see the failover:

```text
> show segment-routing srv6 sid
 SID               Behavior   Context  Protocol  Locator  AllocationType
 ----------------------------  -------  --------  -------  --------------
 fcbb:bbbb:3:40::  End.DT46   -        bgp       LOC3     dynamic
    -> egress-protection redirect: H.Encaps to fcbb:bbbb:4:1::
```

The annotation clears when the link recovers and the SID returns to its
canonical End.DT46 decap.

### SR-MPLS

`show isis egress-protection` shows the same view for `dataplane mpls`,
with the auto-allocated **context label** in the SID/Context column:

```text
> show isis egress-protection
Local egress-protection:
Protected-Locator      SID/Context              DP    Via-VRF    Advertised
1.1.1.3/32             label 15000              mpls  vrf-cust   yes

Received Mirror Context labels:
Protector          Context-Label  Protected-FEC
0000.0000.0004     15000          1.1.1.3/32
```

The binding rides in the protector's LSP as a SID/Label Binding TLV with
the Mirror (M) flag, visible on every peer:

```text
> show isis database detail
...
  SID/Label Binding (Mirror Context): 1.1.1.3/32 label/index 15000
```

The protector installs the context label as a pop-and-decap ILM — it pops
the label and routes the inner packet into `via-vrf` (the same netlink
form as a BGP MPLS-VPN label, rendered `Mirror Ctx`):

```text
> show mpls ilm                                    # on the protector (PEB)
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
*> i 115  15000  Pop         Mirror Ctx (tbl 1) vrf-cust
```

On the protected egress (PEA) the per-VRF VPN label decaps normally into
the VRF (`VPN Decap`):

```text
> show mpls ilm                                    # on PEA
*> b 20   16     Pop         VPN Decap (tbl 1)  vrf-cust
```

When PEA's PE–CE link fails, PEA rewrites this label's **kernel** route
into a swap that pushes the context label toward the protector. Like the
SRv6 redirect, this is a FIB-level override: `show isis egress-protection`
and `show mpls ilm` keep reporting the canonical `VPN Decap` form, while
the kernel LFIB reflects the live redirect — inspect it directly:

```text
> ip -f mpls route                                 # on PEA, PE–CE link UP
16 dev vrf-cust proto bgp                              # pop + decap into the VRF

> ip -f mpls route                                 # on PEA, PE–CE link DOWN (redirected)
16 as to 15000 via inet 10.0.34.2 dev pea-peb proto isis   # swap 16 -> 15000 toward PEB
```

(The transport label to the protector is omitted here because PEB is a
directly-adjacent next hop under PHP; a non-adjacent protector would show
`16 as to <transport>/15000 …`.)

The redirect is **latched**: PEA restores the `VPN Decap` form only when
the VRF can deliver locally again (the link recovers). End to end, a
ping across the L3VPN keeps flowing through the failover and the
recovery, just over a different egress.

## Current status

**Egress link protection is implemented end-to-end on both dataplanes**
and validated on real-namespace BDD topologies.

- **SRv6** — Mirror SID **advertisement** (End.M sub-TLV + Protected
  Locators sub-sub-TLV), the `show isis egress-protection` view (local
  **and received**), the protector's **End.M localsid install**, the
  **static `via-vrf` mirror-context population**, the **PLR repair**
  (an H.Encaps-to-the-Mirror-SID backup with BFD-driven failover), and
  the **egress-as-its-own-PLR link redirect** (PEA redirects its own
  service SID to the protector on PE–CE link down, restored on recovery),
  and **node-protection stale-route retention** — a high-distance seg6
  H.Encaps floating backup to the Mirror SID that best-path promotes when
  PEA's node fails and its locator route is withdrawn, so the failover
  survives SPF reconvergence (not just the sub-second BFD window),
  optionally bounded by the `hold-down` timer.
- **SR-MPLS** — the SID/Label Binding TLV (149, M-flag) **advertisement**
  with a context label from the SRLB, **reception** into the
  `show isis egress-protection` view, the protector's **context-label
  ILM** (pop + decap into `via-vrf`), and the **egress link redirect**
  (PEA swaps its own VPN-label ILM to push the context label toward the
  protector, latched on link state).

Still landing in later stages: ingress **BGP-PIC** for an end-to-end
*service* failover on node loss (the retention keeps the locator route,
but the ingress must also keep forwarding to it); **SR-MPLS node
protection**
(blocked on stock Linux — no per-context label table; needs eBPF/VPP);
learning the context population from **BGP L3VPN** instead of static
`via-vrf`; auto-allocation
of the SRv6 Mirror SID when `mirror-sid` is omitted, and a TI-LFA-style
repair list to the protector (today the SRv6 repair is a single
`[Mirror SID]` segment, assuming the protector is reachable on a path that
avoids the failed egress). SR-MPLS rides an **IPv4** transport because
IS-IS has no IPv6 prefix-SID yet (deferred until SRv6-over-IS-IS).
