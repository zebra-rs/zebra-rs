# IS-IS LSP MTU and Fragmentation

A Link State PDU carries a router's adjacencies and reachability, and
IS-IS floods it as a **single link-layer frame** — a PDU is never
fragmented at the link layer the way an IP packet is. Two independent
knobs under `router isis` govern how large an LSP may grow and what
happens when one would not fit on the wire:

- `lsp-mtu-size` — the *originating buffer size*: the largest LSP this
  router will build for itself. When its content exceeds this, the
  router splits the LSP into numbered fragments.
- `lsp-mtu` — the *transmit MTU*: the largest LSP this router will send
  on an interface. It guards against emitting a PDU larger than a link
  can carry.

## Originating buffer size — `lsp-mtu-size`

`lsp-mtu-size` is the ISO 10589 `originatingLSPBufferSize`, advertised
in TLV 14 per RFC 1195. It caps the byte length of every
*self-originated* LSP and drives the send-side packer's fragment
boundary. A router with more reachability than fits in one PDU spreads
its TLVs across numbered fragments named
`<hostname>.<pseudonode>-<fragment>` (for example `z1.00-00`,
`z1.00-01`, …), and receivers merge those fragments back into one
logical origin before running SPF.

- **Range:** 128..16384 bytes
- **Default:** 1492 — the originatingLSPBufferSize every IS-IS
  implementation is required to accept (ISO 10589), and the safe value
  on any standard Ethernet.

```
router isis
  lsp-mtu-size 1492
```

Changing `lsp-mtu-size` at runtime re-originates the self-LSP so the
new buffer size takes effect immediately. See the fragmentation BDD
feature (`isis_fragmentation_ipv4`) for a worked example that fragments
at both a tight 400-byte cap and the standard 1500-byte MTU.

## Transmit MTU — `lsp-mtu`

`lsp-mtu` sets the maximum byte size of an LSP PDU this router will
transmit on an interface.

- **Range:** 400..9490 bytes
- **Default:** 1497 — fits inside a standard 1500-byte Ethernet frame,
  so the over-MTU check below stays inert on ordinary links.

Because an LSP is flooded as one link-layer frame, when `lsp-mtu`
exceeds an interface's MTU an LSP generated at that size cannot fit on
the wire. Rather than emit an over-sized frame that the kernel or peer
would reject, the flood path **drops the LSP on send for that
interface** and logs a warning:

```
[LspFlood] eth0: dropping L2 LSP flood: lsp-mtu 9000 exceeds interface MTU 1500
```

Only LSP flooding is gated — Hello, CSNP and PSNP PDUs are unaffected —
so the **adjacency stays up** while LSP updates are withheld on the
offending link. Dropping the send does not purge a neighbour's existing
database; it simply prevents the over-sized update from propagating.
Once the mismatch is resolved (lower `lsp-mtu`, or raise the interface
MTU), the next origination or database-sync re-marks the LSP and it
floods normally again.

Raise `lsp-mtu` only on a network where every interface in the flooding
domain has a correspondingly large (jumbo) MTU. The drop-and-warn
behaviour then catches any interface that was accidentally left at a
smaller MTU instead of silently black-holing the topology.

```
router isis
  lsp-mtu 9000
```

## Showing the LSP MTU per interface

`show isis interface detail` prints the effective LSP MTU for every
enabled interface, and flags any interface whose MTU is smaller than
`lsp-mtu` (so LSPs are being dropped on it):

```
Interface: eth0, State: Up, Active, Circuit Id: 0x01
  Type: lan, Level: L2, SNPA: 2c:54:91:88:c9:e3, MTU: 1500
  LSP MTU: 9000 (exceeds interface MTU 1500 - LSPs dropped on send)
  Level-2 Information:
    Metric: 10, Active neighbors: 1
    ...
```

When `lsp-mtu` is at or below the interface MTU the line reads simply
`LSP MTU: 1497` with no warning. The same `lsp_mtu` value and a
`lsp_mtu_exceeds_interface` boolean are present in the JSON form
(`show isis interface detail` with JSON output).

## Cross-reference — IOS-XR command mapping

| zebra-rs YANG | IOS-XR command |
|---|---|
| `lsp-mtu-size` | `lsp-mtu` (originating LSP buffer size) |
| `lsp-mtu` | *(no direct equivalent — transmit-side over-MTU guard)* |

> **Naming note.** IOS-XR's `lsp-mtu` command sets the originating LSP
> size, which maps to zebra-rs `lsp-mtu-size`. zebra-rs's `lsp-mtu` is a
> *separate* transmit-side guard with no exact IOS-XR analogue, so take
> care not to conflate the two when porting configuration.
