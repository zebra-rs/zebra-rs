# pfcp-inject

A minimal **PFCP/N4 SMF simulator** for driving the zebra-rs BGP MUP
controller in tests and by hand.

It pretends to be a 5G SMF (Session Management Function) and pushes one
mobile session into the controller (`router bgp mup-c`): a UE IP address,
an access-side GTP-U F-TEID, and a Network Instance. The controller learns
the session and **originates a MUP Session-Transformed route** (draft-ietf-bess-mup-safi,
SAFI 85). With `--delete` it tears the session down again.

It is intentionally tiny and synchronous: the [`rs-pfcp`](https://crates.io/crates/rs-pfcp)
crate is a pure codec, and the only transport needed is a single blocking
UDP socket.

## What it does

A run performs, in order:

1. **Association Setup** — `AssociationSetupRequest` → expects `AssociationSetupResponse`.
2. **Session Establishment** — `SessionEstablishmentRequest` (one PDR with the
   UE IP / access F-TEID / Network Instance + one FAR forwarding to `Core`)
   → expects `SessionEstablishmentResponse`. The controller's UP F-SEID from
   the response is reused as the SEID for any later message.
3. **Session Deletion** *(only with `--delete`)* — `SessionDeletionRequest`
   → expects `SessionDeletionResponse`.

## Build

```bash
cargo build --release -p pfcp-inject
# binary: target/release/pfcp-inject
```

For the BDD suite the binary must be on the host `PATH`, the same way the
`zebra-rs` / `vtyctl` binaries are staged:

```bash
sudo cp target/release/pfcp-inject /usr/bin/
```

## Options

| Flag | Default | Description |
| --- | --- | --- |
| `--target <IP>` | *(required)* | Controller PFCP listener address. |
| `--port <u16>` | `8805` | Controller PFCP listener port. |
| `--node-id <IP>` | `10.0.0.99` | The SMF's PFCP Node ID. |
| `--ue-ipv4 <v4>` | — | UE IPv4 address. At least one of `--ue-ipv4` / `--ue-ipv6` is **required**. |
| `--ue-ipv6 <v6>` | — | UE IPv6 address. |
| `--teid <u32>` | `0x12345678` | Access-side GTP-U TEID — decimal or `0x`-prefixed hex. |
| `--endpoint <IP>` | `10.0.0.1` | Access-side GTP-U (F-TEID) endpoint address (the gNB) — used for the **Type-1 ST**. |
| `--core-endpoint <IP>` | — | Core-side GTP-U (F-TEID) endpoint address — used for the **Type-2 ST**. When set, a second `SourceInterface=Core` PDR is added so the controller learns a distinct core endpoint; omit and the Type-2 ST falls back to the access endpoint. |
| `--core-teid <u32>` | `0x87654321` | Core-side GTP-U TEID (only used with `--core-endpoint`). |
| `--network-instance <s>` | `access` | Network Instance (APN/DNN). Matched against a per-VRF `mup` config on the controller. |
| `--seid <u64>` | `1` | CP-side F-SEID advertised in the Session Establishment Request. |
| `--delete` | `false` | Also delete the session after establishing it. |
| `--timeout <secs>` | `3` | Per-exchange receive timeout. |

The most important knob is `--network-instance`. The controller correlates
it to a `router bgp vrf <name> afi-safi mup route {st1|st2} network-instance
<ni>` binding, which decides the route type that gets originated:

- a VRF binding the NI under `route st1` → a **Type-1 ST** (downlink / access;
  carries the UE prefix + the **access** endpoint, `--endpoint`);
- a VRF binding the NI under `route st2` → a **Type-2 ST** (uplink / core;
  carries the **core** endpoint, `--core-endpoint`, + GTP TEID). The access
  and core endpoints are distinct network functions (draft §3.3.7 / §3.3.10).

A single session can originate both at once when two VRFs (one st1, one st2)
bind the same NI.

## Examples

Downlink Type-1 ST (`access` Network Instance):

```bash
pfcp-inject --target 192.168.0.1 --port 8805 \
  --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 \
  --network-instance access
```

Uplink Type-2 ST (`core` Network Instance):

```bash
pfcp-inject --target 192.168.0.1 \
  --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 \
  --network-instance core
```

Mixed-AFI (IPv6 UE over an IPv4 access transport):

```bash
pfcp-inject --target 192.168.0.1 \
  --ue-ipv6 2001:db8::5 --teid 0x12345678 --endpoint 10.0.0.1 \
  --network-instance access
```

Establish then immediately withdraw:

```bash
pfcp-inject --target 127.0.0.1 \
  --ue-ipv4 192.0.2.5 --network-instance access --delete
```

## Verifying the effect

After a successful run the controller should have originated the route.
Check it with `show bgp mup`, e.g.:

```
[ST1][65000:100][ue=192.0.2.5/32][teid=305419896]
    next-hop <controller-v6>  weight 32768
    rt:65000:200 mup:1:2
```

`--delete` (or a Session Deletion / Association loss) withdraws it.

## Prerequisites

A live MUP controller listening on `--target:--port` is required:

- a `router bgp mup-c` block with `enable`, `controller-address`, and the
  `pfcp` listener configured;
- at least one per-VRF `afi-safi mup route {st1|st2} network-instance <ni>`
  binding whose `<ni>` matches `--network-instance`.

In the BDD suite this is namespace `z1` (combined UPF + controller), and the
tool is invoked as `When I execute "pfcp-inject …" in namespace "z1"`.

## Usage in tests

Used from the MUP end-to-end BDD features, for example:

- `bdd/tests/features/bgp_mup_e2e.feature` — ST1 origination;
- `bdd/tests/features/bgp_mup_st2.feature` — ST2 origination;
- `bdd/tests/features/bgp_mup_dual_st.feature` — one session → both ST1 + ST2;
- `bdd/tests/features/bgp_mup_mixed_afi.feature` — IPv6 UE over IPv4 transport;
- `bdd/tests/features/bgp_mup_interwork.feature` — DSD ↔ ST2 resolution.

> This is a **test-only** tool: it terminates exactly enough of PFCP/N4 to
> drive route origination. It is not a conformant UPF or SMF.
