# tc-evpn-replicate

eBPF **TC/clsact** dataplane for EVPN BUM replication over an **RFC 9524 SR
replication segment** (the SR-MPLS / SRv6 P2MP tree signalled by EVPN Type-3
IMET, `draft-ietf-bess-mvpn-evpn-sr-p2mp`).

## Why TC, not XDP

The stock Linux kernel cannot forward RFC 9524 natively — there is no
`End.Replicate` seg6local action, no MPLS P2MP/multicast, and no `End.DT2M` for
the L2 leaf flood. Replication means *one copy per downstream branch, each with
a different rewritten header*. The TC layer can express that with
`bpf_clone_redirect` in a loop (mutating the skb between clones); XDP cannot
clone per-copy. So this is a `#[classifier]` program on `clsact`, unlike the
sibling [`xdp-bfd-echo`](../xdp-bfd-echo) offload.

Roles (all clsact-attached):
- **root / bud** (ingress) — **implemented**: match the local Replication-SID
  (the outer IPv6 DA), then for each downstream leaf clone the packet and
  rewrite the outer DA to that leaf's SID (`End.Replicate`);
- **leaf** (ingress) — *follow-up (DP3c)*: match the local `End.DT2M` SID, strip
  the outer IPv6+SRH, redirect the inner frame to the bridge for native BUM
  flooding.

The branch/leaf table is a BPF map the loader fills from the BGP control plane
(`ReplSeg`, fed by `EvpnFloodState::replication_leaves`).

## Status

**`End.Replicate` works.** The classifier reads three maps the loader fills:

- `REPL_SEG` — per-VNI replication segment (tree + leaf SIDs);
- `REPL_LOCAL_SID` — local replication SID → VNI, for demuxing an inbound packet
  to its segment by outer IPv6 DA (derived from each segment's root SID);
- `CONFIG` — index 0 = egress ifindex the copies are `clone_redirect`'d out of.

On an inbound IPv6 frame whose DA is a known replication SID it decrements the
outer Hop Limit (dropping anything that arrives with Hop Limit ≤ 1) and emits
one clone per leaf with the outer DA rewritten, then drops the original.

Validated end-to-end on a veth pair —
[`scripts/veth-replicate-test.sh`](scripts/veth-replicate-test.sh) sends one
frame to a replication SID and asserts a copy arrives at *each* leaf SID:

```sh
sudo bash offload/tc-evpn-replicate/scripts/veth-replicate-test.sh
```

The **leaf `End.DT2M` decap** (strip outer IPv6+SRH, redirect inner to the
bridge) and the **root H.Encaps-from-bare-frame** path are follow-up slices.

## Build / run

Like `xdp-bfd-echo`, this is a self-contained workspace, **excluded** from the
root `cargo` workspace (it needs the nightly toolchain + `bpf-linker`, which the
stable CI gate lacks). It is not built or tested by CI.

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker                 # needs LLVM
cd offload/tc-evpn-replicate
cargo build                              # builds loader; build.rs compiles the eBPF object
cargo run -- --iface eth0 --direction ingress   # runs under `sudo -E` (CAP_NET_ADMIN)
```
