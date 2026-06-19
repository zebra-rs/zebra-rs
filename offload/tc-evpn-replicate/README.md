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

Planned roles (all clsact-attached):
- **root** (egress): `H.Encaps` each copy toward a downstream SID / leaf;
- **bud** (ingress): match the local Replication-SID, clone+rewrite per branch
  (`End.Replicate`);
- **leaf** (ingress): match the local `End.DT2M` SID, strip the outer IPv6+SRH,
  redirect the inner frame to the bridge for native BUM flooding.

The branch/leaf table is a BPF map the loader fills from the BGP control plane
(`ReplSeg`, fed by `EvpnFloodState::replication_leaves`).

## Status

**Skeleton only.** The classifier loads and attaches but passes every frame
through (`TC_ACT_PIPE`); the replication logic and maps are follow-up slices.

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
