# bfd-echo-reflector — XDP BFD Echo reflector (PoC)

A standalone proof-of-concept that reflects **BFD Echo** frames (UDP **3785**,
RFC 5880 §6.4 / RFC 5881 §4) in the data plane using **XDP/eBPF** (via
[aya](https://aya-rs.dev/)).

A matching IPv4 UDP/3785 frame has its Ethernet source/destination MAC swapped
and is sent straight back out the same interface (`XDP_TX`). It is a pure L2
hairpin — no IP/UDP checksum recompute, no TTL decrement. Everything else
(including BFD **control** on UDP/3784) is passed through untouched.

This is the smallest, best-fit first piece of the broader BFD/S-BFD/STAMP XDP
offload effort: the reflector is stateless, so it maps cleanly onto XDP. The
originator/sender side (which needs periodic TX timers) is **not** part of this
PoC. See `../../docs/design/bfd-sbfd-stamp-xdp-offload-notes.md` and
`../../docs/design/bfd-echo-plan.md`.

> **Status:** scaffolding + program written, **not yet compiled or run** in this
> repo — the eBPF toolchain (bpf-linker + LLVM) was not installed when it was
> authored. Build it with the steps below and report back.

## Layout

```
bfd-echo-reflector/
├── Cargo.toml      # workspace root (own workspace; excluded from zebra-rs)
├── .cargo/config.toml  # `cargo run` -> sudo (XDP attach needs CAP_NET_ADMIN)
├── loader/         # userspace: load + attach the XDP program (aya)
│   ├── build.rs    # aya-build: compiles ebpf/ for bpfel-unknown-none
│   └── src/main.rs
└── ebpf/           # the XDP program (no_std), built for bpfel-unknown-none
    ├── src/lib.rs  # trivial lib target (host build-dep, cache tracking)
    └── src/main.rs # bfd_echo_reflect: udp/3785 -> swap MAC -> XDP_TX
```

This tree is **excluded** from the top-level zebra-rs workspace
(`exclude = ["offload/*"]`), so the stable CI gate
(`cargo {build,clippy,test} --workspace`) never tries to build it.

## Prerequisites (one-time)

Kernel 5.x+ with XDP (this lab is 6.8 — fine). Then:

```sh
# 1. nightly toolchain with rust-src (aya-build invokes `rustup run nightly … -Z build-std=core`)
rustup toolchain install nightly --component rust-src

# 2. LLVM — needed to build/install bpf-linker (NEEDS sudo)
sudo apt install -y llvm        # Debian/Ubuntu; use your distro's LLVM package otherwise

# 3. bpf-linker (links the eBPF object; a few minutes to compile)
cargo install bpf-linker
```

If `cargo install bpf-linker` fails to find LLVM, follow the platform notes in
the [bpf-linker README](https://github.com/aya-rs/bpf-linker#installation).

## Build

```sh
cd offload/bfd-echo-reflector
cargo build --release        # build.rs compiles the eBPF object via nightly+bpf-linker
```

(`cargo build` builds only the `loader`; the eBPF crate is compiled for
`bpfel-unknown-none` by `loader/build.rs`. Do **not** use `--workspace`.)

## Run

```sh
# `cargo run` is wrapped in sudo via .cargo/config.toml
RUST_LOG=info cargo run --release -- --iface veth0
# or run the binary directly:
sudo RUST_LOG=info ./target/release/bfd-echo-reflector -i veth0
```

`--mode auto` (default) attaches native/driver XDP and falls back to generic
**SKB mode**. On **veth and virtual NICs** native XDP *attaches* but does not
loop frames to the program, so force generic mode with **`-m skb`** there
(`-m native` forces driver mode). Validated in SKB mode on the
Parallels/aarch64 lab.

## Verify end-to-end (veth pair)

One command (builds first if needed):

```sh
sudo bash scripts/veth-test.sh
```

It creates a veth pair with the **sender end in its own network namespace**,
attaches the reflector (`-m skb`) on the root-ns end, sends 3 UDP/3785 frames
from the namespace, and confirms a reflected frame arrives back. Expected tail:

```
PASS: BFD Echo frame reflected via XDP_TX
      (reflector logged 3 reflect(s); 1 inbound frame(s) on bfde1)
```

The namespace is required: if both veth ends share a namespace the kernel
delivers `10.123.0.2 -> 10.123.0.1` locally via loopback and the frame never
crosses the wire, so the XDP hook never fires.

**Pass criteria:** the sent `udp/3785` frame reappears *inbound* on the sender's
veth with the Ethernet source/destination swapped (`tcpdump -e` shows the swap;
it even decodes as `BFD, Echo`), and the reflector logs `BFD Echo udp/3785
reflected (XDP_TX)`. `XDP_TX` re-transmits out the same interface, i.e. toward
the peer end, so the sender sees the bounce.

## Limitations / next slices

- **IPv4 only** (EtherType 0x0800). IPv6 (0x86DD) is a follow-up.
- Option-less IPv4 only (IHL=5); BFD Echo frames carry no IP options.
- Reflector only — no originator/sender, no detect timer, no FSM wiring.
- Not yet integrated into zebra-rs (no config, no advertising non-zero
  `Required Min Echo RX Interval`).
- aya deps are pulled from git to match the current build glue; pin a rev for
  reproducible builds.
