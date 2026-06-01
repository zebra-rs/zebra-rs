# bfd-echo-reflector — XDP BFD Echo reflector

An XDP/eBPF program (with an [aya](https://aya-rs.dev/) userspace loader) that
reflects **BFD Echo** frames (UDP **3785**, RFC 5880 §6.4 / RFC 5881 §4) in the
data plane. **zebra-rs spawns and supervises it automatically** — one instance
per interface — when the BFD Echo function is enabled on a single-hop IPv4
session (e.g. `router ospf area 0 interface X bfd { echo-mode true; }`), so a
peer (FRR `echo-mode`, IOS, …) can run BFD Echo against zebra-rs. It can also be
run standalone for testing (see [Run](#run)).

A matching IPv4 UDP/3785 frame is reflected back out the same interface
(`XDP_TX`), acting as a **forwarding-plane hop**: swap the Ethernet
source/destination MAC, **decrement the IP TTL by one and patch the IP header
checksum** (RFC 1141). The UDP checksum is untouched (TTL isn't in its
pseudo-header). Everything else (including BFD **control** on UDP/3784) is
passed through untouched.

> **Why decrement TTL (interop-critical):** BFD Echo is looped by the remote's
> *forwarding plane* (RFC 5880 §6.4), which is a hop. FRR's IPv4 fp-echo
> receiver (`bfd_recv_ipv4_fp`) **drops any looped frame whose TTL isn't 254** —
> it sends at 255 and requires exactly one decrement, both to confirm a real
> forwarding loop and to discard its own egress copy (FRR receives Echo on an
> `AF_PACKET` socket, so a naive MAC-swap-only reflector that left TTL at 255 was
> silently dropped → BFD flapped). Note `accept_local`/`rp_filter` on the Echo
> *originator* are irrelevant for the same `AF_PACKET` reason.

> **Status:** integrated into zebra-rs and **validated end-to-end against FRR
> `echo-mode`** (zebra-rs ↔ FRR ospfd over a veth link): FRR originates Echo,
> this reflector loops it back at TTL 254, FRR's Echo detection succeeds, and the
> BFD/OSPF session stays Up.

## How zebra-rs drives it

The BFD instance reference-counts a reflector child per interface that has an
active single-hop IPv4 Echo session: it spawns this binary on the first such
session and stops it (SIGTERM → clean XDP detach) on the last. zebra-rs only
advertises a non-zero `Required Min Echo RX Interval` once the reflector is up,
so the promise to loop Echo back stays honest.

- **Binary path:** `$ZEBRA_BFD_REFLECTOR_BIN`, else `~/.zebra/bin/bfd-echo-reflector`,
  else `/usr/sbin/bfd-echo-reflector` (the `.deb` install location).
- **Attach mode:** `$ZEBRA_BFD_REFLECTOR_MODE` = `auto` (default) | `native` | `skb`.
- **Capabilities:** needs `cap_net_admin,cap_bpf`; the package postinstall grants them.

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

> In production zebra-rs spawns this for you (see [How zebra-rs drives it](#how-zebra-rs-drives-it));
> run it by hand only for standalone testing.

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

## Limitations / follow-ups

- **IPv4 only** (EtherType 0x0800). IPv6 (0x86DD) is a follow-up.
- Option-less IPv4 only (IHL=5); BFD Echo frames carry no IP options.
- **Responder only** — zebra-rs reflects a peer's Echo (and honestly advertises
  the capability), but does not yet *originate* Echo itself; the sender half
  needs periodic TX timers + an Echo detect timer.
- aya deps are pulled from git to match the current build glue; pin a rev for
  reproducible builds.
