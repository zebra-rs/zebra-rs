# xdp-bfd-echo — XDP BFD Echo datapath (reflector + originator)

An XDP/eBPF program (with an [aya](https://aya-rs.dev/) userspace loader) that
reflects **BFD Echo** frames (UDP **3785**, RFC 5880 §6.4 / RFC 5881 §4) in the
data plane. **zebra-rs spawns and supervises it automatically** — one instance
per interface — when the BFD Echo function is enabled on a single-hop IPv4
session (e.g. `router ospf area 0 interface X bfd { echo-mode receive; }`), so a
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

- **Binary path:** `$ZEBRA_XDP_BFD_ECHO_BIN`, else `~/.zebra/bin/xdp-bfd-echo`,
  else `/usr/sbin/xdp-bfd-echo` (the `.deb` install location).
- **Attach mode:** `$ZEBRA_XDP_BFD_ECHO_MODE` = `auto` (default) | `native` | `skb`.
- **Capabilities:** needs `cap_net_admin,cap_bpf` (and `cap_net_raw` for the
  AF_PACKET Echo originator); the package postinstall grants them.

## Layout

```
xdp-bfd-echo/
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

Kernel 5.x and upper with XDP. Then:

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
cd offload/xdp-bfd-echo
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
sudo RUST_LOG=info ./target/release/xdp-bfd-echo -i veth0
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

## Interoperability: FRR ↔ zebra-rs

zebra-rs is responder-only, so the *originator* is a peer that runs the Echo
function — here FRR with `echo-mode`. FRR sends Echo to UDP/3785, the zebra-rs
XDP reflector loops it back as a forwarding hop, and FRR's Echo detection rides
on it (BFD/OSPF stays Up; FRR then slows its control packets). zebra-rs needs no
manual run — its BFD instance spawns the reflector once the Echo session is up.

**FRR** — `192.168.10.2` (originates Echo via the `echo-on` profile):

```
!
interface enp0s6
 ip address 192.168.10.2/24
 ip ospf bfd
 ip ospf bfd profile echo-on
!
router ospf
 network 192.168.10.0/24 area 0
!
bfd
 profile echo-on
  echo-mode
 exit
 !
exit
!
```

**zebra-rs** — `192.168.10.1` (reflects via XDP; `echo-mode receive` advertises
a non-zero Required Min Echo RX so the FRR peer may run Echo against us; use
`both` to also originate our own Echo toward FRR):

```
interface enp0s6 {
  ipv4 {
    address 192.168.10.1/24;
  }
}
router {
  ospf {
    area 0 {
      interface enp0s6 {
        bfd {
          echo-mode receive;
          enable true;
        }
        enable true;
      }
    }
  }
}
```

**Confirmation** (`tcpdump` on FRR; `00:1c:42:e8:0c:23` = FRR, `00:1c:42:45:b2:35`
= zebra-rs):

```
$ sudo tcpdump -nei enp0s6 udp port 3785
02:40:49.382278 00:1c:42:e8:0c:23 > 00:1c:42:45:b2:35, ethertype IPv4 (0x0800), length 66: 192.168.10.2.3785 > 192.168.10.2.3785: BFD, Echo, length: 24
02:40:49.382520 00:1c:42:45:b2:35 > 00:1c:42:e8:0c:23, ethertype IPv4 (0x0800), length 66: 192.168.10.2.3785 > 192.168.10.2.3785: BFD, Echo, length: 24
02:40:49.422078 00:1c:42:e8:0c:23 > 00:1c:42:45:b2:35, ethertype IPv4 (0x0800), length 66: 192.168.10.2.3785 > 192.168.10.2.3785: BFD, Echo, length: 24
02:40:49.422285 00:1c:42:45:b2:35 > 00:1c:42:e8:0c:23, ethertype IPv4 (0x0800), length 66: 192.168.10.2.3785 > 192.168.10.2.3785: BFD, Echo, length: 24
```

Each pair is FRR's Echo out (`e8:0c:23 → 45:b2:35`) and the reflector's return
~0.2 ms later with the MACs **swapped** (`45:b2:35 → e8:0c:23`). The
self-addressed `192.168.10.2 → 192.168.10.2` is normal BFD Echo — the looping
system never parses it, it just hairpins it. (Not shown: the TTL drops 255 → 254
on the return — add `-v` to see it; FRR drops any other TTL.) On zebra-rs,
`show bfd peers` then reports `Echo receive interval: 50ms`.

## Originator (Echo sender)

Beyond reflecting, the helper also *originates* Echo when zebra-rs asks it to
(RFC 5880 §6.8.5/§6.8.9), driven over a stdin/stdout line protocol:

- `echo-add <discr> <local-ip> <peer-ip> <tx-us> <detect-mult>` / `echo-del <discr>`
  from zebra-rs; `echo-down <discr>` back when detection fires.
- **Transmit** is userspace (XDP can't originate): an `AF_PACKET` socket sends a
  self-addressed Echo (src=dst=local, udp/3785, TTL 255) every `tx-us` (75–100%
  jittered); the peer's forwarding plane loops it back.
- **Detection is offloaded to the kernel.** The XDP program recognizes our
  returning Echo (source ∈ `OUR_LOCAL_IPS`), arms/re-arms a per-session
  `bpf_timer` in the `ECHO_TIMERS` BTF map (keyed by discriminator), and drops
  the frame. If returns stop for `tx-us × detect-mult`, the timer fires in
  softirq and sets a `down` flag; the helper polls it and emits `echo-down`. A
  userspace timeout covers the bootstrap window before the first return arms the
  timer.

## Limitations / follow-ups

- IPv4 (EtherType 0x0800) and IPv6 (0x86DD) are both reflected/originated, but
  the IPv6 reflect is not a pure analogue of IPv4. IPv4 Echo is self-addressed
  (`src == dst`) and looped by the peer's forwarding plane, so a MAC swap
  suffices. FRR's IPv6 Echo (`ptm_bfd_echo_snd`) is **peer-addressed**
  (`src = originator, dst = us`) and looped by FRR's bfdd in software
  (`bp_bfd_echo_in`), so the IPv6 reflect also **swaps the IPv6 src/dst** to
  retarget the frame at the originator — otherwise it keeps `dst = us`, the
  originator re-forwards it, and it ping-pongs until the Hop Limit reaches 0.
  The swap needs no checksum fix-up (no IPv6 header checksum; the UDP
  pseudo-header sum `src + dst` is invariant under the swap; Hop Limit isn't in
  it). The Hop Limit is decremented (255 → 254) just as the IPv4 path decrements
  the TTL — and here that decrement is what stops the loop, since FRR reflects
  only Hop Limit 255 and *processes* anything else as a return. A self-addressed
  Echo (e.g. our own originator) is unaffected: the address swap is a no-op.
- Option-less IPv4 only (IHL=5) and base IPv6 headers only (no extension
  headers); BFD Echo frames carry neither.
- `bpf_timer` detection needs a kernel that supports it (≥ 5.15) and `CAP_BPF`;
  the responder path has no such requirement.
- aya deps are pulled from git to match the current build glue; pin a rev for
  reproducible builds.
