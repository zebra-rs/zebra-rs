# Building

If you only want to run zebra-rs, install a prebuilt package — see
[Install](ch-00-06-install.md). This chapter covers building from source, which
you need when your distribution is not packaged, or when you want to hack on
zebra-rs itself. The steps mirror the CI build scripts under
`.github/workflows/` (`ci.yaml`, `build-amd64.yaml`, `build-arm64.yaml`,
`nightly.yaml`).

## Setting up the build host

The quickest way to get a build host ready is the `setup-build-env.sh` script
under `packaging/`. It installs everything the rest of this chapter describes —
the APT system packages, the stable Rust toolchain, the XDP/eBPF toolchain
(nightly Rust with `rust-src`, LLVM, and `bpf-linker`), and the `nfpm` package
builder — in a single, idempotent pass, mirroring the CI workflows:

``` shell
packaging/setup-build-env.sh
```

Re-running it is safe: it skips work that is already done. A few flags trim it
down to what you actually need:

| Flag | Effect |
|---|---|
| `--no-xdp` | Skip the XDP/eBPF toolchain (nightly `rust-src`, LLVM, `bpf-linker`). Use this if you only build with `make all` / `cargo test`. |
| `--no-nfpm` | Skip `nfpm` (only needed to build the `.deb` package). |
| `--no-rust` | Do not install rustup/Rust (assume a toolchain is already present). |
| `-h`, `--help` | Show the help and exit. |

Two environment variables override the pinned tool versions:
`LLVM_VERSION` (default `18`) and `BPF_LINKER_VERSION` (default `0.10.3`).

The script targets Ubuntu/Debian (it drives `apt-get`). On other distributions,
install the equivalent pieces by hand — the rest of this chapter documents each
one.

## Build requirements

### Rust toolchain

Install the stable Rust toolchain with [rustup](https://rustup.rs/):

``` shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### System packages

On Ubuntu/Debian:

``` shell
sudo apt update
sudo apt install -y build-essential pkg-config curl \
    protobuf-compiler libpam0g-dev libnanomsg-dev bison xxd
```

| Package | Needed for |
|---|---|
| `build-essential`, `pkg-config`, `curl` | C toolchain for the `vty` shell — GNU bash 5.3 is downloaded and compiled from source |
| `protobuf-compiler` | `protoc`, which generates the gRPC/protobuf management API code |
| `libpam0g-dev` | the `vtypam` PAM authentication helper |
| `libnanomsg-dev` | the vty hooks built into the `vty` shell |
| `bison` | bash's grammar, regenerated during the `vty` build |
| `xxd` | embeds `vty.sh` into the `vty` binary during the build |

Building or testing only the Rust workspace (`cargo build`, `cargo test`)
needs just `protobuf-compiler` and `libpam0g-dev` — that is all `ci.yaml`
installs. The remaining packages are used by the `vty` build and packaging.

### XDP/eBPF toolchain: LLVM and bpf-linker

The XDP BFD Echo helper (`offload/xdp-bfd-echo`) offloads BFD Echo
reflection to XDP. It is compiled for the `bpfel-unknown-none` target, which
requires a nightly Rust toolchain with `rust-src`, LLVM 18, and
[`bpf-linker`](https://github.com/aya-rs/bpf-linker) (which links against
LLVM). The validated combination is bpf-linker 0.10.3 with LLVM 18.1:

``` shell
# Nightly Rust + rust-src for the BPF target
rustup toolchain install nightly --component rust-src

# LLVM 18 from apt.llvm.org
wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh
chmod +x /tmp/llvm.sh
sudo /tmp/llvm.sh 18
export PATH="/usr/lib/llvm-18/bin:$PATH"

# bpf-linker, linked against the LLVM installed above
cargo install bpf-linker --version 0.10.3 --locked
```

This toolchain is **not** required for `make all`. It is required for
`make xdp-bfd-echo` and for building the Debian package, which bundles the
helper.

## Build and install from source

``` shell
make all
```

builds the release binaries of the Rust workspace (`zebra-rs`, `vtyctl`,
`vtyhelper`, `vtypam`) and the `vty` shell.

``` shell
make install
```

installs `zebra-rs`, `vtyctl`, and `vtyhelper` into `/usr/bin` (via `sudo`,
granting `zebra-rs` the necessary network capabilities with `setcap`) and
copies the YANG schemas to `/etc/zebra-rs/yang`. Keep the schemas in lockstep
with the binary: a stale schema directory silently rejects newly added
configuration even when the binary supports it.

## Debian package

Building the `.deb` package needs all of the build requirements above —
including the XDP/eBPF toolchain (LLVM + bpf-linker), because the package
bundles the `xdp-bfd-echo` helper — plus the
[`nfpm`](https://github.com/goreleaser/nfpm) package builder:

``` shell
echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
sudo apt update
sudo apt install nfpm
```

Then from the `packaging/` directory:

``` shell
cd packaging
make amd64   # or: make arm64
```

This builds the `vty` shell and the Rust workspace if needed, compiles the
`xdp-bfd-echo` XDP helper, and produces a `.deb` package for the selected
architecture — the same steps `build-amd64.yaml` and `build-arm64.yaml` run
in CI.

``` shell
sudo dpkg -i zebra-rs_26.7.1_arm64.deb
```

will install zebra-rs and start the daemon.
