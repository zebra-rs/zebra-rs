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
the APT system packages, the stable Rust toolchain, and the `cargo-deb`
package builder — in a single, idempotent pass, mirroring the CI workflows:

``` shell
packaging/setup-build-env.sh
```

Re-running it is safe: it skips work that is already done. A few flags trim it
down to what you actually need:

| Flag | Effect |
|---|---|
| `--no-cargo-deb` | Skip `cargo-deb` (only needed to build the `.deb` package). |
| `--no-rust` | Do not install rustup/Rust (assume a toolchain is already present). |
| `-h`, `--help` | Show the help and exit. |

Building zebra-rs needs only the **stable** Rust toolchain: all XDP/eBPF
data-plane code lives in
[cradle-rs](https://github.com/zebra-rs/cradle-rs), which is built and
packaged separately, so no nightly Rust, LLVM, or `bpf-linker` is required
here.

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
    protobuf-compiler libpam0g-dev bison xxd
```

| Package | Needed for |
|---|---|
| `build-essential`, `pkg-config`, `curl` | C toolchain for the `vty` shell — GNU bash 5.3 is downloaded and compiled from source |
| `protobuf-compiler` | `protoc`, which generates the gRPC/protobuf management API code |
| `libpam0g-dev` | the `vtypam` PAM authentication helper |
| `bison` | bash's grammar, regenerated during the `vty` build |
| `xxd` | embeds `vty.sh` into the `vty` binary during the build |

Building or testing only the Rust workspace (`cargo build`, `cargo test`)
needs just `protobuf-compiler` and `libpam0g-dev` — that is all `ci.yaml`
installs. The remaining packages are used by the `vty` build and packaging.

### XDP/eBPF toolchain

Not needed. The eBPF data plane — including the BFD Echo reflector and the
in-kernel detection watchdog — lives in
[cradle-rs](https://github.com/zebra-rs/cradle-rs), a separate repository
with its own build (nightly Rust, LLVM, `bpf-linker`) and its own `.deb`.
Nothing in the zebra-rs workspace targets `bpfel-unknown-none`, so `make
all`, `cargo test`, and the Debian package all build with stable Rust alone.

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
copies the YANG schemas to `/usr/share/zebra-rs/yang`. Keep the schemas in lockstep
with the binary: a stale schema directory silently rejects newly added
configuration even when the binary supports it.

## Debian package

Building the `.deb` package needs the build requirements above plus the
[`cargo-deb`](https://github.com/kornelski/cargo-deb) package builder (the
XDP/eBPF data-plane helpers moved to cradle-rs, which ships its own `.deb`, so
this package no longer bundles them):

``` shell
cargo install cargo-deb --locked
```

Then from the `packaging/` directory:

``` shell
cd packaging
make amd64   # or: make arm64
```

This builds the `vty` shell and the Rust workspace if needed and produces a
`.deb` package for the selected architecture — the same steps
`build-amd64.yaml` and `build-arm64.yaml` run in CI.

``` shell
sudo dpkg -i zebra-rs_26.7.1_arm64.deb
```

will install zebra-rs and start the daemon.
