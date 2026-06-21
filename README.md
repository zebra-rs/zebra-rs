# <img src="docs/logo.svg" alt="Project Logo" width="25" height="25"> zebra-rs

zebra-rs is a BGP, OSPF, and IS‑IS routing stack with SRv6, SR-MPLS, L3VPN, and EVPN extensions, written from scratch in Rust. Memory‑safe, async to the core, idempotent by design — and the first routing daemon to ship with a native MCP server for AI agents. Project Home Page <http://zebra.rs/>.

## Installation

### Quick Install

Prebuilt `.deb` packages are currently provided only for the following Ubuntu
releases. Other distributions or releases are not packaged yet and should
[build from source](#build-and-install-from-source).

| Ubuntu release | Code name | Architectures |
|---|---|---|
| 22.04 | jammy | x86_64, ARM64 |
| 24.04 | noble | x86_64, ARM64 |
| 26.04 | resolute | x86_64, ARM64 |

The fastest way to get zebra-rs is the install script, which detects your
distribution and CPU architecture, fetches the matching prebuilt `.deb`
package, and installs it:

``` shell
curl -fsSL https://zebra.rs/install.sh | bash
```

The script downloads the latest package from the
[GitHub releases](https://github.com/zebra-rs/zebra-rs/releases) and installs
it with `apt`, so it pulls in the runtime dependencies automatically. It needs
`sudo` for the install step. Piping a remote script into `bash` runs it with
your privileges — read it first at <https://zebra.rs/install.sh> if you'd rather
review before running.

### Nightly Packages

The nightly CI workflow publishes ready-to-install `.deb` packages to the
[nightly release page](https://github.com/zebra-rs/zebra-rs/releases/tag/nightly)
for Ubuntu 22.04 (jammy), 24.04 (noble), and 26.04 (resolute), on both
x86_64 and ARM64. Download the package matching your distribution and
architecture from that page, then install it:

``` shell
sudo apt install ./<filename>.deb
```

If you only want to run zebra-rs, this is the quickest path. The rest of this
section describes building from source; the steps mirror the CI build scripts
under `.github/workflows/` (`ci.yaml`, `build-amd64.yaml`, `build-arm64.yaml`,
`nightly.yaml`).

### Build Requirements

#### Rust toolchain

Install the stable Rust toolchain with [rustup](https://rustup.rs/):

``` shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### System packages

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
| `libnanomsg-dev` | the vtysh hooks built into the `vty` shell |
| `bison` | bash's grammar, regenerated during the `vty` build |
| `xxd` | embeds `vty.sh` into the `vty` binary during the build |

Building or testing only the Rust workspace (`cargo build`, `cargo test`)
needs just `protobuf-compiler` and `libpam0g-dev` — that is all `ci.yaml`
installs. The remaining packages are used by the `vty` build and packaging.

#### XDP/eBPF toolchain: LLVM and bpf-linker

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

### Build and Install from Source

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

## Debian Package

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
sudo dpkg -i zebra-rs_26.5.1_arm64.deb
```

will install zebra-rs and start the daemon.

``` shell
vty
ubuntu>?
Exec commands:
-> cli			Command line interface
   configure		Manipulate software configuration information
   help			Show help
-> show			Show command
ubuntu>show ip route

```

## Configuration

zebra-rs keeps two configuration views:

- **running config** — what the daemon is currently acting on. Only `commit` changes it.
- **candidate config** — the editable buffer that accumulates `set` and `delete` statements until you `commit` (or `discard`) them.

Enter configure mode with `configure`, edit the candidate, then `commit`:

``` shell
ubuntu>configure
ubuntu#set system hostname r1
ubuntu#set router bgp global as 65001
ubuntu#set router bgp global router-id 10.0.0.1
ubuntu#set router bgp neighbor 10.0.0.2 remote-as 65001
ubuntu#commit
r1#show running-config
system {
  hostname r1
}
router {
  bgp {
    global {
      as 65001;
      router-id 10.0.0.1;
    }
    neighbor 10.0.0.2 {
      remote-as 65001;
    }
  }
}
```

Other useful editing commands:

| Command | Effect |
|---|---|
| `delete <path>` | Remove a leaf or list item from the candidate |
| `discard` | Revert candidate back to running |
| `load` | Re-load the on-disk config file into the candidate, then commit |
| `save` | Write the running config to the on-disk file |

The same configuration can be viewed in different formats. `show running-config formal` prints the flat `set ...` form, `show running-config json` and `show running-config yaml` print the equivalent JSON / YAML. The same trio works for `show candidate-config`.
