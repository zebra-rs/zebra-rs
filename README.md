# <img src="docs/logo.svg" alt="Project Logo" width="25" height="25"> zebra-rs

zebra-rs is a BGP, OSPF, and IS‑IS routing stack with SRv6, SR-MPLS, L3VPN, and EVPN extensions, written from scratch in Rust. Memory‑safe, async to the core, idempotent by design — and the first routing daemon to ship with a native MCP server for AI agents. Project Home Page <http://zebra.rs/>.

## Install Instruction

To build the project, we need protocol buffer's `protoc` compiler.

On Linux,

``` shell
sudo apt install -y protobuf-compiler
```

will be necessary.

After that,

``` shell
make all
make install
```

will install `zebra`, `vty`, and `vtyctl` under the `${HOME}/.zebra/bin` directory.
Please add

``` shell
export PATH="${PATH}:${HOME}/.zebra/bin"
```

to your `.bashrc`, `.zshrc`, or any other shell profile.

## Debian Package

``` shell
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y protobuf-compiler bison libpam0g-dev
```

To build a Debian package, we use the [`nfpm`](https://github.com/goreleaser/nfpm) package builder. Install nfpm as follows:

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

This produces a `.deb` package for the selected architecture.

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

