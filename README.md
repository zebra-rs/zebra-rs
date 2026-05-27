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

zebra-rs keeps two configuration views:

- **running config** — what the daemon is currently acting on. Only `commit` changes it.
- **candidate config** — the editable buffer that accumulates `set` and `delete` statements until you `commit` (or `discard`) them.

Enter configure mode with `configure`, edit the candidate, then `commit`:

``` shell
ubuntu>configure
ubuntu#set system hostname r1
ubuntu#set router bgp 65000 router-id 10.0.0.1
ubuntu#set router bgp 65000 neighbor 10.0.0.2 peer-as 65001
ubuntu#commit
r1#show running-config
system {
    hostname r1
}
router {
    bgp 65000 {
        router-id 10.0.0.1
        neighbor 10.0.0.2 {
            peer-as 65001
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
