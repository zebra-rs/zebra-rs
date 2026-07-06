# <img src="docs/logo.svg" alt="Project Logo" width="25" height="25"> zebra-rs

zebra-rs is a BGP, OSPF, and IS‑IS routing stack with SRv6, SR-MPLS, L3VPN, and EVPN extensions, written from scratch in Rust. Memory‑safe, async to the core, idempotent by design — and the first routing daemon to ship with a native MCP server for AI agents. Project Home Page <http://zebra.rs/>.

## Quick Install

Prebuilt `.deb` packages are currently provided only for the following Ubuntu
releases. Other distributions or releases are not packaged yet and should be
[built from source](https://zebra.rs/docs.html).

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

## Documentation

Full documentation lives at <https://zebra.rs/docs.html>, including:

- **Install** — nightly packages and the supported distribution matrix.
- **Building** — building from source, the `packaging/setup-build-env.sh`
  build-host setup script, and the Debian package build.
- **Configuration** — the candidate/running config model, the CLI, and every
  supported protocol and feature.
