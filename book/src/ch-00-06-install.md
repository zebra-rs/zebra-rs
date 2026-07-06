# Install

The fastest way to get zebra-rs is a prebuilt Debian package — no toolchain,
no compile step. There are two ways to obtain one:

- **[Quick Install](#quick-install)** — an install script that fetches the
  latest stable release for your distribution and CPU architecture.
- **[Nightly Packages](#nightly-packages)** — packages rebuilt from the tip of
  the tree by the nightly CI workflow.

If your distribution is not packaged, or you want to build from source, see
[Building](ch-00-07-building.md).

## Quick Install

Prebuilt `.deb` packages are currently provided only for the following Ubuntu
releases. Other distributions or releases are not packaged yet and should
[build from source](ch-00-07-building.md).

| Ubuntu release | Code name | Architectures |
|---|---|---|
| 22.04 | jammy | x86_64, ARM64 |
| 24.04 | noble | x86_64, ARM64 |
| 26.04 | resolute | x86_64, ARM64 |

The install script detects your distribution and CPU architecture, fetches the
matching prebuilt `.deb` package, and installs it:

``` shell
curl -fsSL https://zebra.rs/install.sh | bash
```

The script downloads the latest package from the
[GitHub releases](https://github.com/zebra-rs/zebra-rs/releases) and installs
it with `apt`, so it pulls in the runtime dependencies automatically. It needs
`sudo` for the install step. Piping a remote script into `bash` runs it with
your privileges — read it first at <https://zebra.rs/install.sh> if you'd rather
review before running.

## Nightly Packages

The nightly CI workflow publishes ready-to-install `.deb` packages to the
[nightly release page](https://github.com/zebra-rs/zebra-rs/releases/tag/nightly)
for Ubuntu 22.04 (jammy), 24.04 (noble), and 26.04 (resolute), on both
x86_64 and ARM64. Download the package matching your distribution and
architecture from that page, then install it:

``` shell
sudo apt install ./<filename>.deb
```

Installing with `apt` (rather than `dpkg -i`) lets it resolve the runtime
dependencies for you.

## First run

Once installed, the `zebra-rs` daemon is running. Connect to it with the `vty`
shell:

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

See the configuration chapters for how to drive it from there.
