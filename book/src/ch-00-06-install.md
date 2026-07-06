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

## Configure

Changing the running configuration means entering *configure mode*, which
requires the Admin role. There are three ways to obtain it:

1. **Run `vty` as root.** The `root` user (uid 0) is Admin automatically, so
   `configure` enters configure mode with no prompt.
2. **Enter the root password.** Any user can run `configure` and, when
   prompted, type the **root** password to elevate for the session.
3. **Join the `zebra-rs` group.** Members of the `zebra-rs` group run
   `configure` (or `enable`) with no password at all.

The package installer creates the `zebra-rs` group. To let user `kunihiro`
configure without a password, add them to it:

``` shell
sudo usermod -aG zebra-rs kunihiro
newgrp zebra-rs
```

`usermod` records the membership, but an existing login shell keeps the groups
it started with; `newgrp zebra-rs` (or logging out and back in) picks up the
new group in the current session. You might need to reboot the system to
reflect the `zebra-rs` group across every session.

Once you are a member, run `vty` and enter configure mode:

``` shell
vty
ubuntu>configure
% Enabled (admin role active for 900 seconds)
ubuntu#
```

The `% Enabled` line confirms the Admin role, which is held for 900 seconds of
idle time — refreshed on each command — up to a four-hour hard cap. In configure
mode you can review the running configuration with `show`, edit it with `set`
and `delete`, and apply your changes with `commit`.

See [VTY Access Control](ch-06-00-vty-access.md) for the full role and
authentication model.
