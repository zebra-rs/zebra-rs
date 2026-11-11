# system hostname names the system with feature insomnia

## Overview

As an operator of a box whose whole configuration zebra-rs owns
I want `set system hostname <name>` to rename the system itself when
zebra-rs runs with `--feature insomnia`, and `delete` to give the
system back the name it had, so that the configuration is the one
place the name is kept. Without the feature the name must stay a label
inside the daemon.

A network namespace shares the host's UTS namespace, so no BDD daemon
may reach the real `sethostname(2)`: the harness gives each one a
file-backed stand-in (`ZEBRA_HOSTNAME_STUB_DIR`), `kernel` for the
kernel name, `hostname` for /etc/hostname and `saved.json` for the name
found at the first takeover. The stand-in's kernel name before anything
set one is `localhost`, and it has no static name.

The real call, and the rule that only a zebra-rs in the default network
namespace makes it, run in the last two scenarios inside a sandbox
(tests/scripts/system_hostname_sandbox.sh): a private UTS namespace and
an overlay on /etc, so that the machine running the tests keeps its
name whatever zebra-rs does (docs/design/system-hostname.md §10).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build a single-node topology with the feature on | |
| A committed hostname becomes the system's | |
| Changing the hostname renames the system | |
| A name the kernel would refuse is refused at commit | |
| Deleting the hostname gives the system its name back | |
| A hostname removed while zebra-rs was down is given back at the next start | |
| Without the feature the hostname stays a label | |
| The real host name changes in the default network namespace | |
| The real host name is left alone outside the default network namespace | |
| Teardown topology | |
