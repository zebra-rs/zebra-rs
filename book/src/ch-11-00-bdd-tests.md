# BDD Integration Tests

zebra-rs ships a behaviour-driven integration suite under `bdd/`. Each
scenario builds a **real** topology of Linux network namespaces, starts
one `zebra-rs` daemon per namespace, drives it through `vtyctl`, and
asserts on live `show` output, route tables, and `ping` reachability —
so the tests exercise the actual control plane and kernel forwarding,
not a mock.

The suite is written with [cucumber-rs]. Scenarios live in
[Gherkin] `.feature` files under `bdd/tests/features/`; the step
definitions that back them are in `bdd/tests/cucumber.rs`.

[cucumber-rs]: https://github.com/cucumber-rs/cucumber
[Gherkin]: https://cucumber.io/docs/gherkin/reference

## Anatomy of a feature

Every feature file opens with a tag that names it, for example
`@ospf_clear_neighbor`. That tag is more than a label: the harness uses
it to scope every namespace, bridge, and pid-file name it creates
(`<tag>_o1`, `br_<hash>`, …), so different features can run side by side
without colliding on host-global resource names.

A scenario typically follows the same shape:

1. `Given a clean test environment` — sweep any stale namespaces, bridges,
   and pid files left by a crashed prior run of *this* feature.
2. **Build** the topology — create namespaces, link them, start
   `zebra-rs`, apply per-router config.
3. **Assert** — `show` command contents, BGP/OSPF/IS-IS state, `ping`.
4. **Teardown** — stop the daemons, delete the namespaces and bridge,
   then `Then the test environment should be clean`.

## Running the suite

The helpers shell out to `sudo ip netns …`, so the tests need
**passwordless `sudo`** (or to be run as root). You do *not* prefix
`cargo test` with `sudo` yourself — the harness elevates the individual
`ip` calls.

The `bdd/Makefile` wraps the common invocations:

```sh
cd bdd
make                       # run every feature
make ospf_clear_neighbor   # run one feature by its make target
```

Under the hood each target is a tag filter:

```sh
cargo test --test cucumber -- --concurrency=1 --tags "@ospf_clear_neighbor"
```

`--concurrency=1` keeps scenarios serial (they manipulate host-global
namespaces). The `--tags` expression supports `not`, `and`, and `or`, so
you can select or exclude scenarios — e.g. `--tags "@isis_l1_p2p or
@isis_tilfa"`.

## Keeping the topology for inspection — `BDD_KEEP`

By default a scenario tears its topology down at the end, even on
failure, leaving nothing to look at. Set the **`BDD_KEEP`** environment
variable to turn the teardown steps into no-ops so the daemons,
namespaces, veths, and bridge survive the run:

```sh
BDD_KEEP=1 make ospf_clear_neighbor
```

With `BDD_KEEP` set, four steps are skipped (each prints a `⏭  BDD_KEEP
set …` line instead of acting):

- `I stop zebra-rs in namespace …` — the daemon keeps running,
- `I delete namespace …` — the namespace stays up,
- `I delete bridge …` — the bridge stays up,
- `Then the test environment should be clean` — the cleanliness check is
  skipped (it would otherwise fail, by design, because the topology is
  still present).

The scenario still runs to completion and its assertions still apply;
only the cleanup is held back. Once the run finishes you can inspect the
live topology directly — the namespaces are named `<feature-tag>_<node>`:

```sh
sudo ip netns list
sudo ip netns exec ospf_clear_neighbor_o1 vtyctl show "show ip ospf neighbor"
sudo ip netns exec ospf_clear_neighbor_o1 ip route
```

Per-daemon logs are written to `bdd/logs/<namespace>.log` regardless of
`BDD_KEEP`, so they are available even on a normal run.

> **Note** — a kept topology never leaks into a later run. The next run
> of the same feature begins with `Given a clean test environment`,
> which kills the stale pid files and deletes the prefix-matched
> namespaces and bridge before rebuilding. You can also tear it down by
> hand with `sudo ip netns del <feature-tag>_<node>`.

`BDD_KEEP` is a coarse switch: it gates the teardown step definitions
globally, so if a scenario ever used `delete namespace` or `stop
zebra-rs` mid-test (rather than only as teardown) those would be
suppressed too. In today's features those steps appear only in the
teardown block, so the flag does exactly what its name implies.
