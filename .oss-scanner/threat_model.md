# Threat model

## What this project does and where untrusted input enters
zebra-rs is a routing daemon for Linux: BGP, OSPFv2/v3, IS-IS, BFD, STAMP,
PIM/IGMP/MLD and IPv6 ND, with SR-MPLS, SRv6, L3VPN, EVPN and MUP extensions.
It runs as root (the packaged systemd unit), programs the kernel FIB over
netlink, and sits on the control plane of the networks it routes for: a wrong
route or a stalled protocol affects every packet forwarded through the box.

Untrusted:
- **BGP (TCP 179).** `accept` drops a connection whose source is neither a
  configured neighbor nor inside a configured `listen-range` before any byte is
  read (`zebra-rs/src/bgp/peer.rs` `handle_peer_connection`,
  `try_dynamic_accept`). A configured neighbor is usually another
  organisation's router: treat every OPEN/UPDATE/NOTIFICATION/ROUTE-REFRESH
  from it as hostile. Framing is in `peer_read`; decoding is
  `BgpPacket::parse_packet` in `crates/bgp-packet` (all AFI/SAFIs, path
  attributes and capabilities). TCP-MD5/TCP-AO (`zebra-rs/src/bgp/auth.rs`)
  and GTSM (`zebra-rs/src/bgp/ttl.rs`) are optional and per neighbor.
- **OSPFv2/v3 (raw IP protocol 89), IS-IS (AF_PACKET, LLC/NLPID 0x83), BFD
  (UDP 3784/4784), STAMP (UDP 862), PIM (protocol 103), IGMP/MLD, ND/RA
  (ICMPv6).** Any host on an enabled link, or anything that can route the
  packet to a local address, reaches the parser. Authentication, where the
  protocol has it, is optional and checked after parsing.
- **PFCP (UDP 8805)** when the MUP controller (`zebra-rs/src/mup_c`) is
  configured; PFCP sessions become BGP MUP routes.
- **Data-plane-derived state:** MACs learned from frames (bridge FDB) and
  IGMP/MLD snooping (MDB) reach EVPN route origination through netlink and
  cradle. The netlink messages themselves come from the kernel and are trusted.

Local, semi-trusted:
- **The vty gRPC server** (`zebra-rs/src/config/serve.rs`, `session.rs`,
  `proto/*.proto`): a Linux abstract Unix socket `@zebra-rs/vty` by default,
  or `unix:/PATH` / `tcp:HOST:PORT` via `--vty-socket`. Callers are identified
  by `SO_PEERCRED`; uid 0 is admin and everyone else starts view-only.
  `enable` raises a session to admin: members of the `zebra-rs` group without
  a password, other users with root's password checked through PAM
  (`vtypam`). A local user who gains
  admin, changes config, reads secrets (BGP/OSPF/IS-IS keys) or impersonates
  an endpoint (the vty socket, cradle's `@cradle/grpc`) is crossing a
  boundary.
- **`vtypam`** (`/usr/sbin/vtypam`, file capabilities `cap_dac_read_search`,
  `cap_audit_write`): the PAM helper behind `enable`.
- **`zebra-topology`** (`ai/topology`, shipped in the .deb, not started by the
  unit): lab visualizer with an HTTP listener.

Trusted: the config file and YANG schemas, the admin's vty commands, the kernel
(netlink), the cradle-rs binary itself, and the operator's command line and
environment.

## Components that matter most / least
- Most: `crates/bgp-packet`, `crates/isis-packet`, `crates/ospf-packet`,
  `crates/bfd-packet`, `crates/stamp-packet`, `crates/pim-packet`,
  `crates/nd-packet`, `crates/packet-utils`; then the receive paths and state
  machines that consume them under `zebra-rs/src/{bgp,ospf,isis,bfd,stamp,pim,nd,mup_c}`
  (adjacency/session FSMs, LSDB and LSP flooding, SPF/TI-LFA inputs, BGP RIB,
  policy, RFC 7606 error handling, graceful restart).
- Also in scope: route installation (`zebra-rs/src/rib`, `zebra-rs/src/fib`),
  the vty/session code in `zebra-rs/src/config`, `vtypam`, `vtyctl`/`vtyhelper`
  as clients, and the graceful-restart checkpoint files under
  `/var/lib/zebra-rs/checkpoint`.
- Low: the Lua engine (`zebra-rs/src/script`, cargo feature `lua`, off by
  default) and `ai/topology`.
- Out of scope: `bdd/` (test harness), `tools/` (bgp-bench, fpm-tap,
  pfcp-inject are test utilities), `playset/` (lab topologies), `docs/`,
  `book/`, `rfc/`, `tests/`, `packaging/`, and `vty/` (build glue for the
  operator's patched bash shell, which runs as the invoking user).

## How to exercise it
- The checkout is `/src`. Every binary and test target is prebuilt in
  `target/debug`; the daemon is also built in `target/release/zebra-rs`.
  `CARGO_NET_OFFLINE=true` is set and the registry is warm, so
  `cargo test -p <crate>` rebuilds only what changed. The agent has 2 CPUs:
  keep `-j2`.
- Parser bugs: write a `#[test]` that feeds hex bytes to the crate's entry
  point, as the existing tests do — `BgpPacket::parse_packet(buf, as4, opt)`
  (`crates/bgp-packet/tests/parser.rs`), `isis_packet::parse` (the daemon
  strips the 3 LLC bytes first; `crates/isis-packet/tests/parser.rs`),
  `ospf_packet::parse` / `parse_v3` (`crates/ospf-packet/tests/ospfv2.rs`),
  `ControlPacket::parse` (`crates/bfd-packet/tests/roundtrip.rs`),
  `SenderPacket::parse` / `ReflectorPacket::parse`
  (`crates/stamp-packet/tests/roundtrip.rs`).
- Daemon bugs: run zebra-rs in a network namespace and attack it from another
  one. The abstract vty socket is per namespace, so several daemons coexist.
  `python3-scapy` is installed for OSPF/IS-IS/BFD frames. Example:

  ```sh
  ip netns add r1; ip netns add r2
  ip link add v1 netns r1 type veth peer name v2 netns r2
  ip -n r1 addr add 192.168.0.1/24 dev v1; ip -n r1 link set v1 up; ip -n r1 link set lo up
  ip -n r2 addr add 192.168.0.2/24 dev v2; ip -n r2 link set v2 up; ip -n r2 link set lo up
  # bdd/tests/configs/<feature>/*.yaml has a config for almost every feature
  ip netns exec r1 target/debug/zebra-rs --yang-path /src/zebra-rs/yang \
      --config-file bdd/tests/configs/bgp_basic_ebgp/z1-1.yaml &
  ip netns exec r1 target/debug/vtyctl show "show bgp neighbor"
  # then speak BGP to 192.168.0.1:179 from r2, e.g. a Python socket
  ```
- `crates/{bgp,isis,ospf}-packet/AUDIT.md` list earlier audit findings that
  are still open and deliberately deferred; do not report those again unless
  you show a worse impact than they record.

## How you rate severity
A panic is the main failure mode to look for. Protocol instances and socket
readers run as tokio tasks; a panic kills that task without restarting it, so
the protocol silently stops (or a session hangs until its hold timer) while
the rest of the daemon keeps running.

- Critical: memory corruption or code execution reachable from the network;
  bypass of TCP-MD5/TCP-AO or OSPF/IS-IS cryptographic authentication that
  lets a sender without the key inject routing state; config change or
  command execution through the vty by a local user who is not admin.
- High: a packet from an unauthenticated sender (any host on an enabled link,
  any host that can reach a UDP listener) that crashes the daemon, kills a
  protocol instance or socket reader, or injects or removes routes; a
  malformed message from a configured BGP neighbor that takes down the BGP
  instance or other neighbors' sessions; a route accepted past configured
  policy (prefix sets, AS-path matches) or AS-path loop detection; local
  privilege escalation through `vtypam` or the vty.
- Medium: a small input that causes unbounded memory or CPU (amplification),
  or a lasting hang; a single session reset where RFC 7606 requires
  treat-as-withdraw; secrets disclosed to a local non-admin user.
- Low: log flooding, wrong `show` output, crashes that need admin
  configuration to reach.
- Release builds have no overflow checks. An arithmetic-overflow panic seen
  only in a debug build counts by what the release build does with the
  wrapped value (`target/release/zebra-rs`).

## Reports and patches
- One report per root cause. The same bug in OSPFv2 and OSPFv3 (or in IPv4
  and IPv6 paths) is one report.
- Reproducer: a hex-bytes `#[test]` in the owning crate when the bug is in a
  parser, otherwise a netns script like the one above.
- Patch: a minimal diff plus the regression test, formatted with
  `cargo fmt --all` and clean under
  `cargo clippy --workspace --all-targets -- -D warnings`.

## Anything to leave alone
- Anything that needs admin on the vty, a malicious config or YANG file, or
  control of the kernel, cradle-rs or the daemon's command line/environment.
- Volumetric flooding of a listener; control-plane policing is the operator's
  job. Amplification (small input, large cost) is in scope.
- Spoofed packets on an interface where the operator configured no
  authentication, when the protocol behaves as its RFC specifies.
- Missing protocol features or RFC deviations with no security impact.
- Vulnerabilities in dependencies with no reachable path from zebra-rs.
