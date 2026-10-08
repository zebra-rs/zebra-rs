# OVN / cEOS functional validation

Validated on 2026-10-08 against zebra-rs base revision
`1f9343d8803e06603d02246b40db5cb171de488c`, with the changes on
`ovn-native-evpn`. The JSON records the working-tree diff hash and the
SHA-256 of the identical zebra-rs binaries installed on both hosts.

| Component | Version |
| --- | --- |
| OVN | 26.09.0 |
| OVS library | 3.7.90 |
| cEOS container image | 4.36.2F |
| Linux kernel | 7.0.0-1013-aws |
| zebra-rs base | 26.10.1 |

The lab uses two Kind hosts connected to two Arista cEOS leaves with
Containerlab, local OVN dual-stack workloads, an external switched host
and an external routed host. L2 VNI 1000 and L3 VNI 2000 exchange
state through Linux Netlink; OVS forwards tenant traffic on `br-int`.

| Validation | Result |
| --- | --- |
| FRR control | 47/47 acceptance checks passed |
| Unmodified zebra-rs | 11/47 acceptance checks passed |
| This feature branch, fresh image and cluster | **47/47 passed** |
| Rust workspace tests (excluding privileged BDD) | 3,730 passed, 13 ignored |
| Synthetic kernel → OVN → OVS: 1,000 MACs + 1,000 IPv4 + 1,000 IPv6 bindings | Installed and cleaned, zero remaining flow delta |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |

The full suite includes BGP sessions, Type-3 import, dual-stack Type-2
export/import/forwarding, dual-stack Type-5 export/kernel/Southbound
import/forwarding, internal OVN dual stack, VXLAN captures on both VNIs,
access-link withdrawal and restoration, routed-prefix withdrawal and
restoration, and speaker restart with forwarding recovery. See
[the individual results](ovn-ceos-kind.json).

These are functional interoperability checks at small route counts. They
do not establish 500k-route speaker capacity, convergence performance,
IPv6 VTEP support, mobility or EVPN multihoming/ECMP behavior. The host
was not a dedicated performance benchmark machine. The Kind/cEOS lab
launcher is maintained in the companion OVN workspace under
`tutorial/ovn-zebra-kind`; reproducing it requires a licensed cEOS image.

For the routing configuration and kernel contract, see
[Native OVN EVPN route exchange](../ovn-route-exchange.md).

[The synthetic scale report](ovn-kernel-scale-1000-dual.json) measures the
kernel-to-OVN path. Its entries bypass BGP, so it does not benchmark the
speaker's BGP throughput or route capacity.
