@multi_ipv6_address
@rib
Feature: Multiple IPv6 addresses per interface
  As a network operator
  I want to configure several IPv6 addresses on one interface
  So that the daemon mirrors the kernel's per-address model — one
  connected route per subnet that survives partial deletes, DAD state
  captured and cleared in place — while OSPFv3 and IS-IS advertise
  subnets (masked, deduped) instead of addresses, address changes
  reach peers immediately, and a link-local renumber recovers.

  Test Topology (shared bridge):
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
    2001:db8:1::1/64        2001:db8:1::9/64
    2001:db8:1::11/64          (vz2ns)
    2001:db8:2::1/64
            (vz1ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
  ```

  Config files:
  - z1.yaml: three addresses on vz1ns; OSPFv3 area 0 + IS-IS L2 on it
  - z2.yaml: one address on vz2ns; same protocols, DR priority 0 so
    z1 is always the DR (the DR's aggregated prefixes are not
    FIB-routable on the DR itself)

  Scenario: Setup topology and the kernel address model is mirrored
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # All three addresses install and complete DAD.
    Then command "ip -6 addr show vz1ns" in namespace "z1" should eventually contain "2001:db8:1::1/64"
    And command "ip -6 addr show vz1ns" in namespace "z1" should eventually contain "2001:db8:1::11/64"
    And command "ip -6 addr show vz1ns" in namespace "z1" should eventually contain "2001:db8:2::1/64"
    And command "ip -6 addr show vz1ns" in namespace "z1" should eventually not contain "tentative"
    # The daemon captured the addresses AND their DAD lifecycle: the
    # kernel's completion notification cleared the tentative flag in
    # place (netlink IFA_FLAGS capture + in-place merge).
    And show command "show interface vz1ns" in namespace "z1" should eventually contain "inet6 2001:db8:1::11/64"
    And show command "show interface vz1ns" in namespace "z1" should eventually contain "inet6 2001:db8:2::1/64"
    And show command "show interface vz1ns" in namespace "z1" should eventually not contain "tentative"
    # One kernel connected route per subnet, never one per address.
    And kernel route "2001:db8:1::/64" in namespace "z1" should eventually contain "dev vz1ns"
    And kernel route "2001:db8:2::/64" in namespace "z1" should eventually contain "dev vz1ns"

  Scenario: Protocols advertise subnets once, masked, and forwarding works
    Given the test topology exists
    Then isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And show command "show ospfv3 neighbor" in namespace "z1" should eventually contain "Full"
    # z2 learns every z1 global from one packed TLV 233 — the parser
    # must not stop at the first entry.
    And show command "show isis neighbor detail" in namespace "z2" should eventually contain "2001:db8:1::11"
    And show command "show isis neighbor detail" in namespace "z2" should eventually contain "2001:db8:2::1"
    # IS-IS IPv6 Reachability is masked and deduped: one entry per
    # subnet, no host bits on the wire.
    And show command "show isis database detail" in namespace "z2" should eventually contain "2001:db8:1::/64"
    And show command "show isis database detail" in namespace "z2" should eventually contain "2001:db8:2::/64"
    And show command "show isis database detail" in namespace "z2" should not contain "2001:db8:1::1/64"
    And show command "show isis database detail" in namespace "z2" should not contain "2001:db8:1::11/64"
    And show command "show isis database detail" in namespace "z2" should not contain "2001:db8:2::1/64"
    # The transit interface's extra subnet reaches z2 through the
    # DR's Network-LSA-referenced Intra-Area-Prefix aggregation
    # (RFC 5340 §4.4.3.9) — each router's own LSA suppresses transit
    # prefixes, so this route existing at all proves the aggregation.
    And show command "show ipv6 route" in namespace "z2" should eventually contain "2001:db8:2::/64"
    And show command "show ipv6 route" in namespace "z2" should eventually contain "via fe80"
    And ping from "z2" to "2001:db8:2::1" should eventually succeed

  Scenario: Deleting one same-subnet address keeps the connected route and the advertisement
    Given the test topology exists
    When I apply command "delete interface vz1ns ipv6 address 2001:db8:1::11/64" in namespace "z1"
    Then command "ip -6 addr show vz1ns" in namespace "z1" should eventually not contain "2001:db8:1::11/64"
    # The subnet is still covered by the sibling address: the
    # connected route survives (kernel last-cover refcount, mirrored
    # by the daemon), both protocols keep advertising it, and
    # forwarding keeps working.
    And kernel route "2001:db8:1::/64" in namespace "z1" should eventually contain "dev vz1ns"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:1::/64"
    And show command "show isis database detail" in namespace "z2" should eventually contain "2001:db8:1::/64"
    And ping from "z2" to "2001:db8:2::1" should eventually succeed

  Scenario: Address add and delete reach the peer immediately
    Given the test topology exists
    # Withdrawal: deleting the second subnet's only address must leave
    # the Link-LSA / LSP now, not at the ~30min refresh.
    When I apply command "delete interface vz1ns ipv6 address 2001:db8:2::1/64" in namespace "z1"
    Then show command "show ipv6 route" in namespace "z2" should eventually not contain "2001:db8:2::/64"
    And show command "show isis database detail" in namespace "z2" should eventually not contain "2001:db8:2::/64"
    # Re-advertisement: adding it back reaches z2 promptly through
    # both protocols' re-origination triggers.
    When I apply command "set interface vz1ns ipv6 address 2001:db8:2::1/64" in namespace "z1"
    Then show command "show ipv6 route" in namespace "z2" should eventually contain "2001:db8:2::/64"
    And ping from "z2" to "2001:db8:2::1" should eventually succeed

  Scenario: A link-local renumber on z1 is followed by z2
    Given the test topology exists
    # A numerically lower link-local wins the stable source pick:
    # z1's hellos re-source from it, z2 follows the moved source
    # (same-system new-address refresh) and re-pins its nexthops.
    When I execute "ip -6 addr add fe80::1:1/64 dev vz1ns" in namespace "z1"
    Then show command "show ipv6 route" in namespace "z2" should eventually contain "via fe80::1:1"
    And ping from "z2" to "2001:db8:2::1" should eventually succeed
    # Deleting it falls everything back to the EUI-64 link-local.
    When I execute "ip -6 addr del fe80::1:1/64 dev vz1ns" in namespace "z1"
    Then show command "show ipv6 route" in namespace "z2" should eventually not contain "via fe80::1:1"
    And ping from "z2" to "2001:db8:2::1" should eventually succeed

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
