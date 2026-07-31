@ipv4_address_secondary
@rib
Feature: Multiple IPv4 addresses per interface with kernel secondary flag
  As a network operator
  I want to configure several IPv4 addresses on one interface
  So that same-subnet duplicates carry the kernel's IFA_F_SECONDARY
  verdict — no config keyword — while routing protocols keep treating
  the interface as one link per subnet: the connected route survives a
  secondary's removal, advertisements count subnets not addresses, and
  nexthops/endpoints always use the primary.

  Test Topology (shared bridge):
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
      10.0.1.1/24 (primary)  10.0.1.9/24
      10.0.1.2/24 (secondary)  (vz2ns)
      10.2.0.1/24 (primary)
            (vz1ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
  ```

  Config files:
  - z1.yaml: three addresses on vz1ns; OSPFv2 area 0 + IS-IS L2 on it
  - z2.yaml: one address on vz2ns; same protocols

  Scenario: Setup topology and the kernel computes the secondary verdict
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    # Pin the kernel default: deleting a primary must cascade its
    # same-subnet secondaries away, not promote them (the daemon
    # mirrors that cascade for configured siblings).
    And I execute "sysctl -w net.ipv4.conf.all.promote_secondaries=0" in namespace "z1"
    And I execute "sysctl -w net.ipv4.conf.default.promote_secondaries=0" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # Kernel truth: same subnet + same mask as an earlier address →
    # IFA_F_SECONDARY; the distinct-subnet 10.2.0.1 stays primary.
    Then command "ip -4 addr show vz1ns" in namespace "z1" should eventually contain "10.0.1.2/24 scope global secondary"
    And command "ip -4 addr show vz1ns" in namespace "z1" should eventually contain "10.2.0.1/24 scope global vz1ns"
    # The daemon reads the flag back (config-driven install has no
    # netlink self-echo, so this proves the local verdict mirror).
    And show command "show interface vz1ns" in namespace "z1" should eventually contain "inet 10.0.1.2/24 secondary"
    And show command "show interface vz1ns" in namespace "z1" should not contain "inet 10.0.1.1/24 secondary"
    And show command "show interface vz1ns" in namespace "z1" should not contain "inet 10.2.0.1/24 secondary"
    # One kernel connected route per subnet, never one per address.
    And kernel route "10.0.1.0/24" in namespace "z1" should eventually contain "dev vz1ns"
    And kernel route "10.2.0.0/24" in namespace "z1" should eventually contain "dev vz1ns"

  Scenario: Protocols advertise subnets once and pick the primary as nexthop
    Given the test topology exists
    Then isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And show command "show ospf neighbor" in namespace "z1" should eventually contain "Full"
    # z2 learns every z1 interface address from one packed TLV 132 —
    # the parser must not stop at the first entry.
    And show command "show isis neighbor detail" in namespace "z2" should eventually contain "10.0.1.2"
    And show command "show isis neighbor detail" in namespace "z2" should eventually contain "10.2.0.1"
    # z1's Router-LSA: transit 10.0.1.0/24 + stub 10.2.0.0/24 = 2
    # links. A counted secondary would make it 3. (z2's own LSA has 1.)
    And show command "show ospf database detail" in namespace "z2" should eventually contain "Number of Links: 2"
    And show command "show ospf database detail" in namespace "z2" should not contain "Number of Links: 3"
    # IS-IS reachability is deduped: both subnets present.
    And show command "show isis database detail" in namespace "z2" should eventually contain "10.0.1.0/24"
    And show command "show isis database detail" in namespace "z2" should eventually contain "10.2.0.0/24"
    # The learned route uses z1's primary as nexthop; the secondary is
    # never a nexthop anywhere in the table (OSPF and IS-IS both).
    And show command "show ip route" in namespace "z2" should eventually contain "10.2.0.0/24"
    And show command "show ip route" in namespace "z2" should eventually contain "via 10.0.1.1"
    And show command "show ip route" in namespace "z2" should not contain "via 10.0.1.2"
    And ping from "z2" to "10.2.0.1" should eventually succeed

  Scenario: Deleting the secondary keeps the connected route and the advertisement
    Given the test topology exists
    When I apply command "delete interface vz1ns ipv4 address 10.0.1.2/24" in namespace "z1"
    Then command "ip -4 addr show vz1ns" in namespace "z1" should eventually not contain "10.0.1.2/24"
    # The subnet is still covered by the primary: connected route
    # stays, both protocols keep advertising it, forwarding keeps
    # working.
    And kernel route "10.0.1.0/24" in namespace "z1" should eventually contain "dev vz1ns"
    And show command "show ip route" in namespace "z1" should eventually contain "10.0.1.0/24"
    And show command "show isis database detail" in namespace "z2" should eventually contain "10.0.1.0/24"
    And show command "show ip route" in namespace "z2" should eventually contain "via 10.0.1.1"
    And ping from "z2" to "10.2.0.1" should eventually succeed

  Scenario: Deleting the primary hands the subnet to the configured sibling
    Given the test topology exists
    # Restore the secondary first; it must come back as a secondary.
    When I apply command "set interface vz1ns ipv4 address 10.0.1.2/24" in namespace "z1"
    Then show command "show interface vz1ns" in namespace "z1" should eventually contain "inet 10.0.1.2/24 secondary"
    # Config-deleting the primary makes the kernel cascade 10.0.1.2
    # away (promote_secondaries=0); the daemon mirrors the cascade and
    # re-installs the still-configured sibling, which the kernel now
    # accepts as the subnet's primary.
    When I apply command "delete interface vz1ns ipv4 address 10.0.1.1/24" in namespace "z1"
    Then command "ip -4 addr show vz1ns" in namespace "z1" should eventually not contain "10.0.1.1/24"
    And command "ip -4 addr show vz1ns" in namespace "z1" should eventually contain "10.0.1.2/24 scope global vz1ns"
    And command "ip -4 addr show vz1ns" in namespace "z1" should not contain "secondary"
    And kernel route "10.0.1.0/24" in namespace "z1" should eventually contain "dev vz1ns"
    # Hellos re-source and LSAs/LSPs re-originate promptly: z2's
    # nexthop follows the new primary without waiting for a refresh.
    And show command "show ip route" in namespace "z2" should eventually contain "via 10.0.1.2"
    And show command "show ip route" in namespace "z2" should eventually not contain "via 10.0.1.1"
    And ping from "z2" to "10.2.0.1" should eventually succeed

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
