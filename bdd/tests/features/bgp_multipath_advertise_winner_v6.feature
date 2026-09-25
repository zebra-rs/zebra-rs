@serial
@bgp_multipath_advertise_winner_v6
Feature: With maximum-paths above 1, a neighbor is sent the best path, not a multipath member (IPv6)
  As a network operator
  I want my neighbors to receive the path `show bgp` marks best when I
  install several equal-cost paths
  So what I advertise matches what I report, and a change in the ECMP
  member set alone does not re-advertise a different path.

  Path selection returns the winner first and the multipath members after
  it. The plain advertise paths took the LAST entry as "best" — a leftover
  from when the selection result was a change history — so with
  `maximum-paths 2` a neighbor was sent the ECMP member instead of the
  winner. The FIB and VRF export already read the first entry.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.51.0/24                   │
  └──────┬──────────────┬──────────────┬──────────────┬─────┘
    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
    │   h1    │    │   h2    │    │   z1    │    │   z2    │
    │scripted │    │scripted │    │  (DUT)  │    │ zebra-rs│
    │ AS65071 │    │ AS65071 │    │ AS65001 │    │ AS65072 │
    │  .2     │    │  .3     │    │  .1     │    │  .4     │
    └─────────┘    └─────────┘    └─────────┘    └─────────┘
  ```
  h1 and h2 run tests/scripts/bgp_attr_inject_send.py and announce
  2001:db8:50::/64 with the same AS_PATH ("65071") and their own global
  IPv6 next-hops (2001:db8:51::2 / ::3), so z1 installs both under
  `maximum-paths 2`. h1 tags its path with
  community 65071:2, h2 with 65071:3. The paths tie down to the BGP
  Identifier, so h1 (192.168.51.2) wins and h2 is the multipath member.

  Config files:
  - z1.yaml: DUT — eBGP to h1 and h2 (passive) and to z2; ipv6
    maximum-paths 2; IPv6 unicast over IPv4 sessions.
  - z2.yaml: z1's downstream eBGP neighbor.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.51.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.51.2/24" on bridge "br0"
    And I create namespace "h2" with IP "192.168.51.3/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.51.4/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:51::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:51::2/64 dev vh1ns" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8:51::3/64 dev vh2ns" in namespace "h2"
    And I execute "ip -6 addr add 2001:db8:51::4/64 dev vz2ns" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.51.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.51.1 65071 192.168.51.2 6 2001:db8:51::2 /tmp/bgp_multipath_advertise_winner_v6_h1 2001:db8:50::/64=c0:08:fe2f0002" in namespace "h1"
    And I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.51.1 65071 192.168.51.3 6 2001:db8:51::3 /tmp/bgp_multipath_advertise_winner_v6_h2 2001:db8:50::/64=c0:08:fe2f0003" in namespace "h2"
    Then BGP session in "z1" to "192.168.51.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.51.3" should eventually be "Established"

  Scenario: z1 installs both paths, with h1's as the best path
    Given the test topology exists
    # "*=" marks the multipath member beside the ">" best path.
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "*="
    And show command "show bgp ipv6 2001:db8:50::/64" in namespace "z1" should contain "Community: 65071:2"
    And show command "show bgp ipv6 2001:db8:50::/64" in namespace "z1" should contain "Community: 65071:3"

  Scenario: z2 is sent the best path, not the multipath member
    Given the test topology exists
    # Pre-fix z2 was sent h2's path (65071:3): the plain fan-out took the
    # last entry of the selection, the multipath member.
    Then show command "show bgp ipv6 2001:db8:50::/64" in namespace "z2" should eventually contain "Community: 65071:2"
    And show command "show bgp ipv6 2001:db8:50::/64" in namespace "z2" should not contain "65071:3"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
