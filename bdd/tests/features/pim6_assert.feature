@serial
@pim6_assert
Feature: PIMv6 assert election and LAN Join/Prune behaviors
  As a network operator
  I want duplicate forwarders on a shared IPv6 LAN to elect a single
  assert winner, routers sharing an upstream LAN to suppress each other's
  periodic Joins, and a Prune overheard on a LAN to be overridden by
  routers that still want the traffic — the RFC 7761 multi-access
  behaviors that keep exactly one copy of each packet on every LAN.

  r1 and r2 both connect the upstream LAN swA (toward r0 and the source)
  and the contested LAN swB. They must forward the same (S,G) onto swB by
  two independent mechanisms — so that DR gating cannot collapse the test
  to a single forwarder:

    * r2 is the DR on swB (highest dr-priority) and forwards for h2, a
      receiver attached directly to swB.
    * r1 is NOT the DR on swB; it forwards because r3 (downstream, with
      receiver h3) has its RPF toward the source pointed at r1.

  Both forward onto swB and the duplicate data triggers the assert. The
  IPv6 assert tiebreak is the link-local source (non-deterministic on
  veths), so the winner is made deterministic by RPF cost instead: r2's
  static route to the source has a lower metric than r1's, so r2 wins and
  r1 steps down, prunes toward r0, and r2 overrides that Prune — the
  assert winner then carries swB for both receivers.

  Test Topology:
  ```
    h1(src) - r0 - [swA 2001:db8:61/64] - r1(::2) - [swB 2001:db8:62/64] - r2(::3, DR) - h2(::10 direct)
                                             |             |
                                          r0 also        r3(::1) - h3   (r3 RPFs to r1)
  ```

  Scenario: Assert election, join suppression and prune override on LANs
    Given a clean test environment
    When I create namespace "swa"
    And I create namespace "swb"
    And I create namespace "r0"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "h1"
    And I create namespace "h2"
    And I create namespace "h3"
    And I connect namespace "r0" interface "eth1" to namespace "swa" interface "pa0"
    And I connect namespace "r1" interface "eth1" to namespace "swa" interface "pa1"
    And I connect namespace "r2" interface "eth1" to namespace "swa" interface "pa2"
    And I connect namespace "r1" interface "eth2" to namespace "swb" interface "pb1"
    And I connect namespace "r2" interface "eth2" to namespace "swb" interface "pb2"
    And I connect namespace "r3" interface "eth1" to namespace "swb" interface "pb3"
    And I connect namespace "h2" interface "eth0" to namespace "swb" interface "pb4"
    And I connect namespace "r0" interface "eth2" to namespace "h1" interface "eth0"
    And I connect namespace "r3" interface "eth2" to namespace "h3" interface "eth0"
    And I execute "ip link add bra type bridge mcast_snooping 0" in namespace "swa"
    And I execute "ip link set pa0 master bra" in namespace "swa"
    And I execute "ip link set pa1 master bra" in namespace "swa"
    And I execute "ip link set pa2 master bra" in namespace "swa"
    And I execute "ip link set bra up" in namespace "swa"
    And I execute "ip link add brb type bridge mcast_snooping 0" in namespace "swb"
    And I execute "ip link set pb1 master brb" in namespace "swb"
    And I execute "ip link set pb2 master brb" in namespace "swb"
    And I execute "ip link set pb3 master brb" in namespace "swb"
    And I execute "ip link set pb4 master brb" in namespace "swb"
    And I execute "ip link set brb up" in namespace "swb"
    And I start zebra-rs in namespace "r0"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r0.yaml" to namespace "r0"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I add address "2001:db8:60::10/64" to interface "eth0" in namespace "h1"
    And I add address "2001:db8:62::10/64" to interface "eth0" in namespace "h2"
    And I add address "2001:db8:63::10/64" to interface "eth0" in namespace "h3"

    # Neighborship on the contested LAN.
    Then show command "show pim ipv6 neighbor" in namespace "r1" should eventually contain "fe80"

    # Both receivers source-specifically join. r2 (DR on swB) serves h2
    # directly; r3 turns h3's membership into an (S,G) Join toward r1, so
    # r1 forwards onto swB too. Each router overhears the other's Join on swA.
    When I spawn "timeout 260 python3 tests/scripts/ssm_recv6.py ff3e::6 2001:db8:60::10 eth0 5001 /tmp/pim6_assert_h2" in namespace "h2"
    And I spawn "timeout 260 python3 tests/scripts/ssm_recv6.py ff3e::6 2001:db8:60::10 eth0 5001 /tmp/pim6_assert_h3" in namespace "h3"
    Then show command "show pim ipv6 upstream" in namespace "r1" should eventually contain "Joined"
    And show command "show pim ipv6 upstream" in namespace "r2" should eventually contain "Joined"

    # The sender starts: both forward onto swB, the duplicates trigger
    # the assert, and the lower RPF metric (r2) wins deterministically.
    # (Join suppression and prune override are generic LAN J/P behaviors
    # already proven in the IPv4 `pim_assert`; here the point is that the
    # Assert itself elects a winner over the PIMv6 transport.)
    When I spawn "timeout 200 python3 tests/scripts/mcast_send6.py ff3e::6 5001 eth0 170" in namespace "h1"
    Then show command "show pim ipv6 assert" in namespace "r2" should eventually contain "Winner"
    And show command "show pim ipv6 assert" in namespace "r1" should eventually contain "Loser"

    # Steady state: the assert winner carries swB for both receivers.
    And command "cat /tmp/pim6_assert_h2" in namespace "h2" should eventually contain "ssm-hello"
    And command "cat /tmp/pim6_assert_h3" in namespace "h3" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_assert_h2" in namespace "h2"
    And I execute "rm -f /tmp/pim6_assert_h3" in namespace "h3"
    And I stop zebra-rs in namespace "r0"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r0"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "swa"
    And I delete namespace "swb"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "h3"
    Then the test environment should be clean
