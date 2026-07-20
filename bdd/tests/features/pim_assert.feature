@serial
@pim_assert
Feature: PIM assert election and LAN Join/Prune behaviors
  As a network operator
  I want duplicate forwarders on a shared LAN to elect a single
  assert winner, a router's overheard Join on a shared upstream LAN
  to suppress the other joined router's periodic refresh (leaving
  one refresher per LAN), and a Prune overheard on a LAN to be
  overridden by routers that still want the traffic — the RFC 7761
  multi-access behaviors that keep exactly one copy of each packet
  on every LAN.

  r1 and r2 both connect the upstream LAN swA (toward r0 and the
  source) and the contested LAN swB. They must forward the same
  (S,G) onto swB by two independent mechanisms — so that DR gating
  (only the DR turns local membership into forwarding state) cannot
  collapse the test to a single forwarder:

    * r2 is the DR on swB and forwards for h2, a receiver attached
      directly to swB.
    * r1 is NOT the DR on swB; it forwards because r3 (downstream,
      with receiver h3) has its RPF toward the source pointed at r1
      and sends r1 an (S,G) Join.

  Both forward onto swB, the duplicate data triggers the assert, and
  the higher address (r2, 10.6.2.3) wins. r1 steps down; with its
  only outgoing interface assert-lost its JoinDesired collapses and
  it prunes toward r0. r2 overhears that Prune and overrides it,
  keeping r0 forwarding, and the assert winner then carries the LAN
  for both receivers.

  Test Topology:
  ```
    h1(src) - r0 - [swA 10.6.1/24] - r1(.2) - [swB 10.6.2/24] - r2(.3, DR) - h2(.10 direct)
                                        |             |
                                     r0 also        r3(.1) - h3   (r3 RPFs to r1)
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
    And I add address "10.6.0.10/24" to interface "eth0" in namespace "h1"
    And I add address "10.6.2.10/24" to interface "eth0" in namespace "h2"
    And I add address "10.6.3.10/24" to interface "eth0" in namespace "h3"

    # Full neighborship on the contested LAN and r2 elected DR there.
    Then show command "show pim neighbor" in namespace "r1" should eventually contain "10.6.2.3"
    And show command "show pim interface" in namespace "r2" should eventually contain "10.6.2.3"

    # Both receivers join. r2 (DR on swB) serves h2 directly; r3 turns
    # h3's membership into an (S,G) Join toward r1, so r1 forwards onto
    # swB too. On swA, r2 joins first (h2's report reaches the DR
    # directly) and r1 joins ~0.5s later (h3's membership rides the
    # extra r3 hop); r1's immediate initial Join is overheard by the
    # already-joined r2, which suppresses its own refresh
    # (RFC 7761 §4.5.7) and therefore never sends a Join for r1 to
    # overhear in turn — suppression keeps exactly one periodic
    # refresher per LAN, so only r2 logs it.
    When I spawn "timeout 220 python3 tests/scripts/ssm_recv.py 232.6.6.6 10.6.0.10 10.6.2.10 5001 /tmp/pim_assert_h2" in namespace "h2"
    And I spawn "timeout 220 python3 tests/scripts/ssm_recv.py 232.6.6.6 10.6.0.10 10.6.3.10 5001 /tmp/pim_assert_h3" in namespace "h3"
    Then show command "show pim upstream" in namespace "r1" should eventually contain "Joined"
    And show command "show pim upstream" in namespace "r2" should eventually contain "Joined"
    And daemon log in namespace "r2" should eventually contain "join suppressed"

    # The sender starts: both forward onto swB, the duplicates trigger
    # the assert election, and the higher address (r2) wins.
    When I spawn "timeout 180 python3 tests/scripts/mcast_send.py 232.6.6.6 5001 10.6.0.10 150" in namespace "h1"
    Then daemon log in namespace "r1" should eventually contain "assert loser"
    And show command "show pim assert" in namespace "r1" should eventually contain "Loser"
    And show command "show pim assert" in namespace "r1" should contain "10.6.2.3"
    And show command "show pim assert" in namespace "r2" should eventually contain "Winner"

    # The loser's only outgoing interface is gone: it withdraws from
    # the source tree; r2 overhears the Prune and overrides it.
    And daemon log in namespace "r1" should eventually contain "pruned toward"
    And daemon log in namespace "r2" should eventually contain "prune override"

    # Steady state: r0 still forwards and the assert winner carries
    # swB for both receivers.
    And command "ip mroute show" in namespace "r0" should eventually contain "Iif: eth2"
    And command "cat /tmp/pim_assert_h2" in namespace "h2" should eventually contain "ssm-hello"
    And command "cat /tmp/pim_assert_h3" in namespace "h3" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_assert_h2" in namespace "h2"
    And I execute "rm -f /tmp/pim_assert_h3" in namespace "h3"
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
