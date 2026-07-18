@serial
@pim_assert
Feature: PIM assert election and LAN Join/Prune behaviors
  As a network operator
  I want duplicate forwarders on a shared LAN to elect a single
  assert winner, routers sharing an upstream LAN to suppress each
  other's periodic Joins, and a Prune overheard on a LAN to be
  overridden by routers that still want the traffic — the RFC 7761
  multi-access behaviors that keep exactly one copy of each packet
  on every LAN.

  r1 and r2 both connect the upstream LAN (swA, toward r0 and the
  source) and the receiver LAN (swB). Both track h2's IGMPv3 join
  (no DR gating on local membership), so both join (S,G) toward r0 —
  each must log the other's Join as suppressing — and both forward
  onto swB, where the duplicate data triggers the assert election.
  Metrics tie, so the higher address (r2, 10.6.2.3) must win; r1
  must step down, and with its only outgoing interface assert-lost
  its JoinDesired collapses — it prunes toward r0. r2 must overhear
  that Prune and send the override Join, keeping r0 forwarding, and
  h2 must keep receiving through r2.

  Test Topology:
  ```
    h1 --- r0 --- [swA LAN 10.6.1.0/24] --- r1 --- [swB LAN 10.6.2.0/24] --- h2
   (src)           .1(r0) .2(r1) .3(r2)     r2          .2(r1) .3(r2)      (rcv)
  ```

  Scenario: Assert election, join suppression and prune override on LANs
    Given a clean test environment
    When I create namespace "swa"
    And I create namespace "swb"
    And I create namespace "r0"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h1"
    And I create namespace "h2"
    And I connect namespace "r0" interface "eth1" to namespace "swa" interface "pa0"
    And I connect namespace "r1" interface "eth1" to namespace "swa" interface "pa1"
    And I connect namespace "r2" interface "eth1" to namespace "swa" interface "pa2"
    And I connect namespace "r1" interface "eth2" to namespace "swb" interface "pb1"
    And I connect namespace "r2" interface "eth2" to namespace "swb" interface "pb2"
    And I connect namespace "h2" interface "eth0" to namespace "swb" interface "pb3"
    And I connect namespace "r0" interface "eth2" to namespace "h1" interface "eth0"
    And I execute "ip link add bra type bridge mcast_snooping 0" in namespace "swa"
    And I execute "ip link set pa0 master bra" in namespace "swa"
    And I execute "ip link set pa1 master bra" in namespace "swa"
    And I execute "ip link set pa2 master bra" in namespace "swa"
    And I execute "ip link set bra up" in namespace "swa"
    And I execute "ip link add brb type bridge mcast_snooping 0" in namespace "swb"
    And I execute "ip link set pb1 master brb" in namespace "swb"
    And I execute "ip link set pb2 master brb" in namespace "swb"
    And I execute "ip link set pb3 master brb" in namespace "swb"
    And I execute "ip link set brb up" in namespace "swb"
    And I start zebra-rs in namespace "r0"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r0.yaml" to namespace "r0"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "10.6.0.10/24" to interface "eth0" in namespace "h1"
    And I add address "10.6.2.10/24" to interface "eth0" in namespace "h2"

    # Full neighborship on the upstream LAN.
    Then show command "show pim neighbor" in namespace "r0" should eventually contain "10.6.1.2"
    And show command "show pim neighbor" in namespace "r0" should eventually contain "10.6.1.3"

    # h2 joins (10.6.0.10, 232.6.6.6): both r1 and r2 track the
    # membership and join toward r0 — each overhears the other's Join
    # on swA and suppresses its own refresh.
    When I spawn "timeout 200 python3 tests/scripts/ssm_recv.py 232.6.6.6 10.6.0.10 10.6.2.10 5001 /tmp/pim_assert_rx" in namespace "h2"
    Then show command "show pim upstream" in namespace "r1" should eventually contain "Joined"
    And show command "show pim upstream" in namespace "r2" should eventually contain "Joined"
    And daemon log in namespace "r1" should eventually contain "join suppressed"
    And daemon log in namespace "r2" should eventually contain "join suppressed"

    # The sender starts: both forward onto swB, the duplicates
    # trigger the assert election, and the higher address (r2) wins.
    When I spawn "timeout 150 python3 tests/scripts/mcast_send.py 232.6.6.6 5001 10.6.0.10 120" in namespace "h1"
    Then daemon log in namespace "r1" should eventually contain "assert loser"
    And show command "show pim assert" in namespace "r1" should eventually contain "Loser"
    And show command "show pim assert" in namespace "r1" should contain "10.6.2.3"
    And show command "show pim assert" in namespace "r2" should eventually contain "Winner"

    # The loser's only outgoing interface is gone: it withdraws from
    # the source tree; r2 overhears the Prune and overrides it.
    And daemon log in namespace "r1" should eventually contain "pruned toward"
    And daemon log in namespace "r2" should eventually contain "prune override"

    # Steady state: r0 still forwards, r2 carries the LAN, h2 receives.
    And command "ip mroute show" in namespace "r0" should eventually contain "Iif: eth2"
    And command "cat /tmp/pim_assert_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_assert_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r0"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r0"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "swa"
    And I delete namespace "swb"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
