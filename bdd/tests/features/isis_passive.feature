@isis_passive
@isis
Feature: IS-IS passive interfaces and the self-sourced-Hello guard
  As a network operator
  I want IS-IS to advertise a loopback / stub prefix without running the
  Hello protocol on it, and I never want a router to form an adjacency with
  itself when its own Hellos loop back to it.

  Two independent guarantees are exercised here:

  1. A loopback is implicitly passive, and an explicitly `passive` interface
     advertises its prefixes into the LSP but sends/processes no Hello PDUs —
     so no adjacency forms over it, while its subnet is still reachable from
     the rest of the network.

  2. The self-sourced-IIH guard: if an IIH arrives carrying this router's own
     system-id (a loopback reflecting its own Hello, an L2 loop, or a
     duplicate system-id), it is dropped before the neighbor table is
     touched, so the router never peers with itself.

  Test Topology:
  ```
        z3 (IS-IS active, but ISOLATED — z1's side of the link is passive)
        │
        │ z3:i1 ── 10.0.13.2/30
        │ z1:i3 ── 10.0.13.1/30   (PASSIVE on z1)
        │
   z2 ══════════════ z1                 z4
   i1   10.0.12.0/30  i2           sa ─┐  (sa<->sb are one veth pair
   .2                 .1           sb ─┘   inside z4: a self-loop)

    loopbacks: zI -> 10.0.0.I/32  and  2001:db8::I/128
  ```

  z1–z2 is an ordinary point-to-point Level-2 backbone link and forms an
  adjacency. z1–z3 has z1 configured `passive`, so even though z3 runs IS-IS
  actively it never hears a Hello and z3 stays isolated; z1 still advertises
  10.0.13.0/30 so z2 can reach it. z4 is wired to itself (sa and sb are the
  two ends of one veth pair in the same namespace) to force its own Hellos
  back at it, exercising the self-sourced-IIH guard. Every router also runs
  IS-IS on its loopback (network-type defaults to LAN, the configuration that
  used to make a router peer with itself over `lo`).

  All routers are level-2-only.

  Scenario: Build the topology — a real adjacency forms, no router self-peers
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "z4"
    And I connect namespace "z1" interface "i2" to namespace "z2" interface "i1"
    And I connect namespace "z1" interface "i3" to namespace "z3" interface "i1"
    And I connect namespace "z4" interface "sa" to namespace "z4" interface "sb"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 25 seconds
    # The ordinary z1–z2 backbone adjacency comes up at Level-2.
    Then isis neighbor in namespace "z1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "z2" at level 2 on interface "i1" should be up
    And show command "show isis neighbor" in namespace "z1" should contain "z2"
    And show command "show isis neighbor" in namespace "z2" should contain "z1"
    # But neither router forms an adjacency with ITSELF over its loopback.
    # Before the fix, an IS-IS-enabled loopback echoes its own LAN Hellos
    # back and the router peers with itself — its own hostname would appear
    # in its own neighbor table.
    And show command "show isis neighbor" in namespace "z1" should not contain "z1"
    And show command "show isis neighbor" in namespace "z2" should not contain "z2"
    # The loopback prefix is still advertised despite no adjacency on lo, so
    # the two loopbacks reach each other.
    And ping from "z1" to "10.0.0.2" should succeed
    And ping from "z2" to "10.0.0.1" should succeed

  Scenario: A passive interface forms no adjacency but still advertises its prefix
    Given the test topology exists
    # z1's i3 toward z3 is `passive`: z1 sends no Hellos there, so even
    # though z3 runs IS-IS actively no adjacency forms in either direction
    # and z3 stays isolated (it never receives a Hello to peer with).
    Then isis neighbor in namespace "z1" at level 2 on interface "i3" should not be up
    And show command "show isis neighbor" in namespace "z1" should not contain "z3"
    And show command "show isis neighbor" in namespace "z3" should not contain "z1"
    # z3 is isolated: its loopback never reaches the backbone.
    And ping from "z2" to "10.0.0.3" should fail
    # But the passive interface's own subnet IS advertised by z1 into the L2
    # LSP (prefix advertisement does not depend on an adjacency). z3 is the
    # only other router on that subnet and it is isolated, so the only way
    # z2 can reach z1's address on it is via z1's passive advertisement.
    And ping from "z2" to "10.0.13.1" should succeed

  Scenario: A self-looped circuit never peers with itself (self-sourced-IIH guard)
    Given the test topology exists
    # z4's sa and sb are the two ends of one veth pair inside z4, so every
    # Hello z4 sends out one end arrives on the other carrying z4's OWN
    # system-id. The guard drops those before the neighbor table is touched,
    # so z4 never forms an adjacency with itself — its hostname must not
    # appear in its own neighbor table.
    Then show command "show isis neighbor" in namespace "z4" should not contain "z4"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    Then the test environment should be clean
