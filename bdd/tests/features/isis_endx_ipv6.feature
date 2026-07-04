@isis_endx_ipv6
@isis
Feature: IS-IS SRv6 End.X (adjacency) SID is gated on the neighbor's IPv6
  As a network operator
  I want an SRv6 End.X adjacency SID to be allocated only for a neighbor that
  can actually forward IPv6 — one that advertises the IPv6 NLPID in its
  Protocols Supported TLV AND gives us an IPv6 link-local nexthop — and I want
  that decision re-evaluated as the neighbor's capability changes, so enabling
  IPv6 on an already-Up adjacency starts advertising an End.X without a flap.

  Test Topology:
  ```
   x1 ───────────────── x2
   i2  10.0.12.0/30      i1
       2001:db8:12::/64
   lo 10.0.0.1/32        lo 10.0.0.2/32
   SRv6 locator LX1
   (fcbb:1::/64)
  ```

  x1 runs SRv6 with a classic locator, so it owns an End SID and would carve
  an End.X for each IPv6-capable adjacency. The x1–x2 IS-IS circuit starts
  IPv4-only (IS-IS `ipv4 enabled` only), so x2 advertises no IPv6 and x1 must
  NOT allocate an End.X for it. A later scenario enables IPv6 on the circuit;
  x2 then advertises IPv6 and x1 allocates the End.X by re-evaluation.

  This also pins the `show segment-routing srv6 sid` column rename: the owner
  column is "Protocol" and the value is "isis" (no instance suffix).

  Scenario: Build the topology — an IPv4-only neighbor gets no End.X SID
    Given a clean test environment
    When I create namespace "x1"
    And I create namespace "x2"
    And I connect namespace "x1" interface "i2" to namespace "x2" interface "i1"
    And I start zebra-rs in namespace "x1"
    And I start zebra-rs in namespace "x2"
    And I apply config "x1.conf" to namespace "x1"
    And I apply config "x2.conf" to namespace "x2"
    And I wait 35 seconds
    Then isis neighbor in namespace "x1" at level 2 on interface "i2" should be up
    # x1's SRv6 is up: its locator End SID is present in the registry.
    And show command "show segment-routing srv6 sid" in namespace "x1" should contain "End"
    # The column rename: header is "Protocol" and the owner renders as plain
    # "isis", not "isis(0)" (no protocol-instance support).
    And show command "show segment-routing srv6 sid" in namespace "x1" should contain "Protocol"
    And show command "show segment-routing srv6 sid" in namespace "x1" should contain "isis"
    And show command "show segment-routing srv6 sid" in namespace "x1" should not contain "isis(0)"
    # x2 is IPv4-only on this circuit, so no End.X (adjacency) SID is carved.
    And show command "show segment-routing srv6 sid" in namespace "x1" should not contain "End.X"
    # And nothing is advertised: x2's LSDB sees no End.X in x1's LSP.
    And show command "show isis database detail" in namespace "x2" should not contain "SRv6 End.X SID"

  Scenario: Enabling IPv6 on the neighbor re-evaluates and allocates the End.X SID
    Given the test topology exists
    # Turn IPv6 on for the IS-IS circuit at both ends. The diff-based apply
    # adds `ipv6 enabled true`; the adjacency stays Up. x2 now advertises the
    # IPv6 NLPID and an IPv6 link-local, so x1 re-evaluates this neighbor,
    # allocates an End.X SID, and re-originates its LSP.
    When I apply config "x1-v6.conf" to namespace "x1"
    And I apply config "x2-v6.conf" to namespace "x2"
    And I wait 20 seconds
    Then show command "show segment-routing srv6 sid" in namespace "x1" should contain "End.X"
    # The LSP was re-originated (no flap), so x2 now learns the End.X SID
    # in x1's LSP — proving the change is advertised, not just allocated.
    And show command "show isis database detail" in namespace "x2" should contain "SRv6 End.X SID"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "x1"
    And I stop zebra-rs in namespace "x2"
    And I delete namespace "x1"
    And I delete namespace "x2"
    Then the test environment should be clean
