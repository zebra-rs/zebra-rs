@isis_p2p_allis
@isis
Feature: IS-IS point-to-point circuits send LSPs, CSNPs and PSNPs to AllISs
  As a network operator
  I want zebra-rs to send every IS-IS PDU on a point-to-point circuit to
  the AllISs group MAC 09:00:2b:00:00:05, as RFC 5309 recommends and FRR
  does, so that a hardware NOS on the far end, which only traps IS-IS
  frames addressed to a group MAC, receives my LSPs and SNPs as well as
  my Hellos.

  zebra-rs used to send P2P Hellos to AllISs but unicast the LSPs, CSNPs
  and PSNPs to the neighbour's MAC. That works against a Linux peer but
  not against a peer whose forwarding plane drops unicast IS-IS frames.
  The adjacency still comes up on the multicast Hellos, but the peer
  never learns our routes and keeps retransmitting its own LSPs, because
  our PSNP acknowledgements never reach it either.

  Test Topology:
  ```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
  ```

  Both routers are level-2-only with network-type point-to-point on the
  shared link and 1 s Hellos.

  Scenario: LSPs, CSNPs and PSNPs on a point-to-point circuit leave on AllISs
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I connect namespace "a1" interface "i2" to namespace "a2" interface "i1"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    # Capture from before the adjacency forms: the LSP exchange and its
    # PSNP acknowledgements happen once, at adjacency Up.
    And I start capturing IS-IS frames sent on interface "i2" in namespace "a1"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    Then isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And IS-IS LSPs, CSNPs and PSNPs sent on interface "i2" in namespace "a1" should all be addressed to AllISs

  Scenario: A peer that drops unicast IS-IS frames still learns our routes
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I connect namespace "a1" interface "i2" to namespace "a2" interface "i1"
    # Both ends model a hardware NOS: IS-IS frames reach the peer's IS-IS
    # only when addressed to a group MAC. Hellos pass either way, so the
    # adjacency forms even without the fix; the routes show whether the
    # LSPs and SNPs got through.
    And I drop unicast IS-IS frames leaving interface "i2" in namespace "a1"
    And I drop unicast IS-IS frames leaving interface "i1" in namespace "a2"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    Then isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.2/32"
    And ping from "a2" to "10.0.0.1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I delete namespace "a1"
    And I delete namespace "a2"
    Then the test environment should be clean
