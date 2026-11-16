@static_srv6_segment_order
Feature: A static SRv6 segment list is visited in the order it is written
  As a network operator
  I want `segments <s1> <s2> ...` on a static route to send the packet to
  s1 first, then s2, as `ip -6 route add ... encap seg6 ... segs s1,s2`
  does, so that the list I configure is the path the packet takes.

  The kernel takes the SRH as it goes on the wire, where the list is
  stored backwards and the outer destination is read from the top index.
  zebra-rs wrote the list in forwarding order, so a list of two or more
  segments was visited last segment first, and `encap-type H.Encap.Red`
  dropped the first segment altogether. A single segment reads the same
  both ways, so one-segment routes always worked.

  z1 cannot reach z3's SIDs by itself (a static blackhole covers z3's
  locator), so every list below delivers only if the packet is sent to
  z2's SID, the first segment, first.

  Test Topology:
  ```
   z1 ───────────────── z2 ───────────────── z3 ─────────────── h3
      2001:db8:12::/64     2001:db8:23::/64     2001:db8:300::/64
   LOC1 fcbb:bbbb:1::/48   LOC2 fcbb:bbbb:2::/48   LOC3 fcbb:bbbb:3::/48
   blackhole fcbb:bbbb:3::/48                      End.DT6 fcbb:bbbb:3:e064::
  ```
  h3 is a host with 2001:db8:300::100, ::101 and ::102, one per list.

  Scenario: The kernel holds each list in the order written
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "h3"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I connect namespace "z2" interface "z2-z3" to namespace "z3" interface "z3-z2"
    And I connect namespace "z3" interface "z3-h3" to namespace "h3" interface "h3-z3"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "h3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "h3.yaml" to namespace "h3"
    # iproute2 prints a segment list in the order the packet visits it.
    # H.Encap: both segments, z2's first.
    Then kernel route "2001:db8:300::100" in namespace "z1" should eventually contain "mode encap segs 2 [ fcbb:bbbb:2:: fcbb:bbbb:3:e064:: ]"
    # H.Encap.Red: the kernel's own reduced mode, given the whole list.
    And kernel route "2001:db8:300::101" in namespace "z1" should eventually contain "mode encap.red segs 2 [ fcbb:bbbb:2:: fcbb:bbbb:3:e064:: ]"
    # Three segments keep their order too.
    And kernel route "2001:db8:300::102" in namespace "z1" should eventually contain "segs 3 [ fcbb:bbbb:2:: fcbb:bbbb:3:: fcbb:bbbb:3:e064:: ]"
    # zebra-rs shows the same order it installed.
    And show command "show ipv6 route" in namespace "z1" should eventually contain "via seg6 [fcbb:bbbb:2::, fcbb:bbbb:3:e064::]"
    # The cut that makes the pings below depend on the order.
    And kernel route "fcbb:bbbb:3::/48" in namespace "z1" should eventually contain "blackhole"

  Scenario: Each list delivers through its first segment
    Given the test topology exists
    Then ping from "z1" to "2001:db8:300::100" should eventually succeed
    And ping from "z1" to "2001:db8:300::101" should eventually succeed
    And ping from "z1" to "2001:db8:300::102" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "h3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "h3"
    Then the test environment should be clean
