@ospfv3_srv6_flavor_kernel
Feature: A flavored SRv6 locator keeps its SIDs in the kernel
  As a network operator
  I want the End and End.X SIDs of a locator with RFC 8986 §4.16 flavors
  to stay installed in the kernel when the kernel does not perform a
  flavor, so that segment lists passing through those SIDs keep working.

  The kernel performs PSP on End and no flavor on End.X; USP and USD it
  performs nowhere. It refuses the whole route for a flavor it does not
  perform. zebra-rs used to stop there, so `flavor usd` removed the End
  SID from the kernel and `flavor psp` every End.X SID. It now offers
  the kernel the configured flavors, then PSP alone, then none.

  z2's locator carries `flavor: [psp, usd]`. The advertisement keeps
  both (End with PSP & USD, codepoint 29). In the kernel the End SID
  lands without USD and the End.X SIDs plain, and a two-segment list
  from z1 through z2's End SID reaches z3.

  Test Topology:
  ```
   z1 ───────────────── z2 ───────────────── z3 ─────────────── h3
      2001:db8:12::/64     2001:db8:23::/64     2001:db8:300::/64
   LOC1 fcbb:bbbb:1::/48   LOC2 fcbb:bbbb:2::/48   LOC3 fcbb:bbbb:3::/48
                           flavor [psp, usd]       End.DT6 fcbb:bbbb:3:e064::
  ```
  h3 is a host, 2001:db8:300::100; z3-h3 is not in OSPFv3.

  Scenario: The flavored SIDs are in the kernel
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
    # What z2 advertises does not change: End with PSP & USD is 29, and
    # only z2 can be its origin (z1 and z3 advertise 1, plain End).
    Then show command "show ospfv3 database detail" in namespace "z1" should eventually contain "Endpoint Behavior: 29"
    # The End SID is in the kernel although the kernel refuses USD.
    And kernel route "fcbb:bbbb:2::" in namespace "z2" should eventually contain "seg6local action End"
    # One End.X SID per adjacency, although the kernel refuses PSP there.
    And kernel route "fcbb:bbbb:2:e000::" in namespace "z2" should eventually contain "seg6local action End.X"
    And kernel route "fcbb:bbbb:2:e001::" in namespace "z2" should eventually contain "seg6local action End.X"
    # The operator is told which flavor the kernel left out.
    And daemon log in namespace "z2" should eventually contain "kernel refuses SRv6 flavor usd for End SID fcbb:bbbb:2::"

  Scenario: The show commands print the flavors
    Given the test topology exists
    # The route line prints the SID as it is advertised, then what the
    # kernel holds, since the kernel left USD out (and, on the End.X
    # SIDs, PSP).
    Then show command "show ipv6 route" in namespace "z2" should eventually contain "seg6local End (PSP, USD) [kernel: End"
    And show command "show ipv6 route" in namespace "z2" should eventually contain "seg6local End.X (PSP) [kernel: End.X] nh6"
    # The SID registry and the OSPFv3 view print the flavors too.
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "End (PSP, USD)"
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "End.X (PSP)"
    And show command "show ospfv3 srv6" in namespace "z2" should contain "End SID: fcbb:bbbb:2:: (End (PSP, USD))"
    And show command "show ospfv3 srv6" in namespace "z2" should contain "End.X (PSP)"
    # A locator without flavors prints as before.
    And show command "show ipv6 route" in namespace "z1" should contain "seg6local End, "
    And show command "show ospfv3 srv6" in namespace "z1" should contain "End SID: fcbb:bbbb:1:: (End)"

  Scenario: A segment list passes through the flavored End SID
    Given the test topology exists
    # 2001:db8:300::/64 is known to z1 only by this route: first z2's
    # End SID, a transit segment, then z3's End.DT6 SID. It is a kernel
    # route so that the scenario tests z2 and nothing of z1's own
    # segment-list encoding. The target is the host, not z3's own
    # address: End.DT6 looks the inner packet up in the main table,
    # which holds no local addresses.
    When I execute "ip -6 route add 2001:db8:300::/64 encap seg6 mode encap segs fcbb:bbbb:2::,fcbb:bbbb:3:e064:: dev z1-z2" in namespace "z1"
    Then kernel route "2001:db8:300::/64" in namespace "z1" should eventually contain "segs 2 [ fcbb:bbbb:2:: fcbb:bbbb:3:e064:: ]"
    And ping from "z1" to "2001:db8:300::100" should eventually succeed

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
