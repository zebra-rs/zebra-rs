@isis_afi_enable
@isis
Feature: IS-IS re-originates its LSP when an interface address-family is toggled
  As a network operator
  I want enabling (or disabling) an address-family on an IS-IS interface to
  immediately update the self-originated LSP, so a newly-enabled prefix is
  advertised without waiting for the periodic LSP refresh.

  Regression: enabling IPv6 on a loopback that already had IPv4 enabled used
  to leave the loopback's IPv6 prefix out of the LSP, because re-origination
  only fired on a 0<->non-zero *global* protocols-supported (NLPID)
  transition — and the global IPv6 count was already non-zero thanks to the
  dual-stack backbone link. The fix re-originates on any per-interface AFI
  flip.

  Test Topology:
  ```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
       2001:db8:12::/64
   lo 10.0.0.1/32      lo 10.0.0.2/32
      2001:db8::1/128     2001:db8::2/128
  ```

  Both routers are level-2-only and the a1–a2 link is dual-stack, so the
  global IPv6 interface count on a1 is already non-zero. a1's loopback starts
  with **only IPv4** enabled in IS-IS; its IPv6 address exists on the kernel
  interface but is not advertised. A later scenario enables IPv6 on a1's
  loopback at runtime and proves a2 then learns 2001:db8::1/128.

  Scenario: Build the topology — the IPv4 loopback is advertised, the IPv6 loopback is not
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I connect namespace "a1" interface "i2" to namespace "a2" interface "i1"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    And I wait 25 seconds
    Then isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    # a1's loopback has IPv4 enabled, so a2 learns 10.0.0.1/32 and can reach it.
    And show command "show ipv6 route" in namespace "a2" should not contain "2001:db8::1/128"
    And ping from "a2" to "10.0.0.1" should succeed
    # a1's loopback IPv6 is NOT enabled in IS-IS yet, so its /128 is absent
    # from a2's IPv6 table and unreachable (the link's 2001:db8:12::/64 is
    # still reachable — that interface has IPv6 enabled).
    And ping from "a2" to "2001:db8::1" should fail
    And ping from "a2" to "2001:db8:12::1" should succeed

  Scenario: Enabling IPv6 on the loopback re-originates the LSP and advertises the prefix
    Given the test topology exists
    # Re-apply a1's config with one line added: `ipv6 enable true` on lo. The
    # diff-based apply turns that single leaf on. With the fix, a1 immediately
    # re-originates its L2 LSP carrying 2001:db8::1/128 in the IPv6
    # Reachability TLV; a2 floods it in, runs SPF, and installs the route.
    When I apply config "a1-lo-v6.yaml" to namespace "a1"
    And I wait 10 seconds
    Then show command "show ipv6 route" in namespace "a2" should contain "2001:db8::1/128"
    And ping from "a2" to "2001:db8::1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I delete namespace "a1"
    And I delete namespace "a2"
    Then the test environment should be clean
