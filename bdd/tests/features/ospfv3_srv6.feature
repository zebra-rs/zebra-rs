@ospfv3_srv6
Feature: OSPFv3 SRv6 locator origination (RFC 9513)
  As a network operator
  I want an OSPFv3 router configured with `segment-routing srv6
  locator <name>` to resolve the locator from the global registry,
  install its End/uN SID, and originate the SRv6 Locator LSA
  (function code 42) plus the SRv6 Capabilities TLV, so that SRv6
  state floods through the area exactly like the IS-IS sibling.

  Phase 2 of `docs/design/ospfv3-srv6-plan.md`: origination only —
  receive-side locator routes and TI-LFA SRv6 repairs are later
  phases, so reachability assertions stay out of scope here.

  Test Topology:
  ```
   z1 ──────────────── z2
   i2  2001:db8:12::/64  i1
   lo 2001:db8::1/128    lo 2001:db8::2/128
   LOC1 fcbb:bbbb:1::/48 (usid)   LOC2 2001:db8:f:2::/64 (classic)
  ```

  Scenario: Build the topology and confirm SRv6 LSA origination
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i2" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 30 seconds
    # Both routers originate the new LSA into their own LSDB...
    Then show command "show ospfv3 database" in namespace "z1" should contain "SRv6-Locator-LSA"
    # ...and area flooding carries it to the peer: z1's LSDB holds
    # z2's Locator LSA and vice versa (both advertising routers
    # appear, so the count is 2 — asserted via the detail dump
    # containing both locator prefixes).
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SRv6 Locator TLV: fcbb:bbbb:1::/48"
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SRv6 Locator TLV: 2001:db8:f:2::/64"
    And show command "show ospfv3 database detail" in namespace "z2" should contain "SRv6 Locator TLV: fcbb:bbbb:1::/48"
    # The End SID rides inside the Locator TLV with its structure:
    # uN (End with NEXT-CSID, codepoint 48) for z1's uSID locator,
    # classic End (codepoint 1) for z2's.
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SRv6 End SID Sub-TLV:"
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SID: fcbb:bbbb:1::"
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SID Structure: LB 32 LN 16 Fun 16 Arg 0"
    And show command "show ospfv3 database detail" in namespace "z2" should contain "SID Structure: LB 40 LN 24 Fun 16 Arg 0"
    # The SRv6 Capabilities TLV rides the SR-info E-Router-LSA.
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SRv6 Capabilities TLV"

  Scenario: The locator's End/uN SID is installed in the SID registry
    Given the test topology exists
    # z1's uSID locator carves a uN; z2's classic locator an End —
    # both owned by ospfv3 in the shared SID registry.
    Then show command "show segment-routing srv6 sid" in namespace "z1" should contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "ospfv3"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "fcbb:bbbb:1::"
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "End"
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "ospfv3"
    # And the kernel holds the seg6local install: uN is a prefix
    # (LB+LN = /48) route with the NEXT-CSID flavor, classic End an
    # exact /128.
    And kernel route "fcbb:bbbb:1::/48" in namespace "z1" should eventually contain "seg6local"
    And kernel route "2001:db8:f:2::" in namespace "z2" should eventually contain "seg6local"

  Scenario: Each Full adjacency carves an End.X SID with a global nexthop
    Given the test topology exists
    # z1's uSID locator carves a uA for the adjacency plus its LIB
    # twin (the block:function entry a NEXT-C-SID carrier hits after
    # the uN shift); z2's classic locator carves a plain End.X.
    Then show command "show segment-routing srv6 sid" in namespace "z1" should contain "uA"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "uA(LIB)"
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "End.X"
    # The End.X SID is advertised on the Router-Link TLV of the
    # per-link E-Router-LSA and floods to the peer.
    And show command "show ospfv3 database detail" in namespace "z2" should contain "SRv6 End.X SID Sub-TLV:"
    And show command "show ospfv3 database detail" in namespace "z1" should contain "SRv6 End.X SID Sub-TLV:"
    # The dedicated SRv6 show surfaces the locator, the End SID, and
    # the per-adjacency End.X table with the installed nexthop and
    # the LIB twin.
    And show command "show ospfv3 srv6" in namespace "z1" should contain "Locator: LOC1 (fcbb:bbbb:1::/48, usid)"
    And show command "show ospfv3 srv6" in namespace "z1" should contain "End SID: fcbb:bbbb:1:: (uN)"
    And show command "show ospfv3 srv6" in namespace "z1" should contain "Local SRv6 End.X SIDs:"
    And show command "show ospfv3 srv6" in namespace "z1" should contain "2001:db8:12::2"
    And show command "show ospfv3 srv6" in namespace "z1" should contain "fcbb:bbbb:e000::"
    And show command "show ospfv3 srv6" in namespace "z2" should contain "Locator: LOC2 (2001:db8:f:2::/64, classic)"
    And show command "show ospfv3 srv6" in namespace "z2" should contain "End SID: 2001:db8:f:2:: (End)"
    And show command "show ospfv3 srv6" in namespace "z2" should contain "End.X"
    # The kernel entries forward to the NEIGHBOR'S GLOBAL address —
    # learned from its Link-LSA LA-bit /128, upgraded from the
    # hello link-local once that LSA arrives. Linux's seg6local
    # End.X resolves nh6 by the packet's ingress interface, so a
    # link-local nexthop would blackhole (the #1361 lesson).
    And kernel route "fcbb:bbbb:1:e000::" in namespace "z1" should eventually contain "nh6 2001:db8:12::2"
    And kernel route "2001:db8:f:2:e000::" in namespace "z2" should eventually contain "nh6 2001:db8:12::1"
    # The uSID LIB twin installs as a block:function prefix with the
    # NEXT-CSID flavor.
    And kernel route "fcbb:bbbb:e000::/48" in namespace "z1" should eventually contain "flavors next-csid"

  Scenario: Remote locators are reachable via the SRv6 Locator LSA
    Given the test topology exists
    # Locator prefixes ride only the SRv6 Locator LSA — they are not
    # interface subnets and appear in no Intra-Area-Prefix-LSA — so
    # these routes prove the RFC 9513 §7 receive-side processing:
    # each router computes a route to the peer's locator through the
    # SPF cost to the advertising router.
    Then kernel route "2001:db8:f:2::/64" in namespace "z1" should eventually contain "proto ospf"
    And kernel route "fcbb:bbbb:1::/48" in namespace "z2" should eventually contain "proto ospf"
    And show command "show ospfv3 route" in namespace "z1" should contain "2001:db8:f:2::/64"
    And show command "show ospfv3 route" in namespace "z2" should contain "fcbb:bbbb:1::/48"

  Scenario: Removing the locator flushes the LSA and withdraws the SID
    Given the test topology exists
    When I apply command "delete router ospfv3 segment-routing srv6 locator LOC1" in namespace "z1"
    And I wait 10 seconds
    # z1 stops originating: its registry row and kernel route go, and
    # the flushed LSA disappears from the peer too (MaxAge flood).
    Then show command "show segment-routing srv6 sid" in namespace "z1" should not contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "z1" should not contain "uA"
    And show command "show ospfv3 srv6" in namespace "z1" should contain "Locator: (not configured)"
    And kernel route "fcbb:bbbb:1::/48" in namespace "z1" should eventually be gone
    And kernel route "fcbb:bbbb:1:e000::" in namespace "z1" should eventually be gone
    And show command "show ospfv3 database detail" in namespace "z2" should not contain "SRv6 Locator TLV: fcbb:bbbb:1::/48"
    And kernel route "fcbb:bbbb:1::/48" in namespace "z2" should eventually be gone
    # z2's own origination is untouched.
    And show command "show ospfv3 database detail" in namespace "z2" should contain "SRv6 Locator TLV: 2001:db8:f:2::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
