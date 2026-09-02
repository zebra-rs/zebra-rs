@stamp_v6_dad_retry
@isis
Feature: STAMP session creation survives a tentative IPv6 link-local
  As a network operator measuring IPv6-only links with STAMP, I want a
  session whose sender socket could not be created at adjacency-up
  time to be retried, so a link-local that is still tentative under
  Duplicate Address Detection when IS-IS comes up does not leave the
  link unmeasured for the life of the adjacency.

  The v6 link-local STAMP session is keyed from the local and remote
  link-locals the moment the IS-IS neighbor reaches Up. IS-IS runs
  over L2, so the adjacency can form while the kernel is still running
  DAD on the local link-local; binding the sender socket to a tentative
  address fails with EADDRNOTAVAIL. The IGP never re-subscribes on its
  own (its key is stable while the neighbor stays Up), so STAMP itself
  must park the failed creation and retry it.

  Seen live in a c=16 full run of @stamp_v6_te_metric: st1 logged
  "cannot create session ... Cannot assign requested address" at the
  instant st2 created its side, and st1 never had a session.

  Topology (same as @stamp_v6_te_metric):

    st1                                    st2
      st1-st2  2001:db8:61::1/64 ---- 2001:db8:61::2/64  st2-st1
      lo 2001:db8:0:ff61::1/128            lo 2001:db8:0:ff61::2/128

  Config files: st1.yaml  st2.yaml

  Scenario: Build the topology with a slow DAD on st1's link
    Given a clean test environment
    When I create namespace "st1"
    And I create namespace "st2"
    And I connect namespace "st1" interface "st1-st2" to namespace "st2" interface "st2-st1"
    # Keep st1's link-local tentative for ~8 s: raise dad_transmits and
    # bounce the link so DAD restarts under the new count. The daemons
    # start and the IS-IS adjacency forms well inside that window.
    And I execute "sysctl -w net.ipv6.conf.st1-st2.dad_transmits=8" in namespace "st1"
    And I execute "ip link set st1-st2 down" in namespace "st1"
    And I execute "ip link set st1-st2 up" in namespace "st1"
    And I start zebra-rs in namespace "st1"
    And I start zebra-rs in namespace "st2"
    And I apply config "st1.yaml" to namespace "st1"
    And I apply config "st2.yaml" to namespace "st2"
    Then isis neighbor in namespace "st1" at level 2 on interface "st1-st2" should be up

  Scenario: The first creation fails on the tentative address and is retried
    Given the test topology exists
    # Proof the failure path ran: the sender bind hit the tentative
    # link-local (without this line a fast DAD would let the scenario
    # pass without exercising the retry).
    Then daemon log in namespace "st1" should eventually contain "cannot create session"
    # ...and the retry brought the session up once DAD completed.
    And daemon log in namespace "st1" should eventually contain "session created on retry"
    And show command "show stamp" in namespace "st1" should eventually contain "fe80:"
    And show command "show stamp" in namespace "st1" should eventually contain "Active"
    And show command "show stamp" in namespace "st2" should eventually contain "fe80:"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "st1"
    And I stop zebra-rs in namespace "st2"
    And I delete namespace "st1"
    And I delete namespace "st2"
    Then the test environment should be clean
