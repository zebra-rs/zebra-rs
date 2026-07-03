@serial
@ospfv2_graceful_restart
Feature: OSPFv2 graceful restart keeps forwarding through a daemon restart
  As a network operator
  I want zebra-rs to implement RFC 3623 graceful restart — the helper
  holding a restarting neighbor's adjacency past the dead interval, and
  the restarter checkpointing its LSDB, exiting, and resuming inside
  the grace window — so that a planned restart does not disturb
  forwarding.

  Two routers on a point-to-point link: a is the helper, b the
  restarter. The first scenario stages a restart and aborts it,
  proving the Grace-LSA drives helper entry on a. The second commits
  the restart: b's daemon exits, a holds the adjacency and the route
  well past the 40s dead interval, and b resumes from its checkpoint.

  Test Topology:
  ```
    a (helper, 10.0.0.1) -- 10.0.12.0/30 -- b (restarter, 10.0.0.2)

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
  ```

  The restarter's checkpoint lands at the fixed path
  /var/lib/zebra-rs/checkpoint/ospf.cbor, which is shared by every
  namespace (netns does not isolate the filesystem). The restarted
  daemon deletes it after a successful load, but each scenario also
  removes it defensively so an aborted run can never poison a later
  zebra-rs start (any OSPF instance started within 1.5x the grace
  period would replay it).

  Scenario: Grace-LSA from a staged restart drives helper entry; abort recovers
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    # First Hello (<=10s) + DBD exchange + SPF/route install.
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And show command "show ospf graceful-restart" in namespace "a" should contain "Helper enabled: true"

    # Stage (but do not commit) a restart on b: Grace-LSAs flood out
    # every OSPF interface and a enters helper mode for b.
    When I run "clear ospf graceful-restart begin" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospf graceful-restart" in namespace "b" should contain "Restart staged"
    And show command "show ospf graceful-restart" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf graceful-restart" in namespace "a" should contain "SoftwareRestart"
    # The held adjacency stays Full while helping.
    And show command "show ospf neighbor" in namespace "a" should contain "Full"

    # Abort: b flushes its Grace-LSAs and resumes normal operation.
    When I run "clear ospf graceful-restart abort" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospf graceful-restart" in namespace "b" should not contain "Restart staged"
    # Adjacency settles back to Full (the helper-exit path re-forms it
    # from scratch, like a dead-timer expiry, so allow a re-exchange).
    And show command "show ospf neighbor" in namespace "a" should eventually contain "Full"
    And ping from "a" to "10.0.0.2" should eventually succeed

    # Teardown.
    When I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Committed restart survives past the dead interval and resumes from the checkpoint
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf route" in namespace "a" should contain "10.0.0.2/32"
    And ping from "a" to "10.0.0.2" should succeed

    # Stage and commit: b floods Grace-LSAs (120s grace), writes the
    # checkpoint, drains 200ms, and exits the process. Forwarding
    # state is deliberately left in the kernel.
    When I run "clear ospf graceful-restart begin" in namespace "b"
    And I run "clear ospf graceful-restart commit" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospf graceful-restart" in namespace "a" should contain "10.0.0.2"

    # Hold b down well past a's 40s dead interval. Without helper mode
    # the inactivity timer would have killed the neighbor and withdrawn
    # the route; in helper mode both survive.
    When I wait 45 seconds
    Then show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf route" in namespace "a" should contain "10.0.0.2/32"

    # Restart b inside the grace window. The fresh daemon replays the
    # checkpoint (same router-id, LSDB at identical seq/checksum — so
    # a's snapshot check stays quiescent), deletes the file, re-forms
    # the adjacency, and re-originates at seq+1 once Full.
    When I start zebra-rs in namespace "b"
    And I apply config "b.yaml" to namespace "b"
    Then show command "show ospf neighbor" in namespace "b" should eventually contain "Full"
    And show command "show ospf neighbor" in namespace "a" should eventually contain "Full"
    # Eventually: SPF runs on a 1s coalescing timer after the
    # adjacency reaches Full, so the route install trails the
    # neighbor-state check by a beat.
    And show command "show ospf route" in namespace "a" should eventually contain "10.0.0.2/32"
    And ping from "a" to "10.0.0.2" should eventually succeed

    # Teardown.
    When I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
