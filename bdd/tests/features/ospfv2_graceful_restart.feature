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

    # Abort: b flushes its Grace-LSAs and resumes normal operation. The
    # flushed Grace-LSA ends a's help (RFC 3623 §3.2), and the adjacency
    # stays: a helper that never left helper mode used to keep b listed
    # here for good.
    When I run "clear ospf graceful-restart abort" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospf graceful-restart" in namespace "b" should not contain "Restart staged"
    And show command "show ospf graceful-restart" in namespace "a" should eventually contain "(no active helpers)"
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
    # The restart is over, and a has left helper mode. b ended it itself,
    # once each adjacency the checkpoint recorded was Full again, not by
    # running out its grace period.
    And show command "show ospf graceful-restart" in namespace "a" should eventually contain "(no active helpers)"
    And daemon log in namespace "b" should eventually contain "exit-restart success"
    # The restarted daemon found the next-hop objects its predecessor left
    # in the kernel, which its routes still forward through, and kept
    # their ids for them.
    And daemon log in namespace "b" should eventually contain "of an earlier run found"

  Scenario: A route withdrawn while the restarter is down is swept when its restart ends
    # RFC 3623 §2.3 (4): the forwarding entries installed before the
    # restart that are no longer valid are removed when it ends. b goes
    # down for a graceful restart, leaving its routes in the kernel; a
    # withdraws 10.0.1.1/32 meanwhile. The restarted b replaces the routes it
    # still has with its own and sweeps the rest.
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I execute "ip addr add 10.0.1.1/32 dev lo" in namespace "a"
    Then show command "show ospf neighbor" in namespace "b" should eventually contain "Full"
    And kernel route "10.0.1.1/32" in namespace "b" should eventually contain "proto ospf"
    And kernel route "10.0.0.1/32" in namespace "b" should eventually contain "proto ospf"

    When I run "clear ospf graceful-restart begin" in namespace "b"
    And I run "clear ospf graceful-restart commit" in namespace "b"
    And I wait 3 seconds
    Then kernel route "10.0.1.1/32" in namespace "b" should eventually contain "proto ospf"
    When I execute "ip addr del 10.0.1.1/32 dev lo" in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "b.yaml" to namespace "b"
    # a's withdrawal is a topology change that ends its help (§3.2). Its
    # Router-LSA then lists no link back to b until they are adjacent
    # again, and b, receiving it, ends its restart as inconsistent (§2.2
    # (2)) unless the adjacency came back first. The restart ends either
    # way, and its end does the sweep.
    Then daemon log in namespace "b" should eventually contain "LSAs re-originated at seq+1"
    And kernel route "10.0.1.1/32" in namespace "b" should eventually be gone
    And kernel route "10.0.0.1/32" in namespace "b" should eventually contain "proto ospf"

  Scenario: After a crash, the routes an earlier run left are swept at start
    # A crash (SIGKILL) leaves b's routes in the kernel too. With no
    # restart to wait for, b sweeps them at start; those still valid come
    # back once OSPF has converged.
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I execute "ip addr add 10.0.1.1/32 dev lo" in namespace "a"
    Then show command "show ospf neighbor" in namespace "b" should eventually contain "Full"
    And kernel route "10.0.1.1/32" in namespace "b" should eventually contain "proto ospf"
    And kernel route "10.0.0.1/32" in namespace "b" should eventually contain "proto ospf"

    When I stop zebra-rs in namespace "b"
    Then kernel route "10.0.1.1/32" in namespace "b" should eventually contain "proto ospf"
    When I execute "ip addr del 10.0.1.1/32 dev lo" in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "b.yaml" to namespace "b"
    Then kernel route "10.0.1.1/32" in namespace "b" should eventually be gone
    And show command "show ospf neighbor" in namespace "b" should eventually contain "Full"
    And kernel route "10.0.0.1/32" in namespace "b" should eventually contain "proto ospf"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only). The
    # checkpoint removal belongs here too: a leftover ospf.cbor is exactly
    # what a failed GR scenario would strand.
    When I execute "rm -f /var/lib/zebra-rs/checkpoint/ospf.cbor" in namespace "a"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
