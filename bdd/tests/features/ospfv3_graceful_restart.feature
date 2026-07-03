@serial
@ospfv3_graceful_restart
Feature: OSPFv3 graceful restart keeps forwarding through a daemon restart
  As a network operator
  I want zebra-rs OSPFv3 to implement RFC 5187 graceful restart in
  both roles — the helper holding a restarting neighbor's adjacency
  past the dead interval, and the restarter checkpointing its LSDB,
  exiting, and resuming inside the grace window — mirroring
  ospfv2_graceful_restart over the v3 Grace-LSA (0x000B).

  Test Topology (v6 mirror of ospfv2_graceful_restart):
  ```
    a (helper, 10.0.0.1) -- 2001:db8:12::/64 -- b (restarter, 10.0.0.2)
  ```

  The restarter's checkpoint lands at the fixed path
  /var/lib/zebra-rs/checkpoint/ospfv3.cbor, shared by every namespace
  (netns does not isolate the filesystem); each scenario removes it
  defensively so an aborted run can never poison a later start.

  Scenario: Grace-LSA from a staged restart drives helper entry; abort recovers
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospfv3.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "b" should contain "Full"
    And show command "show ospfv3 graceful-restart" in namespace "a" should contain "Helper enabled: true"

    When I run "clear ospfv3 graceful-restart begin" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospfv3 graceful-restart" in namespace "b" should contain "Restart staged"
    And show command "show ospfv3 graceful-restart" in namespace "a" should contain "10.0.0.2"
    And show command "show ospfv3 graceful-restart" in namespace "a" should contain "SoftwareRestart"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "Full"

    When I run "clear ospfv3 graceful-restart abort" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospfv3 graceful-restart" in namespace "b" should not contain "Restart staged"
    And show command "show ospfv3 neighbor" in namespace "a" should eventually contain "Full"
    And ping from "a" to "2001:db8::2" should eventually succeed

    # Teardown.
    When I execute "rm -f /var/lib/zebra-rs/checkpoint/ospfv3.cbor" in namespace "a"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Committed restart survives past the dead interval and resumes from the checkpoint
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I execute "rm -f /var/lib/zebra-rs/checkpoint/ospfv3.cbor" in namespace "a"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8::2/128"
    And ping from "a" to "2001:db8::2" should succeed

    # Stage and commit: b floods v3 Grace-LSAs (120s grace), writes
    # the checkpoint, drains 200ms, and exits. Kernel routes stay.
    When I run "clear ospfv3 graceful-restart begin" in namespace "b"
    And I run "clear ospfv3 graceful-restart commit" in namespace "b"
    And I wait 3 seconds
    Then show command "show ospfv3 graceful-restart" in namespace "a" should contain "10.0.0.2"

    # Hold b down well past a's 40s dead interval: helper mode keeps
    # the neighbor and the route alive.
    When I wait 45 seconds
    Then show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8::2/128"

    # Restart b inside the grace window: the fresh daemon replays the
    # checkpoint, re-forms the adjacency, and re-originates at seq+1.
    When I start zebra-rs in namespace "b"
    And I apply config "b.yaml" to namespace "b"
    Then show command "show ospfv3 neighbor" in namespace "b" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should eventually contain "Full"
    And show command "show ospfv3 route" in namespace "a" should eventually contain "2001:db8::2/128"
    And ping from "a" to "2001:db8::2" should eventually succeed

    # Teardown.
    When I execute "rm -f /var/lib/zebra-rs/checkpoint/ospfv3.cbor" in namespace "a"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
