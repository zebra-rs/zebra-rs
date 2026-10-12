@ospf_gr_adj_sid
Feature: OSPF graceful restart keeps its Adjacency-SID labels held
  A graceful restart checkpoints the dynamic Adjacency-SID labels and puts
  them back, so each adjacency keeps its label across the restart
  (docs/design/mpls-label-allocation.md, phase 7). The restarted
  instance's pool must hold them again too. It did not: the labels came
  back with no pool holding them, so another instance over the same
  SRLB, here OSPFv3, which starts afresh after the restart, was handed
  OSPFv2's label, and both installed it.

  r1 and r2 run OSPFv2 and OSPFv3 over one dual-stack point-to-point
  link, both with SR-MPLS over the default SRLB (15000 and up). On r2,
  OSPFv2 comes up first and holds 15000; OSPFv3 then takes 15001. r2
  restarts OSPFv2 gracefully, which restarts the whole daemon, and comes
  back with both versions.

  Config files:
  - r1.yaml: OSPFv2 and OSPFv3 with SR-MPLS.
  - r2-v2.yaml: r2 with OSPFv2 only.
  - r2.yaml: r2 with both versions.

  Scenario: Before the restart OSPFv2 holds 15000 and OSPFv3 15001
    Given a clean test environment
    When I create namespace "r1"
    And I execute "rm -f /tmp/zebra-rs-ckpt/ospf_gr_adj_sid_r2/ospf.cbor" in namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2-v2.yaml" to namespace "r2"
    Then show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show mpls label table" in namespace "r2" should eventually contain "15000          ospf    local           held"
    When I apply config "r2.yaml" to namespace "r2"
    Then show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show mpls label table" in namespace "r2" should eventually contain "15001          ospfv3  local           held"

  Scenario: After the restart OSPFv2 holds 15000 again and OSPFv3 takes another
    Given the test topology exists
    When I run "clear ospf graceful-restart begin" in namespace "r2"
    And I run "clear ospf graceful-restart commit" in namespace "r2"
    And I wait 3 seconds
    And I start zebra-rs in namespace "r2"
    And I apply config "r2.yaml" to namespace "r2"
    Then daemon log in namespace "r2" should eventually contain "restored from checkpoint"
    And show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    # OSPFv2's restored label is held from the moment its pool exists, so
    # OSPFv3, coming Full after, is handed the next free one.
    And show command "show mpls label table" in namespace "r2" should eventually contain "15000          ospf    local           held"
    And show command "show mpls label table" in namespace "r2" should contain "15001          ospfv3  local           held"
    And daemon log in namespace "r2" should eventually contain "exit-restart success"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I execute "rm -f /tmp/zebra-rs-ckpt/ospf_gr_adj_sid_r2/ospf.cbor" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "r2"
