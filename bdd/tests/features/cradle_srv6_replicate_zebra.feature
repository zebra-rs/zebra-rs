@cradle_srv6_replicate_zebra
Feature: zebra-rs operator replication-segment programs the cradle End.Replicate datapath (RFC 9524)
  An operator `segment-routing replication-segment` declares a local SRv6
  End.Replicate SID and its downstream branches. zebra-rs registers the SID —
  which tees into the managed cradle engine's SRV6_LOCALSID, so the XDP stage
  hands matching frames to the TC replication path — and tees the branch set to
  cradle's REPL_SEG (SetReplSeg). This is the control-plane half of RFC 9524
  SR-P2MP replication; the datapath fan-out itself is proven by the cradle-rs
  `cradle_srv6_replicate` BDD.

  Prerequisite: /usr/bin/cradle (the cradle-rs engine binary) with the
  SetReplSeg RPC. Install from a cradle-rs checkout: `cargo build --release`
  then `install -m755 target/release/cradle /usr/bin/cradle`.

  Topology:
  ```
   crs1 [ zebra-rs + managed cradle, eth0 ebpf port ] ─ eth0 ── eth0 ─ crs2
        segment-routing replication-segment TREE1
          sid fd00:b::5  (End.Replicate)
          branch fd00:1::100, fd00:2::100
  ```

  Scenario: A replication-segment registers an End.Replicate SID and tees its branches
    Given a clean test environment
    When I create namespace "crs1"
    And I create namespace "crs2"
    And I connect namespace "crs1" interface "eth0" to namespace "crs2" interface "eth0"
    And I add address "10.211.1.1/24" to interface "eth0" in namespace "crs1"
    And I add address "10.211.1.2/24" to interface "eth0" in namespace "crs2"
    And I start zebra-rs in namespace "crs1"
    And I apply config "crs1.yaml" to namespace "crs1"
    # The managed cradle engine is up.
    Then show command "show ebpf" in namespace "crs1" should eventually contain "managed"
    # The End.Replicate SID reached cradle's local-SID table (the tee is live).
    And show command "show ebpf srv6" in namespace "crs1" should eventually contain "End.Replicate"
    And show command "show ebpf srv6" in namespace "crs1" should eventually contain "fd00:b::5"
    # zebra teed the two downstream branches to cradle's REPL_SEG.
    And daemon log in namespace "crs1" should eventually contain "repl seg TREE1"
    And daemon log in namespace "crs1" should eventually contain "2 branch(es) teed to cradle"

  Scenario: Deleting the replication-segment withdraws the End.Replicate SID
    Given the test topology exists
    When I apply command "delete segment-routing replication-segment TREE1" in namespace "crs1"
    Then show command "show ebpf srv6" in namespace "crs1" should eventually not contain "End.Replicate"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "crs1"
    And I delete namespace "crs1"
    And I delete namespace "crs2"
    Then the test environment should be clean
