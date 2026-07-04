@serial
@bgp_mup_dynamic_rt
Feature: BGP MUP export route-target applies dynamically to an originated ST route
  As a network operator
  I want a `set vrf <name> mup route-target export <rt>` change to take
  effect on an already-originated controller Session-Transformed route,
  re-stamping it with the new route-target and re-advertising it — without
  re-establishing the PFCP session. The export RTs are read from the VRF
  table at session-establish time, so a route originated before the RT is
  configured (or before a later export-RT commit) must be re-tagged in
  place. This regressed: the export-RT change refreshed only the DSD/ISD
  segment routes, never the controller's ST1/ST2 routes, so the new RT
  never reached the route or the peer.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ MUP-C   │ iBGP│ receiver│
           │192.168. │◄───►│192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴──────┐
           │ pfcp-inject│  (SMF simulator, run in z1)
           └───────────┘
  ```

  z1 runs the controller (PFCP listener on 192.168.0.1:8805, VRF
  `mobile-up` binding Network Instance `core` to a Type-2 ST route with the
  Direct segment id `1:2`). The top-level `vrf mobile-up` starts with NO
  `mup route-target export`. z2 imports MUP route-target 100:10. The
  feature injects a session (z1 originates the ST2 with no RT), then applies
  `set vrf mobile-up mup route-target export 100:10` at runtime and checks
  the ST2 is re-stamped on z1 and the re-advertised route reaches z2's
  per-VRF view (which only imports 100:10).

  NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
  binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
  `cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
  to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

  Scenario: Setup topology and establish iBGP session with MUP capability
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp mup-c" in namespace "z1" should contain "PFCP listen : 192.168.0.1:8805"

  Scenario: Originate an ST2 with no export RT, then apply the export RT dynamically
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --core-endpoint 10.0.0.1 --core-teid 0x12345678 --network-instance core" in namespace "z1"
    # PFCP ingest learned the session and z1 originated the ST2 — carrying
    # the Direct segment id (mup:1:2) but NO route-target yet.
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    And show command "show bgp mup" in namespace "z1" should not contain "rt:100:10"
    # z2 receives the route into its global MUP Loc-RIB (RT-independent)...
    And show command "show bgp mup" in namespace "z2" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    # ...but its per-VRF view (imports 100:10) is empty: the route has no RT.
    And show command "show bgp vrf mobile-up mup" in namespace "z2" should not contain "[ST2]"
    # Apply the export route-target on the live VRF.
    When I apply command "set vrf mobile-up mup route-target export 100:10" in namespace "z1"
    # The already-originated ST2 is re-stamped in place: rt:100:10 is added,
    # the Direct segment id mup:1:2 preserved.
    Then show command "show bgp mup" in namespace "z1" should eventually contain "rt:100:10 mup:1:2"
    # The re-advertised route reaches z2 carrying the new RT...
    And show command "show bgp mup" in namespace "z2" should eventually contain "rt:100:10 mup:1:2"
    # ...so z2's per-VRF view (imports 100:10) now mirrors it — the
    # end-to-end proof that the export-RT change re-originated AND
    # re-advertised the controller ST route.
    And show command "show bgp vrf mobile-up mup" in namespace "z2" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
