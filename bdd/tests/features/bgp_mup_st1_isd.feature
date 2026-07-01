@serial
@bgp_mup_st1_isd
Feature: BGP MUP ST1 resolves to a local ISD segment and installs SRv6 encap
  A single MUP interwork node originates a local Interwork Segment Discovery
  (ISD, type 1, SAFI 85 / draft-ietf-bess-mup-safi) route advertising its
  per-VRF End.DT46 SID under a prefix, and — via its MUP controller — a
  Type-1 Session-Transformed (ST1) route whose UE address falls inside that
  prefix. Because the UE is covered by the local ISD, zebra-rs resolves the
  ST1 to the ISD's End.DT46 segment (`show bgp vrf <name> mup` prints the
  bind) and installs an oif-only recursive SRv6 H.Encaps route for the UE
  prefix into the VRF's table, so UE-bound traffic in the VRF is encapsulated
  toward that segment.

  Topology: one node z1.

       ┌──────────┐
       │    z1    │  VRF N6: encapsulation srv6
       │ MUP-C +  │    segment interwork prefix 10.60.0.0/16 (ISD)
       │ interwork│    route st1 network-instance access     (ST1 via PFCP)
       └──────────┘

  Scenario: Build a single interwork node and turn on the MUP controller
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp mup-c" in namespace "z1" should contain "PFCP listen : 192.168.0.1:8805"
    # The ISD originates from the segment config, keyed under the VRF's own RD.
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ISD][65000:100][10.60.0.0/16]"

  Scenario: A PFCP session inside the ISD prefix installs the SRv6 encap
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 10.60.1.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance access" in namespace "z1"
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "10.60.1.5"
    And show command "show bgp mup" in namespace "z1" should contain "ue=10.60.1.5/32"
    # The ST1's UE (10.60.1.5) is covered by the local ISD 10.60.0.0/16, so
    # the per-VRF view shows the resolution to the ISD's End.DT46 segment ...
    And show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "resolved 10.60.1.5/32 -> End.DT46"
    # ... and the SRv6 H.Encaps route is installed into the VRF table (an
    # oif-only recursive seg6 encap toward the locator-LOC1 End.DT46 SID).
    And command "ip route show table all" in namespace "z1" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bb01:"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
