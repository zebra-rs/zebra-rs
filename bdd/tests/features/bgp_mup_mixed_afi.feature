@serial
@bgp_mup_mixed_afi
Feature: BGP MUP mixed-AFI Session-Transformed route (IPv6 UE, IPv4 endpoint)
  As a network operator running 5G backhaul where the UE address family and
  the N3 transport differ, I want the zebra-rs BGP MUP Controller to
  originate a Type-1 Session-Transformed route (SAFI 85, RFC 9833 /
  draft-ietf-bess-mup-safi) for an IPv6 UE whose GTP endpoint (gNB) is IPv4,
  and a peer zebra-rs to receive and show it. This validates two behaviours:

    1. Mixed-AFI: the endpoint/source address family is decided by its own
       length octet (32 = IPv4, 128 = IPv6), independent of the outer AFI.
       The route is advertised under the IPv6-MUP AFI (the UE prefix family)
       yet carries an IPv4 endpoint; the receiver must parse it rather than
       reject it for an endpoint-length that differs from the outer AFI.

    2. No SID allocation by the MUP-C: z1 has NO SRv6 locator configured
       (neither `segment-routing` nor `mup-c srv6`). Origination must still
       succeed — the PE derives forwarding from its own ISD/DSD routes, so
       the controller neither allocates nor advertises a service SID.

  Test Topology:
  ```
           ┌─────────┐     ┌─────────┐
           │   z1    │ iBGP│   z2    │
           │ MUP-C   │◄───►│ receiver│
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴───────┐
           │ pfcp-inject │  (SMF simulator, run in z1)
           └────────────┘
  ```

  NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
  binary (the test-only SMF simulator, `tools/pfcp-inject`) must be on the
  BDD host PATH — build with `cargo build --release -p pfcp-inject` and copy
  `target/release/pfcp-inject` to /usr/bin, the same way the zebra-rs /
  vtyctl binaries are staged for BDD.

  Scenario: Setup topology and establish iBGP session with MUP capability
    Given a clean test environment
    When I create bridge "brmx0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "brmx0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "brmx0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv6 MUP: advertised and received"
    And show command "show bgp mobile-uplane mup-c" in namespace "z1" should contain "PFCP listen : 192.168.0.1:8805"

  Scenario: IPv6 UE with IPv4 endpoint originates an ST1 route the peer parses
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv6 2001:db8::5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance access" in namespace "z1"
    Then show command "show bgp mobile-uplane mup-c session" in namespace "z1" should eventually contain "2001:db8::5"
    And show command "show bgp mobile-uplane" in namespace "z1" should contain "ue=2001:db8::5/128"
    And show command "show bgp mobile-uplane" in namespace "z1" should contain "ep=10.0.0.1"
    And show command "show bgp mobile-uplane" in namespace "z2" should eventually contain "ue=2001:db8::5/128"
    And show command "show bgp mobile-uplane" in namespace "z2" should contain "ep=10.0.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "brmx0"
    Then the test environment should be clean
