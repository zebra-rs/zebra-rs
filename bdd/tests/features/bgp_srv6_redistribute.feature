@bgp_srv6_redistribute
@bgp
Feature: BGP IPv6 redistribute connected with SRv6 End.DT6 origination
  As a network operator
  I want a connected IPv6 prefix redistributed into BGP on an
  SRv6-enabled speaker to carry an SRv6 End.DT6 service SID, so a peer
  configured for `encapsulation-type srv6` accepts it and the route
  reaches the peer's BGP table as an SRv6 service route.

  Test Topology (single point-to-point veth, eBGP over IPv6):
  ```
  ┌────────┐  i1 ──────── i1  ┌────────┐
  │   z1   │──────────────────│   z2   │
  │ AS65001│  2001:db8:12::/64│ AS65002│
  │ LOC1   │                  │ encap- │
  │ fcbb:1 │                  │ srv6   │
  └────────┘                  └────────┘
   cust0: 2001:db8:cafe::1/64 (connected, redistributed)
  ```

  - z1 advertises SRv6 locator `LOC1` (fcbb:bbbb:1::/48) and enables
    `segment-routing srv6 ipv6-unicast`, so locally-originated IPv6
    unicast routes carry an End.DT6 SID carved from the locator.
  - z1 redistributes connected; the dummy `cust0` prefix
    `2001:db8:cafe::/64` is originated into BGP with the SID stamped at
    origination (visible as a "Local SID" in `show bgp ipv6`).
  - z2 peers eBGP over IPv6 and sets `encapsulation-type srv6` on the
    session, so it only accepts SID-bearing routes; the redistributed
    prefix arrives carrying the SID (shown as a "Remote SID").

  Config files (in `bdd/tests/configs/bgp_srv6_redistribute/`):
  - z1.yaml, z2.yaml

  Scenario: Redistributed connected IPv6 route carries an End.DT6 Prefix-SID
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I create dummy interface "cust0" with address "2001:db8:cafe::1/64" in namespace "z1"
    And I wait 35 seconds
    # Originator: the redistributed connected prefix carries the SID it
    # owns, rendered as a "Local SID" with End.DT6 behavior.
    Then show command "show bgp ipv6 2001:db8:cafe::/64" in namespace "z1" should contain "Local SID"
    And show command "show bgp ipv6 2001:db8:cafe::/64" in namespace "z1" should contain "End.DT6"
    # Receiver (encapsulation-type srv6): accepted the SID-bearing route;
    # it is in the BGP table tagged as a "Remote SID".
    And show command "show bgp ipv6 2001:db8:cafe::/64" in namespace "z2" should contain "Remote SID"
    And show command "show bgp ipv6 2001:db8:cafe::/64" in namespace "z2" should contain "End.DT6"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
