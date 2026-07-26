@serial
@bgp_evpn_srv6_rr
Feature: A route reflector preserves EVPN SRv6 L2 service SIDs
  As an operator running EVPN through route reflectors — the normal
  deployment, since a full iBGP mesh between PEs does not scale
  I want a reflected Type-2 / Type-3 to reach the far PE with its SRv6 L2
  Service TLV (RFC 9252) intact, so that EVPN-over-SRv6 works in a
  reflected fabric and not only over a direct PE-to-PE session.

  The Prefix-SID is an optional transitive attribute, so an RR is required
  to pass it through untouched. Nothing tested that it survives
  reflection: every other EVPN-over-SRv6 feature peers the PEs directly,
  where the attribute never passes through a third speaker.

  The topology is what makes the assertion airtight. The reflector runs no
  VNI, no locator and no `encapsulation srv6`, so it can carve no SID of
  its own; pe2 likewise has no locator. Any SID in pe2's EVPN RIB
  therefore came from pe1 by reflection — and it must render as a "Remote
  SID", never a "Local SID". The Originator-ID / Cluster-List that RFC
  4456 requires the reflector to add is asserted alongside, so a route
  that somehow arrived without being reflected would not pass either.

  ```
   pe1 ──2001:db8:13::/64── rr ──2001:db8:23::/64── pe2
   LOC1 fcbb:bbbb:1::/48   (no locator,           (no locator)
   VNI 10, encap srv6       no VNI, clients both)   VNI 10
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_rr/`):
  - pe1.yaml, rr.yaml, pe2.yaml — each PE peers ONLY with the reflector.

  Scenario: Setup the reflected EVPN fabric
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "rr"
    And I create namespace "pe2"
    And I connect namespace "pe1" interface "pe1rr" to namespace "rr" interface "rr1"
    And I connect namespace "pe2" interface "pe2rr" to namespace "rr" interface "rr2"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "pe2"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "pe2.yaml" to namespace "pe2"
    And I execute "ip link add br10 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan10 master br10" in namespace "pe1"
    And I execute "ip link set br10 up" in namespace "pe1"
    And I execute "ip link add host0 type dummy" in namespace "pe1"
    And I execute "ip link set host0 master br10" in namespace "pe1"
    And I execute "ip link set host0 up" in namespace "pe1"
    And I execute "ip link add br10 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan10 master br10" in namespace "pe2"
    And I execute "ip link set br10 up" in namespace "pe2"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8:13::3" should be "Established"
    And BGP session in "pe2" to "2001:db8:23::3" should be "Established"

  Scenario: The reflector carries pe1's Type-3 IMET and its End.DT2M SID
    Given the test topology exists
    # The RR itself holds the route with the SID it must pass on.
    Then show command "show bgp evpn" in namespace "rr" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "rr" should contain "(End.DT2M)"

  Scenario: pe2 receives the reflected Type-3 with the SID intact
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "pe2" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "pe2" should contain "(End.DT2M)"
    # pe2 has no locator, so nothing here can be self-originated.
    And show command "show bgp evpn" in namespace "pe2" should not contain "Local SID:"
    # RFC 4456: the reflector stamps its own identity on what it passes on.
    And show command "show bgp evpn" in namespace "pe2" should contain "Originator: 192.168.0.1"
    And show command "show bgp evpn" in namespace "pe2" should contain "Cluster list: 192.168.0.3"

  Scenario: A reflected Type-2 keeps its End.DT2U SID through the RR
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "pe1"
    Then show command "show bgp evpn" in namespace "pe2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "pe2" should eventually contain "(End.DT2U)"
    # The SID survived reflection well enough to bind in the MAC table —
    # the reflected route is usable, not merely present.
    And show command "show l2 mac table" in namespace "pe2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show l2 mac table" in namespace "pe2" should contain "srv6"
    And show command "show l2 mac table" in namespace "pe2" should contain "fcbb:bbbb:1:"

  Scenario: Withdrawing through the reflector clears the far PE
    Given the test topology exists
    When I execute "bridge fdb del aa:bb:cc:dd:ee:01 dev host0 master" in namespace "pe1"
    Then show command "show bgp evpn" in namespace "pe2" should eventually not contain "aa:bb:cc:dd:ee:01"
    And show command "show l2 mac table" in namespace "pe2" should eventually not contain "aa:bb:cc:dd:ee:01"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "rr"
    And I stop zebra-rs in namespace "pe2"
    And I delete namespace "pe1"
    And I delete namespace "rr"
    And I delete namespace "pe2"
    Then the test environment should be clean
