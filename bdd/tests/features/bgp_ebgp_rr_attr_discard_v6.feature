@serial
@bgp_ebgp_rr_attr_discard_v6
Feature: ORIGINATOR_ID and CLUSTER_LIST received from an eBGP peer are discarded (IPv6)
  As a network operator
  I want ORIGINATOR_ID and CLUSTER_LIST arriving over an eBGP session to
  be discarded on ingest (RFC 7606 §7.9 / §7.10, "attribute discard")
  So that another AS's route-reflection state can neither make my routers
  drop its routes as reflection loops nor be relayed into my AS.

  Both attributes describe reflection inside the AS that set them. Kept
  from an eBGP peer, they are checked against the local router-id — a
  neighbor AS whose reflector happens to share it (private router-ids
  collide easily) gets its routes dropped at the border — and they ride
  along when the border router hands the route to its iBGP peers, where
  a match on any of their router-ids drops the route there. Every real
  router strips both on eBGP egress, so only a scripted speaker can put
  the DUT's ingress on the spot. A malformed instance from an external
  neighbor is discarded too: it must cost neither the route nor the
  session.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │  eBGP   │─eBGP────▶│ AS65050 │────iBGP─▶│ AS65050 │
     │ AS65051 │          │192.168. │          │192.168. │
     │ .45.2/24│          │ 45.1/24 │          │ 45.3/24 │
     └─────────┘          └─────────┘          └─────────┘
  ```
  h1 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
  announces, with next-hop 2001:db8:45::2 and AS_PATH 65051 in
  MP_REACH_NLRI:
  - 2001:db8:c0::/64: no reflection attributes (the control);
  - 2001:db8:c1::/64: ORIGINATOR_ID 192.168.45.1 (z1's router-id);
  - 2001:db8:c2::/64: CLUSTER_LIST 192.0.2.99 192.168.45.1 (names z1);
  - 2001:db8:c3::/64: ORIGINATOR_ID 192.168.45.3 (z2's router-id);
  - 2001:db8:c4::/64: CLUSTER_LIST 192.0.2.99 192.168.45.3 (names z2).
  On the trigger file /tmp/bgp_ebgp_rr_attr_discard_v6.go it announces
  2001:db8:c5::/64 with a 3-octet ORIGINATOR_ID and 2001:db8:c6::/64 with a
  5-octet CLUSTER_LIST.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2; not a reflector;
    sessions over IPv4 carrying IPv6 unicast.
  - z2.yaml: iBGP peer of z1.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.45.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.45.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.45.2/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:45::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:45::3/64 dev vz2ns" in namespace "z2"
    And I execute "ip -6 addr add 2001:db8:45::2/64 dev vh1ns" in namespace "h1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.45.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.45.1 65051 192.168.45.2 6 2001:db8:45::2 /tmp/bgp_ebgp_rr_attr_discard_v6 2001:db8:c0::/64 2001:db8:c1::/64=80:09:c0a82d01 2001:db8:c2::/64=80:0a:c0000263c0a82d01 2001:db8:c3::/64=80:09:c0a82d03 2001:db8:c4::/64=80:0a:c0000263c0a82d03 -- 2001:db8:c5::/64=80:09:c0a82d 2001:db8:c6::/64=80:0a:c0000263c0" in namespace "h1"
    Then BGP session in "z1" to "192.168.45.2" should eventually be "Established"

  Scenario: The control prefix reaches z1 and z2
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:c0::/64"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:c0::/64"

  Scenario: Reflection attributes naming the DUT itself do not cost the route at the border
    Given the test topology exists
    # Pre-fix z1 kept both attributes and its own inbound loop check
    # (ORIGINATOR_ID == router-id, router-id in CLUSTER_LIST) dropped the
    # routes: a neighbor AS's reflection state was judged as z1's own.
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:c1::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:c2::/64"
    And BGP route in "z1" has "2001:db8:c1::/64" with "as_path" value "65051"
    And BGP route in "z1" has "2001:db8:c2::/64" with "next_hop" value "2001:db8:45::2"

  Scenario: Reflection attributes from the eBGP peer are not relayed into the AS
    Given the test topology exists
    # Pre-fix z1 relayed the attributes to z2 verbatim, and z2 dropped the
    # routes as reflection loops because they name its router-id.
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:c3::/64"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:c4::/64"
    # z1 holds neither attribute on the rows it learned from h1.
    And show command "show bgp ipv6 2001:db8:c3::/64" in namespace "z1" should not contain "Originator"
    And show command "show bgp ipv6 2001:db8:c4::/64" in namespace "z1" should not contain "Cluster list"

  Scenario: A malformed ORIGINATOR_ID or CLUSTER_LIST from the eBGP peer costs neither route nor session
    Given the test topology exists
    When I execute "touch /tmp/bgp_ebgp_rr_attr_discard_v6.go" in namespace "h1"
    # Pre-fix the malformed attribute was a parse error: z1 reset the
    # session and lost every route h1 had announced.
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:c5::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:c6::/64"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:c6::/64"
    And BGP session in "z1" to "192.168.45.2" should be "Established"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:c0::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_ebgp_rr_attr_discard_v6.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
