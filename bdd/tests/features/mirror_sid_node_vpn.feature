@mirror_sid_node_vpn
@isis
Feature: IS-IS SRv6 Mirror SID egress NODE protection — live L3VPN service failover
  A real BGP L3VPN service survives the death of its egress PE node. The
  dual-homed CE ce2 hangs off the primary egress pea (a stub off pe1) and
  the protector peb (reached from pe1 over a direct bypass). pea carries
  the SRv6 L3VPN service for ce2 (per-VRF End.DT46) and peb advertises a
  Mirror SID (End.M) protecting pea's locator.

  When pea's node is killed, two opt-in mechanisms compose to keep the
  service forwarding end to end:
    * BGP-PIC `pic-retention` on pe1's pea session keeps pea's VPN route
      stale instead of withdrawing it on the session drop;
    * IS-IS Mirror SID node-protection stale-route retention keeps pea's
      locator alive on pe1 as a seg6 H.Encaps to peb's Mirror SID.
  NHT tracks pea's End.DT46 service SID (not pea's loopback), so it
  resolves the retained route *through* the locator, accumulating the
  Mirror SID — pe1 then double-encaps [Mirror SID, pea-SID] to peb, whose
  End.M re-resolves pea's SID in its mirror context and delivers to ce2.

  Topology (loopback 2001:db8::X, SRv6 locator fcbb:bbbb:X::/48):
  ```
    ce1 ── pe1 ──── pea (stub) ── ce2     pea: protected egress (LOC3)
   (c1::2) (::1) │  (::3)          │ \     peb: protector (LOC4),
                 │                 │  \         Mirror SID fcbb:bbbb:4:1::
                 └──── peb ────────┘   ce2 dual-homed (lo c2::1/128)
                      (::4)
  ```
  ce2 returns to ce1 via peb in both states (peb imports ce1), so only the
  forward path changes when pea dies.

  Scenario: Build topology and confirm IS-IS + BGP VPNv6 convergence
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I create namespace "ce1"
    And I create namespace "ce2"
    And I connect namespace "pe1" interface "pe1-pea" to namespace "pea" interface "pea-pe1"
    And I connect namespace "pe1" interface "pe1-peb" to namespace "peb" interface "peb-pe1"
    And I connect namespace "pe1" interface "ce1" to namespace "ce1" interface "eth0"
    And I connect namespace "pea" interface "pea-ce2" to namespace "ce2" interface "eth-a"
    And I connect namespace "peb" interface "peb-ce2" to namespace "ce2" interface "eth-b"
    And I add address "2001:db8:c1::2/64" to interface "eth0" in namespace "ce1"
    And I add route "::/0" via "2001:db8:c1::1" in namespace "ce1"
    And I make namespace "ce2" interface "lo" up
    And I add address "2001:db8:c2::1/128" to interface "lo" in namespace "ce2"
    And I add address "2001:db8:ac::2/64" to interface "eth-a" in namespace "ce2"
    And I add address "2001:db8:bc::2/64" to interface "eth-b" in namespace "ce2"
    And I add route "2001:db8:c1::/64" via "2001:db8:bc::1" in namespace "ce2"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "pea"
    And I start zebra-rs in namespace "peb"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "pea.yaml" to namespace "pea"
    And I apply config "peb.yaml" to namespace "peb"
    And I wait 45 seconds
    Then BGP session in "pe1" to "2001:db8::3" should be "Established"
    And BGP session in "pe1" to "2001:db8::4" should be "Established"
    And BGP session in "pea" to "2001:db8::1" should be "Established"

  Scenario: Baseline — the VPN service forwards ce1 to ce2 via pea
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "pe1" should contain "2001:db8:c2::1/128"
    And ping from "ce1" to "2001:db8:c2::1" should eventually succeed

  Scenario: pea node death — pic-retention keeps the route and the service survives
    Given the test topology exists
    Then ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    # Kill pea's node entirely (daemon stop closes its BGP TCP and stops
    # its IS-IS hellos). pe1's pea session drops; without pic-retention the
    # VPN route would vanish. With it, pe1 keeps pea's route stale, NHT
    # holds it reachable via the retained locator, and pe1 double-encaps to
    # peb's Mirror SID.
    When I stop zebra-rs in namespace "pea"
    And I wait 20 seconds
    # pe1 has NOT withdrawn pea's VPN route — pic-retention held it.
    Then show command "show bgp vpnv6" in namespace "pe1" should contain "2001:db8:c2::1/128"
    # And the L3VPN ping still reaches ce2 — now via peb's Mirror SID. This
    # proves the whole chain: stale BGP route + retained locator + NHT seg
    # accumulation + double-encap End.M decap carry live traffic past the
    # dead egress node.
    And ping from "ce1" to "2001:db8:c2::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "peb"
    And I delete namespace "pe1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    And I delete namespace "ce1"
    And I delete namespace "ce2"
    Then the test environment should be clean
