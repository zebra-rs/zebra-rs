@mirror_sid_egress_link
@isis
Feature: IS-IS SRv6 Mirror SID egress link protection — steady-state baseline
  A dual-homed CE (ce2) hangs off both the primary egress pea and the
  protector peb. pea carries the BGP L3VPN service for ce2 over SRv6
  (per-VRF End.DT46), and peb advertises a Mirror SID (End.M) protecting
  pea's locator with via-vrf vrf-cust, so on a pea PE-CE link failure pea
  can redirect its own service SID to peb's Mirror SID. This feature
  validates the steady state that the failover test builds on: the VPN
  forwards via pea, the Mirror SID is advertised and the End.M localsid +
  mirror-context route install on peb, and pea's End.DT46 service SID is
  in place. The live link-failure redirect is exercised separately.

  Topology (loopback 2001:db8::X, SRv6 locator fcbb:bbbb:X::/48):
  ```
    ce1 ── pe1 ──── pea ──── ce2      pea: protected egress (LOC3)
   (c1::2) (::1)  (::3) │      │ \     peb: protector  (LOC4),
                        │      │  \         Mirror SID fcbb:bbbb:4:1::
                        peb ───┘   ce2 is dual-homed (lo c2::1/128)
                       (::4)
  ```
  ce2 returns to ce1 via peb in both states (peb imports ce1), so the
  forward path is the only thing that changes on failover. peb does not
  originate ce2 into BGP — pe1 always forwards ce2-bound traffic via pea.

  Scenario: Build topology and confirm IS-IS + BGP VPNv6 convergence
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I create namespace "ce1"
    And I create namespace "ce2"
    And I connect namespace "pe1" interface "pe1-pea" to namespace "pea" interface "pea-pe1"
    And I connect namespace "pea" interface "pea-peb" to namespace "peb" interface "peb-pea"
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

  Scenario: The VPN service forwards ce1 to ce2 via pea (primary egress)
    Given the test topology exists
    # pe1 learns ce2's prefix from pea (the sole BGP advertiser) with an
    # End.DT46 SRv6 SID, and forwards over the SRv6 underlay.
    Then show command "show bgp vpnv6" in namespace "pe1" should contain "2001:db8:c2::1/128"
    And ping from "ce1" to "2001:db8:c2::1" should eventually succeed

  Scenario: peb advertises the Mirror SID and installs End.M + mirror-context
    Given the test topology exists
    # The protector advertises End.M for pea's locator, with via-vrf so
    # the mirror-context table re-instantiates pea's End.DT46 into the VRF.
    Then show command "show isis egress-protection" in namespace "peb" should contain "fcbb:bbbb:3::/48"
    And show command "show isis database detail" in namespace "pe1" should contain "End.M"
    And show command "show segment-routing srv6 sid" in namespace "peb" should contain "End.M"
    And kernel route "fcbb:bbbb:4:1::" in namespace "peb" should eventually contain "seg6local"
    # The mirror-context route (pea's locator -> End.DT46 vrftable=vrf-cust)
    # installs into the dedicated mirror-context table, not the main table,
    # so it is not observable via `ip route show`; the live failover test
    # exercises it directly.

  Scenario: pea installs its per-VRF End.DT46 service SID
    Given the test topology exists
    Then show command "show segment-routing srv6 sid" in namespace "pea" should contain "End.DT46"

  Scenario: PE-CE link failure redirects via the Mirror SID
    Given the test topology exists
    # Baseline: ce1 -> ce2 flows via pea (the primary egress).
    Then ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    # Fail pea's PE-CE link. pea stays up (IS-IS/BGP intact, still
    # advertising ce2), so pe1 keeps H.Encaps-ing toward pea's End.DT46
    # service SID — but pea can no longer deliver locally. As its own PLR
    # pea redirects that SID to peb's Mirror SID (End.B6.Encaps); peb's
    # End.M re-resolves the inner SID in the mirror-context table into
    # vrf-cust and delivers over peb-ce2. A successful ping therefore
    # proves the two-level End.M -> End.DT46 decap carries live traffic.
    When I make namespace "pea" interface "pea-ce2" down
    And I wait 8 seconds
    Then ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    # The live redirect is now surfaced in show output (not just the kernel
    # route): pea's End.DT46 SID reports its H.Encaps redirect to peb's
    # Mirror SID.
    And show command "show segment-routing srv6 sid" in namespace "pea" should contain "egress-protection redirect"
    And show command "show segment-routing srv6 sid" in namespace "pea" should contain "fcbb:bbbb:4:1::"
    # Recover the link: pea restores the normal End.DT46 decap and the
    # service forwards locally again.
    When I make namespace "pea" interface "pea-ce2" up
    And I wait 8 seconds
    Then ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    # ...and the redirect annotation clears.
    And show command "show segment-routing srv6 sid" in namespace "pea" should not contain "egress-protection redirect"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "pea"
    And I stop zebra-rs in namespace "peb"
    And I delete namespace "pe1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    And I delete namespace "ce1"
    And I delete namespace "ce2"
    Then the test environment should be clean
