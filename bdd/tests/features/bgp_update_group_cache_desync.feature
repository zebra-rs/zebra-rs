@serial
@bgp_update_group_cache_desync
Feature: A prefix withdrawn after an attribute change inside one MRAI window is not re-announced (IPv4)
  As a network operator
  I want a prefix whose attributes change and which is then withdrawn,
  all within one advertisement interval, to be withdrawn downstream for
  good — not re-announced at the next flush under its old attributes.

  Test Topology:
  ```
  ┌─────────┐          ┌─────────┐          ┌─────────┐
  │   h1    │──eBGP───▶│   z1    │──eBGP───▶│   z2    │
  │scripted │          │  (DUT)  │          │ zebra-rs│
  │ AS65041 │          │ AS65040 │          │ AS65042 │
  │  .2     │          │  .1     │          │  .3     │
  └─────────┘          └─────────┘          └─────────┘
        192.168.40.0/24 (one bridge)
  ```
  h1 runs tests/scripts/bgp_attr_churn_send.py. It announces the warm-up
  prefix 10.40.3.0/24 as soon as the session is up. On the trigger file
  /tmp/bgp_update_group_cache_desync.burst it sends, in one write: announce 10.40.1.0/24
  (ORIGIN IGP), announce it again (ORIGIN INCOMPLETE), withdraw it, and
  announce the control prefix 10.40.2.0/24. z1's eBGP advertisement
  interval is 5 s, so all of it lands in ONE flush window of z1's
  update-group pending-advert cache.

  Review finding #15: the cache inserted the prefix into the new
  attribute bucket without evicting it from the old one, and the
  withdraw purged only the new bucket — so the flush re-announced the
  prefix under its first attributes while z1's Adj-RIB-Out no longer held
  it, and no later withdraw could ever reach z2. The control prefix,
  flushed in the same window, proves the flush happened.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.40.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.40.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.40.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.40.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_churn_send.py 192.168.40.1 65041 192.168.40.2 4 10.40.3.0/24 10.40.1.0/24 10.40.2.0/24 192.168.40.2 /tmp/bgp_update_group_cache_desync" in namespace "h1"
    Then BGP session in "z1" to "192.168.40.2" should eventually be "Established"

  Scenario: The speaker's warm-up prefix reaches z2, so z1 has resolved its next-hop
    Given the test topology exists
    # A next-hop z1 has never tracked starts out unreachable until NHT
    # answers; a burst sent before that would never reach the advertise
    # path (empty selection) and this feature would pass vacuously.
    Then show command "show bgp" in namespace "z2" should eventually contain "10.40.3.0/24"

  Scenario: The churned prefix is withdrawn downstream for good
    Given the test topology exists
    When I execute "touch /tmp/bgp_update_group_cache_desync.burst" in namespace "h1"
    # z1 took the burst: the control prefix is in, the churned one is out.
    Then show command "show bgp" in namespace "z1" should eventually contain "10.40.2.0/24"
    And show command "show bgp" in namespace "z1" should not contain "10.40.1.0/24"
    # z2 received the flush that carried the control prefix ...
    And show command "show bgp" in namespace "z2" should eventually contain "10.40.2.0/24"
    # ... and that flush must not have re-announced the churned prefix.
    # Pre-fix it did (under ORIGIN IGP), and z2 kept it forever.
    And show command "show bgp" in namespace "z2" should not contain "10.40.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_update_group_cache_desync.burst" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
