@serial
@isis_lan_dis_pseudonode_purge
Feature: A resigning DIS purges the pseudonode LSP it originated

  Regression for a pseudonode-LSP leak on DIS resignation.

  On a broadcast LAN the Designated IS originates a pseudonode LSP. When it
  ceases to be DIS it must purge that LSP (ISO 10589 §7.3.4.6) rather than
  leave it to age out over MaxAge (~20 min). `dis_selection` does this via
  `ifsm::dis_dropping`, but a circuit going down never reached that path —
  `Isis::link_state_down` reset `adj` and `dis_status` directly, and
  `dis_dropping` is the only caller that emits `Message::LspPurge` for a
  pseudonode. So a DIS that lost its circuit left a zombie pseudonode LSP
  behind, in its own LSDB and in every other LSDB in the area.

  Forwarding survived it — SPF's two-way check discards a pseudonode the
  ex-DIS's own LSP no longer references — which is exactly why a
  reachability test cannot catch this. The assertion has to look at the
  LSDB.

  Three L2 routers (a1, a2, a3) share one broadcast LAN (br0). a1 holds LAN
  priority 200 (a2/a3 default 64) so a1 is deterministically DIS and owns
  the pseudonode. Dropping a1's circuit must purge it.

  Note this scenario asserts on a1's *own* LSDB. With a single circuit a1
  has nowhere to flood the purge once that circuit is down, so its peers
  necessarily age the LSP out — unavoidable, and true of any
  implementation. A router that still holds another circuit does flood the
  purge to the rest of the area; the originator-side invariant asserted
  here is what makes that possible.

  Scenario: a DIS that loses its circuit purges its pseudonode LSP
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "a1" with IP "192.168.100.1/24" on bridge "br0"
    And I create namespace "a2" with IP "192.168.100.2/24" on bridge "br0"
    And I create namespace "a3" with IP "192.168.100.3/24" on bridge "br0"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I start zebra-rs in namespace "a3"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    And I apply config "a3.yaml" to namespace "a3"
    And I wait 20 seconds
    # Preconditions: a1 must really be the elected DIS (a2 sees a1's system
    # ID as the LAN ID) and must really have originated a pseudonode LSP.
    # Without these the purge assertion below would pass vacuously on any
    # run where a1 never became DIS.
    Then show command "show isis interface" in namespace "a2" should eventually contain "0000.0000.0001."
    And namespace "a1" should eventually have a pseudonode LSP from "a1"
    # a1's circuit fails, so a1 is no longer DIS and must purge. The wait
    # takes us past ZeroAgeLifetime (60s) so the purged entry is evicted
    # outright rather than merely sitting at zero age.
    When I bring link down in namespace "a1"
    And I wait 45 seconds
    Then namespace "a1" should eventually have no pseudonode LSP from "a1"
    # a1's own non-pseudonode LSP is still present. This is what makes the
    # assertion above specific to the pseudonode rather than "a1 emptied
    # its LSDB" — before the fix the pseudonode sat here at its original
    # sequence number with Holdtime counting down from ~1190.
    And show command "show isis database" in namespace "a1" should contain "a1.00-00"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I stop zebra-rs in namespace "a3"
    And I delete namespace "a1"
    And I delete namespace "a2"
    And I delete namespace "a3"
    And I delete bridge "br0"
    Then the test environment should be clean
