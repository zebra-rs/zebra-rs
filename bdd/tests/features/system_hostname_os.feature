@system_hostname_os
Feature: system hostname names the system with feature insomnia
  As an operator of a box whose whole configuration zebra-rs owns
  I want `set system hostname <name>` to rename the system itself when
  zebra-rs runs with `--feature insomnia`, and `delete` to give the
  system back the name it had, so that the configuration is the one
  place the name is kept. Without the feature the name must stay a label
  inside the daemon.

  A network namespace shares the host's UTS namespace, so no BDD daemon
  may reach the real `sethostname(2)`: the harness gives each one a
  file-backed stand-in (`ZEBRA_HOSTNAME_STUB_DIR`), `kernel` for the
  kernel name, `hostname` for /etc/hostname and `saved.json` for the name
  found at the first takeover. The stand-in's kernel name before anything
  set one is `localhost`, and it has no static name.

  The real call, and the rule that only a zebra-rs in the default network
  namespace makes it, run in the last two scenarios inside a sandbox
  (tests/scripts/system_hostname_sandbox.sh): a private UTS namespace and
  an overlay on /etc, so that the machine running the tests keeps its
  name whatever zebra-rs does (docs/design/system-hostname.md §10).

  Scenario: Build a single-node topology with the feature on
    Given a clean test environment
    And the system hostname stand-in of namespace "z1" is empty
    When I create namespace "z1"
    And I start zebra-rs in namespace "z1" with feature "insomnia"
    And I wait 2 seconds
    Then show command "show version" in namespace "z1" should contain "zebra-rs"
    # Nothing is configured: there is no name to apply, and nothing to
    # give back.
    And the system hostname stand-in of namespace "z1" should hold no files

  Scenario: A committed hostname becomes the system's
    Given the test topology exists
    When I apply command "set system hostname bdd-os-r1" in namespace "z1"
    Then the system host name of namespace "z1" should eventually be "bdd-os-r1"
    And the static host name of namespace "z1" should eventually be "bdd-os-r1"
    And the saved host name of namespace "z1" should eventually be kept
    And show command "show hostname" in namespace "z1" should contain "bdd-os-r1"
    And show command "show hostname" in namespace "z1" should not contain "not applied"

  Scenario: Changing the hostname renames the system
    Given the test topology exists
    When I apply command "set system hostname bdd-os-r2" in namespace "z1"
    Then the system host name of namespace "z1" should eventually be "bdd-os-r2"
    And the static host name of namespace "z1" should eventually be "bdd-os-r2"

  Scenario: A name the kernel would refuse is refused at commit
    Given the test topology exists
    Then applying command "set system hostname bdd-os..r9" in namespace "z1" should be rejected with "single dots"
    And the system host name of namespace "z1" should be "bdd-os-r2"

  Scenario: Deleting the hostname gives the system its name back
    Given the test topology exists
    When I apply command "delete system hostname bdd-os-r2" in namespace "z1"
    Then the system host name of namespace "z1" should eventually be "localhost"
    And the static host name of namespace "z1" should eventually be unset
    And the saved host name of namespace "z1" should eventually be removed

  Scenario: A hostname removed while zebra-rs was down is given back at the next start
    Given the test topology exists
    When I apply command "set system hostname bdd-os-r3" in namespace "z1"
    Then the system host name of namespace "z1" should eventually be "bdd-os-r3"
    # A BDD daemon starts from an empty config: the restart is a start
    # with the hostname line gone.
    When I stop zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z1" with feature "insomnia"
    Then the system host name of namespace "z1" should eventually be "localhost"
    And the static host name of namespace "z1" should eventually be unset
    And the saved host name of namespace "z1" should eventually be removed

  Scenario: Without the feature the hostname stays a label
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I wait 2 seconds
    And I apply command "set system hostname bdd-os-r4" in namespace "z1"
    # The commit is in: the daemon names itself.
    Then show command "show hostname" in namespace "z1" should eventually contain "bdd-os-r4"
    And I wait 2 seconds
    # And the system's name is still the one the last scenario left.
    Then the system host name of namespace "z1" should be "localhost"
    And the static host name of namespace "z1" should eventually be unset

  Scenario: The real host name changes in the default network namespace
    Given the test topology exists
    # No stand-in: sethostname(2) and /etc/hostname, in a sandbox with its
    # own PID and network namespace, as a container has. PID 1 is the
    # sandbox's, so zebra-rs is in the default network namespace there.
    # The script checks set, change, delete and a restart with the line
    # gone, and fails the step on the first check that does not hold.
    When I execute "tests/scripts/system_hostname_sandbox.sh apply" in namespace "z1"
    Then show command "show version" in namespace "z1" should contain "zebra-rs"

  Scenario: The real host name is left alone outside the default network namespace
    Given the test topology exists
    # No stand-in here either, and a network namespace that is not PID
    # 1's, as every `ip netns exec` daemon has: zebra-rs must not call
    # sethostname(2), must write nothing, and `show hostname` says why.
    When I execute "tests/scripts/system_hostname_sandbox.sh refuse" in namespace "z1"
    Then show command "show version" in namespace "z1" should contain "zebra-rs"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
