@system_hostname
Feature: system hostname configuration
  As a network operator
  I want `set system hostname <name>` to define the device's name so
  that `show hostname` (and the interactive vty prompt, which tracks
  the same running-config leaf via vtyhelper -H) reflects the
  configured identity instead of the OS hostname, and falls back to
  the OS hostname when the leaf is deleted.

  Scenario: Build a single-node topology
    Given a clean test environment
    When I create namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I wait 2 seconds
    Then show command "show version" in namespace "z1" should contain "zebra-rs"

  Scenario: Configured hostname wins over the OS hostname
    Given the test topology exists
    # Before any config, show hostname reports the OS hostname —
    # whatever it is, it is not our marker name.
    Then show command "show hostname" in namespace "z1" should not contain "bdd-host-n1"
    When I apply command "set system hostname bdd-host-n1" in namespace "z1"
    Then show command "show hostname" in namespace "z1" should eventually contain "bdd-host-n1"

  Scenario: Deleting the hostname falls back to the OS hostname
    Given the test topology exists
    When I apply command "delete system hostname bdd-host-n1" in namespace "z1"
    Then show command "show hostname" in namespace "z1" should eventually not contain "bdd-host-n1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
