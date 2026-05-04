@serial
@bgp_gobgpd_rr
Feature: BGP RR tests with gobgpd clients
  As a network operator
  I want to test zebra-rs BGP RR functionality with gobgpd clients
  Using a test topology with one zebra-rs RR and 29 gobgpd RR clients

  Test Topology:
  ```
                            ┌─────────────┐
                            │     rr      │
                            │ (zebra-rs)  │
                            │   AS64512   │
                            │    (RR)     │
                            │ 198.18.39.94│
                            │  Cluster-ID │
                            │ 198.18.39.94│
                            └──────┬──────┘
                                   │
  ┌────────────────────────────────┴────────────────────────────────────────────┐
  │                                    br0                                      │
  └───┬─────────────┬─────────────┬─────────────┬─────────────┬────────────┬────┘
      │             │             │             │             │            │
 ┌────┴────┐  ┌─────┴─────┐  ┌────┴────┐  ┌─────┴─────┐  ┌────┴────┐  ┌────┴────┐
 │  ese1   │  │   ese2    │  │  ese3   │  │   ese4    │  │  ...    │  │  ese29  │
 │(gobgpd) │  │ (gobgpd)  │  │(gobgpd) │  │ (gobgpd)  │  │         │  │(gobgpd) │
 │ AS64512 │  │  AS64512  │  │ AS64512 │  │  AS64512  │  │         │  │ AS64512 │
 │(client) │  │ (client)  │  │(client) │  │ (client)  │  │         │  │(client) │
 │198.18.  │  │ 198.18.   │  │198.18.  │  │ 198.18.   │  │         │  │198.18.  │
 │ 37.17   │  │  37.30    │  │ 37.81   │  │  37.82    │  │         │  │ 39.158  │
 └─────────┘  └───────────┘  └─────────┘  └───────────┘  └─────────┘  └─────────┘
  ```

  29 gobgpd RR clients: ese1-ese29 (see tests/configs/topology.list for IP addresses)

  Config files:
  - rr.yaml: AS 64512, zebra-rs RR with cluster-id 198.18.39.94, peers to all gobgpd clients
  - gobgpd clients configured as RR clients with l3vpn-ipv4-unicast AFI/SAFI

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
