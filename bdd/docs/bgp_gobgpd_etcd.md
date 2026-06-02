# BGP RR tests with gobgpd clients and etcd

## Overview

As a network operator
I want to test zebra-rs BGP RR functionality with gobgpd clients and etcd backend
Using a test topology with one zebra-rs RR, etcd, and 29 gobgpd RR clients

## Test Topology

```
                     ┌─────────────┐     ┌─────────────┐
                     │     rr      │     │    etcd     │
                     │ (zebra-rs)  │────▶│             │
                     │   AS64512   │     │  Key-Value  │
                     │    (RR)     │     │    Store    │
                     │ 198.18.39.94│     │             │
                     │  Cluster-ID │     │             │
                     │ 198.18.39.94│     │             │
                     └──────┬──────┘     └─────────────┘
                            │
  ┌─────────────────────────┴───────────────────────────────────────────────────┐
  │                                    br0                                      │
  └───┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬───┘
      │             │             │             │             │             │
 ┌────┴────┐  ┌─────┴─────┐  ┌────┴────┐  ┌─────┴─────┐  ┌────┴────┐  ┌────┴────┐
 │  ese1   │  │   ese2    │  │  ese3   │  │   ese4    │  │  ...    │  │  ese29  │
 │(gobgpd) │  │ (gobgpd)  │  │(gobgpd) │  │ (gobgpd)  │  │         │  │(gobgpd) │
 │ AS64512 │  │  AS64512  │  │ AS64512 │  │  AS64512  │  │         │  │ AS64512 │
 │(client) │  │ (client)  │  │(client) │  │ (client)  │  │         │  │(client) │
 │198.18.  │  │ 198.18.   │  │198.18.  │  │ 198.18.   │  │         │  │198.18.  │
 │ 37.17   │  │  37.30    │  │ 37.81   │  │  37.82    │  │         │  │ 39.158  │
 └─────────┘  └───────────┘  └─────────┘  └───────────┘  └─────────┘  └─────────┘
```

## Notes

29 gobgpd RR clients: ese1-ese29 (see tests/configs/topology.list for IP addresses)

## Config Files

- rr.yaml: AS 64512, zebra-rs RR with cluster-id 198.18.39.94, peers to all gobgpd clients
- gobgpd clients configured as RR clients with vpnv4 AFI/SAFI
- etcd: Key-value store backend for zebra-rs configuration

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session | |
