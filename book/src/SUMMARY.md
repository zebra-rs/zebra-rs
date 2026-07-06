# zebra-rs Routing Software

[zebra-rs Routing Software](ch-00-00-introduction.md)
- [Install](ch-00-06-install.md)
- [Building](ch-00-07-building.md)
- [Router ID Selection](ch-00-01-router-id.md)
- [Interface Configuration](ch-00-02-interface-configuration.md)
- [VXLAN Configuration](ch-00-03-vxlan-configuration.md)
- [Bridge Configuration](ch-00-04-bridge-configuration.md)
- [Command Line Options](ch-00-05-command-line-options.md)

## Static Route

- [Static Route](ch-01-00-what-is-static-route.md)
  - [Floating Static Route](ch-01-01-floating-static-route.md)
  - [Recursive Static Route](ch-01-02-recursive-static-route.md)
  - [Blackhole (Discard) Static Route](ch-01-03-blackhole-static-route.md)

## Routing Protocols

- [BGP](ch-02-00-what-is-bgp.md)
  - [Neighbor Groups](ch-02-26-bgp-neighbor-group.md)
  - [Dynamic Neighbors](ch-02-01-dynamic-neighbors.md)
  - [IPv6 Unnumbered (interface-neighbor)](ch-02-27-bgp-unnumbered.md)
  - [Session Authentication (TCP MD5 / TCP-AO)](ch-02-02-tcp-authentication.md)
  - [TTL: eBGP Multihop & Security (GTSM)](ch-02-11-bgp-ttl-security.md)
  - [TCP MSS](ch-02-14-bgp-tcp-mss.md)
  - [TCP Port (listen & per-neighbor)](ch-02-23-bgp-port.md)
  - [AS Override](ch-02-12-bgp-as-override.md)
  - [Local AS (AS Migration)](ch-02-30-bgp-local-as.md)
  - [allowas-in (Inbound AS_PATH Loop Relaxation)](ch-02-13-bgp-allowas-in.md)
  - [Remove Private AS](ch-02-14-bgp-remove-private-as.md)
  - [Enforce First AS](ch-02-15-bgp-enforce-first-as.md)
  - [Well-Known Communities](ch-02-24-bgp-well-known-communities.md)
  - [Table-Map (Policy at the BGP→RIB Install Point)](ch-02-28-bgp-table-map.md)
  - [disable-connected-check](ch-02-16-bgp-disable-connected-check.md)
  - [Fast External Failover](ch-02-37-bgp-fast-external-failover.md)
  - [ip-transparent (non-local update-source)](ch-02-29-bgp-ip-transparent.md)
  - [SRv6 Encapsulation Type (per-neighbor)](ch-02-17-bgp-srv6-encapsulation-type.md)
  - [Timer Configuration](ch-02-03-bgp-timers.md)
  - [L3VPN and Per-VRF Labels](ch-02-04-bgp-l3vpn.md)
  - [L3VPN over an SRv6 Underlay](ch-02-05-bgp-l3vpn-srv6.md)
  - [L3VPN PE-CE Routing Protocols](ch-02-36-bgp-l3vpn-pe-ce.md)
  - [EVPN Type-5 (IP Prefix Routes)](ch-02-06-bgp-evpn-type5.md)
  - [EVPN IGMP/MLD Proxy (Selective Multicast)](ch-02-32-bgp-evpn-igmp-mld-proxy.md)
  - [EVPN BUM & Assisted Replication](ch-02-33-bgp-evpn-assisted-replication.md)
  - [EVPN BUM Tunnel Segmentation (RFC 9572)](ch-02-34-bgp-evpn-segmentation.md)
  - [EVPN VPWS (E-Line over SRv6)](ch-02-38-bgp-evpn-vpws.md)
  - [Mobile User Plane (MUP) & the MUP Controller](ch-02-35-bgp-mup.md)
  - [Route Target Constraint (RTC)](ch-02-07-bgp-rtc.md)
  - [Inter-AS L3VPN](ch-02-18-bgp-interas.md)
    - [Option A (back-to-back VRFs)](ch-02-20-bgp-interas-option-a.md)
    - [Option B (VPNv4 between ASBRs)](ch-02-21-bgp-interas-option-b.md)
    - [Option C over SR-MPLS](ch-02-19-bgp-interas-option-c.md)
    - [Option AB (hybrid)](ch-02-22-bgp-interas-option-ab.md)
  - [BFD](ch-02-08-bgp-bfd.md)
  - [Route Reflector](ch-02-09-bgp-route-reflector.md)
  - [RIB Sharding (Parallel Route Processing)](ch-02-31-bgp-rib-sharding.md)
  - [Clearing BGP Sessions](ch-02-25-bgp-clear.md)
  - [Conditional Tracing](ch-02-10-bgp-tracing.md)
- [IS-IS](ch-07-00-isis.md)
  - [Timer Configuration](ch-07-01-isis-timers.md)
  - [Shared Risk Link Group (SRLG)](ch-07-02-isis-srlg.md)
  - [BFD](ch-07-03-isis-bfd.md)
  - [Clearing IS-IS State](ch-07-04-isis-clear.md)
  - [LSP MTU and Fragmentation](ch-07-05-isis-lsp-mtu.md)
  - [Route Redistribution](ch-07-06-isis-redistribution.md)
  - [Passive Interfaces](ch-07-07-isis-passive.md)
  - [Egress Protection (Mirror SID)](ch-07-08-isis-egress-protection.md)
- [OSPFv2](ch-08-00-ospf.md)
  - [Minimum Working Example](ch-08-04-ospf-minimum-working-example.md)
  - [Area Configuration](ch-08-05-ospf-area-configuration.md)
  - [Area Types: Stub and NSSA](ch-08-13-ospf-area-types.md)
  - [Multi-Area Routing and the ABR](ch-08-14-ospf-multi-area-abr.md)
  - [Moving an Interface Between Areas](ch-08-06-ospf-interface-area-move.md)
  - [Per-Interface Configuration](ch-08-07-ospf-per-interface.md)
  - [Timer Configuration](ch-08-08-ospf-timers.md)
  - [Authentication](ch-08-16-ospf-authentication.md)
  - [Route Redistribution](ch-08-15-ospf-redistribution.md)
  - [Segment Routing](ch-08-09-ospf-segment-routing.md)
  - [Graceful Restart](ch-08-17-ospf-graceful-restart.md)
  - [Conditional Tracing](ch-08-10-ospf-tracing.md)
  - [Cross-Reference with FRR ospfd](ch-08-11-ospf-frr-cross-reference.md)
  - [Gaps Relative to FRR ospfd](ch-08-12-ospf-frr-gaps.md)
  - [BFD](ch-08-02-ospf-bfd.md)
  - [Clearing OSPF State](ch-08-03-ospf-clear.md)
- [OSPFv3](ch-15-00-ospfv3.md)
  - [Minimum Working Example](ch-15-01-ospfv3-minimum-working-example.md)
  - [Area Configuration](ch-15-02-ospfv3-area-configuration.md)
  - [Area Types: Stub and NSSA](ch-15-03-ospfv3-area-types.md)
  - [Multi-Area Topologies and the ABR](ch-15-04-ospfv3-multi-area-abr.md)
  - [Moving an Interface Between Areas](ch-15-05-ospfv3-interface-area-move.md)
  - [Per-Interface Configuration](ch-15-06-ospfv3-per-interface.md)
  - [Timer Configuration](ch-15-07-ospfv3-timers.md)
  - [Authentication](ch-15-08-ospfv3-authentication.md)
  - [Route Redistribution](ch-15-09-ospfv3-redistribution.md)
  - [Segment Routing (SR-MPLS)](ch-15-10-ospfv3-segment-routing.md)
  - [SRv6](ch-15-11-ospfv3-srv6.md)
  - [Graceful Restart](ch-15-12-ospfv3-graceful-restart.md)
  - [Conditional Tracing](ch-15-13-ospfv3-tracing.md)
  - [Cross-Reference with FRR ospf6d](ch-15-14-ospfv3-frr-cross-reference.md)
  - [Gaps Relative to FRR ospf6d](ch-15-15-ospfv3-frr-gaps.md)
  - [BFD](ch-15-17-ospfv3-bfd.md)
  - [Clearing OSPFv3 State](ch-15-16-ospfv3-clear.md)

## Failure Detection

- [BFD](ch-10-00-bfd.md)
  - [The XDP/eBPF Data-Plane Helper](ch-10-01-bfd-xdp-helper.md)

## Fast Reroute

- [Fast Failover: TI-LFA + BFD (NexthopProtect)](ch-12-00-nexthop-protect.md)

## Performance Measurement

- [STAMP](ch-09-00-twamp-stamp.md)

## SRv6

- [SRv6](ch-04-00-srv6.md)

## Policy

- [Policy](ch-05-00-policy.md)
  - [Control Flow](ch-05-01-policy-control-flow.md)
  - [Match](ch-05-02-policy-match.md)
  - [Set](ch-05-03-policy-set.md)
  - [Lua Scripting](ch-05-04-lua-scripting.md)

## Management Interface

- [VTY Access and Authentication](ch-06-00-vty-access.md)
  - [Session Management Design](ch-06-01-session-design.md)
  - [Show Config Commands](ch-06-02-show-config-commands.md)

## Operational Show Commands

- [Overview](ch-14-00-show-overview.md)
  - [System, RIB and Forwarding](ch-14-01-show-system-rib.md)
  - [BGP](ch-14-02-show-bgp.md)
  - [OSPFv2 and OSPFv3](ch-14-03-show-ospf.md)
  - [IS-IS](ch-14-04-show-isis.md)
  - [Neighbor Discovery, BFD and STAMP](ch-14-05-show-bfd-stamp-nd.md)
  - [Policy Objects](ch-14-06-show-policy.md)

## AI Native

- [Native MCP Server](ch-13-00-mcp-server.md)

## Logging and Monitoring

- [Logging Configuration](ch-03-00-logging-overview.md)
  - [Log Output Destinations](ch-03-01-log-output-destinations.md)
  - [Log Formats](ch-03-02-log-formats.md)
  - [Protocol-Specific Logging](ch-03-03-protocol-logging.md)
  - [RIB/FIB Tracing](ch-03-06-rib-fib-tracing.md)
  - [Logging Integration](ch-03-04-logging-integration.md)
  - [Logging Troubleshooting](ch-03-05-logging-troubleshooting.md)

## Testing

- [BDD Integration Tests](ch-11-00-bdd-tests.md)

---

# Appendices

- [Appendix A: Logging Quick Reference](appendix-a-logging-quick-reference.md)
- [Appendix B: Supported RFCs and Internet-Drafts](appendix-b-supported-rfcs.md)
