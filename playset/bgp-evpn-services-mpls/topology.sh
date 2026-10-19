# EVPN services (E-LINE, E-LAN, E-TREE) demo topology: three PEs around a
# P router, each service's CEs hanging off the PEs. The same topology and
# addressing in bgp-evpn-services-vxlan, -mpls and -srv6; only the
# encapsulation changes.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(p pe1 pe2 pe3 line1 line2 lan1 lan2 lan3 root1 leaf2 leaf3)

PLAYSET_LINKS=(
    pe1:pe1-p:p:p-pe1
    pe2:pe2-p:p:p-pe2
    pe3:pe3-p:p:p-pe3
    line1:line1-pe1:pe1:pe1-line1
    line2:line2-pe2:pe2:pe2-line2
    lan1:lan1-pe1:pe1:pe1-lan1
    lan2:lan2-pe2:pe2:pe2-lan2
    lan3:lan3-pe3:pe3:pe3-lan3
    root1:root1-pe1:pe1:pe1-root1
    leaf2:leaf2-pe2:pe2:pe2-leaf2
    leaf3:leaf3-pe3:pe3:pe3-leaf3
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(p pe1 pe2 pe3 line1 line2 lan1 lan2 lan3 root1 leaf2 leaf3)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(p pe1 pe2 pe3 line1 line2 lan1 lan2 lan3 root1 leaf2 leaf3)

# The CE hosts as "ns:iface:mac" — each host's PE-facing port and the MAC
# it gets, 02:00:00:00:<service>:<host> with service 01 = E-LINE,
# 02 = E-LAN, 03 = E-TREE.
PLAYSET_HOSTS=(
    line1:line1-pe1:02:00:00:00:01:01
    line2:line2-pe2:02:00:00:00:01:02
    lan1:lan1-pe1:02:00:00:00:02:01
    lan2:lan2-pe2:02:00:00:00:02:02
    lan3:lan3-pe3:02:00:00:00:02:03
    root1:root1-pe1:02:00:00:00:03:01
    leaf2:leaf2-pe2:02:00:00:00:03:02
    leaf3:leaf3-pe3:02:00:00:00:03:03
)
