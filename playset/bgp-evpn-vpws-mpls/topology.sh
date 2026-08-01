# EVPN VPWS (E-Line over MPLS) demo topology, with a pure-transit P
# router between the PEs.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(c1 pe1 p pe2 c2)

PLAYSET_LINKS=(
    c1:c1-pe1:pe1:pe1-c1
    pe1:pe1-p:p:p-pe1
    p:p-pe2:pe2:pe2-p
    pe2:pe2-c2:c2:c2-pe2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(c1 pe1 p pe2 c2)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(c1 pe1 p pe2 c2)
