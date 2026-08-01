# EVPN VPWS (E-Line over SRv6) demo topology.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(c1 pe1 pe2 c2)

PLAYSET_LINKS=(
    c1:c1-pe1:pe1:pe1-c1
    pe1:pe1-pe2:pe2:pe2-pe1
    pe2:pe2-c2:c2:c2-pe2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(c1 pe1 pe2 c2)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(c1 pe1 pe2 c2)
