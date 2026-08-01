# EVPN over MPLS between IPv6 PEs (E-LAN in eBPF) demo topology, with a
# pure-transit P router between the PEs.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(h1 pe1 p pe2 h2)

PLAYSET_LINKS=(
    h1:h1-pe1:pe1:pe1-h1
    pe1:pe1-p:p:p-pe1
    p:p-pe2:pe2:pe2-p
    pe2:pe2-h2:h2:h2-pe2
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(h1 pe1 p pe2 h2)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(h1 pe1 p pe2 h2)
