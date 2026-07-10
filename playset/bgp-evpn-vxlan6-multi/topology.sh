# BGP EVPN VXLAN multi-tenant (IPv6 transport) demo topology.
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(vtep1 vtep2 vtep3 h1 h2 h3 h4)

PLAYSET_LINKS=(
    vtep1:vtep1-vtep2:vtep2:vtep2-vtep1
    vtep1:vtep1-vtep3:vtep3:vtep3-vtep1
    h1:h1-vtep1:vtep1:vtep1-h1
    h2:h2-vtep2:vtep2:vtep2-h2
    h3:h3-vtep3:vtep3:vtep3-h3
    h4:h4-vtep1:vtep1:vtep1-h4
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(vtep1 vtep2 vtep3 h1 h2 h3 h4)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(vtep1 vtep2 vtep3 h1 h2 h3 h4)
