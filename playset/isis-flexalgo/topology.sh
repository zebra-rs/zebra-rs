# IS-IS FlexAlgo demo
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(se sj ch da va at ln fr sg sy tk)

PLAYSET_LINKS=(
    se:se-sg:sg:sg-se
    se:se-sj:sj:sj-se
    se:se-ch:ch:ch-se
    sj:sj-sy:sy:sy-sj
    sj:sj-da:da:da-sj
    sj:sj-ch:ch:ch-sj
    sj:sj-tk:tk:tk-sj
    ch:ch-da:da:da-ch
    ch:ch-va:va:va-ch
    ch:ch-ln:ln:ln-ch
    da:da-at:at:at-da
    va:va-at:at:at-va
    va:va-fr:fr:fr-va
    ln:ln-fr:fr:fr-ln
    fr:fr-sg:sg:sg-fr
    sg:sg-tk:tk:tk-sg
    sg:sg-sy:sy:sy-sg
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(se sj ch da va at ln fr sg sy tk)

# Routers with vtyctl YAML config (end hosts e1/e2 have no config).
PLAYSET_ROUTERS=(se sj ch da va at ln fr sg sy tk)
