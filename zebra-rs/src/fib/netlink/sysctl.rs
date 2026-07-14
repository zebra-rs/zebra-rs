use sysctl::Sysctl;

const CTLNAMES: &[(&str, &str)] = &[
    ("net.ipv4.ip_forward", "1"),
    // Loosen IPv4 reverse-path filtering. An SRv6 L3VPN egress (End.DT46)
    // decapsulates an inner IPv4 packet and re-injects it on the SR dummy
    // (`sr0`), whose interface is asymmetric to the packet source's return
    // path (a separate H.Encap route) — strict RPF (the common distro
    // default of `1`) would silently drop it, so VPNv4-over-SRv6 forwarding
    // would black-hole while VPNv6 (no RPF) worked. A router forwards
    // asymmetric traffic by design, so disable it globally (matches FRR's
    // SRv6 guidance). `all` is the max with the per-interface value, so it
    // must be `0` for any interface to be loose.
    ("net.ipv4.conf.all.rp_filter", "0"),
    ("net.ipv4.conf.default.rp_filter", "0"),
    ("net.ipv6.conf.all.forwarding", "1"),
    ("net.ipv6.conf.all.seg6_enabled", "1"),
    ("net.ipv6.conf.default.seg6_enabled", "1"),
    ("net.ipv6.conf.all.keep_addr_on_down", "1"),
    ("net.ipv6.conf.default.keep_addr_on_down", "1"),
    ("net.vrf.strict_mode", "1"),
    // Let the global unbound `:179` BGP listener accept inbound TCP
    // connections that arrive on a VRF (l3mdev) interface. Without it the
    // kernel drops the SYN — there is no listener in the VRF's routing
    // table — and a per-VRF BGP peer (e.g. a PE-CE session inside a VRF,
    // as in Inter-AS MPLS/VPN Option A) can never accept and stays stuck
    // in Active. The accept dispatcher then routes the connection to the
    // owning VRF task by source IP. Mirrors FRR's `bgp_vrf` enablement.
    ("net.ipv4.tcp_l3mdev_accept", "1"),
    ("net.mpls.platform_labels", "1048575"),
];

pub fn sysctl_enable() -> anyhow::Result<()> {
    for (ctlname, value) in CTLNAMES.iter() {
        let ctl = sysctl::Ctl::new(ctlname)?;
        let _ = ctl.set_value_string(value)?;
    }
    Ok(())
}

pub fn sysctl_mpls_enable(ifname: &String) -> anyhow::Result<()> {
    let ctlname = format!("net.mpls.conf.{}.input", ifname);
    let ctl = sysctl::Ctl::new(ctlname.as_str())?;
    let _ = ctl.set_value_string("1")?;
    Ok(())
}

/// Set the global kernel MPLS→IP TTL propagation for locally-originated
/// traffic (`net.mpls.ip_ttl_propagate`): `true` = uniform (copy the inner IP
/// TTL into the imposed label so the LSP is visible), `false` = pipe (seed the
/// label TTL independently, hiding the LSP). This governs the host kernel's
/// own MPLS imposition — the lwtunnel MPLS encap routes zebra installs for the
/// router's own traffic — which is the `propagate-local` half of RFC 3443's
/// forwarded/local split. The cradle data plane imposes only forwarded/transit
/// traffic, so the forwarded half is teed there instead. The sysctl exists
/// once the mpls_router module is loaded (`net.mpls.platform_labels`).
pub fn sysctl_mpls_ip_ttl_propagate(propagate: bool) -> anyhow::Result<()> {
    let ctl = sysctl::Ctl::new("net.mpls.ip_ttl_propagate")?;
    let _ = ctl.set_value_string(if propagate { "1" } else { "0" })?;
    Ok(())
}

pub fn sysctl_seg6_enable(ifname: &String) -> anyhow::Result<()> {
    let ctlname = format!("net.ipv6.conf.{}.seg6_enabled", ifname);
    let ctl = sysctl::Ctl::new(ctlname.as_str())?;
    let _ = ctl.set_value_string("1")?;
    Ok(())
}

pub fn sysctl_keep_addr_on_down(ifname: &String) -> anyhow::Result<()> {
    let ctlname = format!("net.ipv6.conf.{}.keep_addr_on_down", ifname);
    let ctl = sysctl::Ctl::new(ctlname.as_str())?;
    let _ = ctl.set_value_string("1")?;
    Ok(())
}
