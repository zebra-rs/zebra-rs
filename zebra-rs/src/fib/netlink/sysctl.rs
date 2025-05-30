use sysctl::Sysctl;

const CTLNAMES: &[(&str, &str)] = &[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
    ("net.ipv6.conf.all.seg6_enabled", "1"),
    ("net.ipv6.conf.default.seg6_enabled", "1"),
    ("net.vrf.strict_mode", "1"),
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
