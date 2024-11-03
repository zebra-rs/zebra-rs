use sysctl::Sysctl;

const CTLNAMES: &[&str] = &[
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.seg6_enabled",
    "net.ipv6.conf.default.seg6_enabled",
    "net.vrf.strict_mode",
];

pub fn sysctl_enable() -> anyhow::Result<()> {
    for ctlname in CTLNAMES.iter() {
        let ctl = sysctl::Ctl::new(ctlname)?;
        let _ = ctl.set_value_string("1")?;
    }
    Ok(())
}
