use sysctl::Sysctl;

#[allow(dead_code)]
const CTLNAMES: &[&str] = &[
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.seg6_enabled",
    "net.ipv6.conf.default.seg6_enabled",
];

#[allow(dead_code)]
pub fn enable() -> anyhow::Result<()> {
    for ctlname in CTLNAMES.iter() {
        let ctl = sysctl::Ctl::new(ctlname)?;
        let _ = ctl.set_value_string("1")?;
    }
    Ok(())
}
