#[derive(Default, Debug, Clone)]
pub struct VlanConfig {
    // VLAN configuration structure
    pub delete: bool,

    // Parent interface the VLAN rides on. Mandatory in YANG.
    pub interface: Option<String>,

    // 802.1Q VLAN id. Mandatory in YANG.
    pub vlan_id: Option<u16>,
}
