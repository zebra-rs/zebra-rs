use super::{addr::OspfAddr, area::OspfArea};

#[derive(Default)]
pub struct OspfNetworkConfig {
    pub area: Option<OspfArea>,
    pub addr: Option<OspfAddr>,
}
