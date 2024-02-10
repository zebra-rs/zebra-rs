use bgpd::*;
use std::error::Error;

fn bgp_config_set(bgp: &mut Bgp) {
    bgp.set("/bgp/global/as/1");
    bgp.set("/bgp/global/router-id/10.211.65.2");
    bgp.set("/bgp/neighbors/address/10.211.55.65/peer-as/100");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut bgp = Bgp::new();
    bgp_config_set(&mut bgp);
    bgp.event_loop().await;
    Ok(())
}
