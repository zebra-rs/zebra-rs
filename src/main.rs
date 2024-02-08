use bgpd::*;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut bgp = Bgp::new();
    bgp.set("/bgp/global/as/1");
    bgp.set("/bgp/global/router-id/10.211.65.2");
    bgp.set("/bgp/neighbors/address/10.211.55.65/peer-as/100");
    bgp.event_loop().await;
    Ok(())
}
