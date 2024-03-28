use anyhow::{Context, Result};
use bgpd::*;
use std::{env, fs};

fn bgp_config_set(bgp: &mut Bgp) {
    bgp.set("/bgp/global/as/1");
    bgp.set("/bgp/global/router-id/10.211.65.2");
    bgp.set("/bgp/neighbors/address/10.211.55.65/peer-as/100");
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args: Vec<String> = env::args().collect();

    // MRT file read.
    if args.len() > 1 {
        if let Some(file_name) = args.pop() {
            let input = fs::read(file_name.clone())
                .with_context(|| format!("Can't open file {}", file_name))?;
            let _ = mrt_import(&input);
        }
        return Ok(());
    }
    let mut bgp = Bgp::new();
    bgp_config_set(&mut bgp);
    bgp.event_loop().await;
    Ok(())
}
