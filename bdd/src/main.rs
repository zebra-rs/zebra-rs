pub mod netns;
// `netns` is compiled into this scratch binary as its own module tree (not
// pulled from the lib), so its `crate::toolchain` dependency has to be
// declared here as well.
pub mod toolchain;

#[tokio::main]
async fn main() {
    // let binding = ["show", "-j", "show ip route"];
    // let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    // if let Ok(output) = output {
    //     println!("{:?}", output);
    // }
    let cmd = format!("show bgp neighbor {}", "192.168.0.2");
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    if let Ok(output) = output {
        println!("{:?}", output);
    }
}
