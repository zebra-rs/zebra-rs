pub mod netns;

#[tokio::main]
async fn main() {
    // let binding = ["show", "-j", "show ip route"];
    // let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    // if let Ok(output) = output {
    //     println!("{:?}", output);
    // }
    let cmd = format!("show bgp neighbors {}", "192.168.0.2");
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    if let Ok(output) = output {
        println!("{:?}", output);
    }
}
