// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

pub mod netns;

#[tokio::main]
async fn main() {
    // let binding = ["show", "-j", "show ip route"];
    // let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    // if let Ok(output) = output {
    //     println!("{:?}", output);
    // }
    let cmd = format!("show ip bgp neighbors {}", "192.168.0.2");
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns("z1", "vtyctl", &binding).await;
    if let Ok(output) = output {
        println!("{:?}", output);
    }
}
