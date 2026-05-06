use anyhow::Result;
use std::process::exit;
use tonic::Request;
use vty::exec_client::ExecClient;
use vty::show_client::ShowClient;
use vty::{ExecRequest, ExecType, ShowRequest};

pub mod vty {
    tonic::include_proto!("vty");
}

pub async fn show(host: &str, command: &str, json: bool) -> Result<()> {
    if command.is_empty() {
        eprintln!("zctl show: command argument is required");
        eprintln!("Usage: zctl show <command>");
        eprintln!("Example: zctl show 'show ip bgp vpnv4'");
        exit(1);
    }

    // Phase 1: Call Exec::do_exec to get paths
    let exec_client = ExecClient::connect(format!("http://{}:{}", host, 2666)).await;
    let Ok(mut exec_client) = exec_client else {
        eprintln!("Can't connect to {}", host);
        exit(3);
    };

    let exec_request = ExecRequest {
        r#type: ExecType::Exec as i32,
        mode: String::from("exec"),
        privilege: 15,
        line: command.to_string(),
        args: Vec::new(),
        ..Default::default()
    };

    let exec_reply = exec_client.do_exec(Request::new(exec_request)).await?;
    let reply = exec_reply.into_inner();

    // Phase 2: Use the paths from exec_reply in ShowRequest
    let show_client = ShowClient::connect(format!("http://{}:{}", host, 2666)).await;
    let Ok(mut show_client) = show_client else {
        eprintln!("Can't connect to {} for show service", host);
        exit(3);
    };

    let request = ShowRequest {
        line: command.to_string(),
        json,
        paths: reply.paths,
    };

    let response = show_client.show(Request::new(request)).await?;

    let mut stream = response.into_inner();

    while let Some(reply) = stream.message().await? {
        print!("{}", reply.str);
    }

    Ok(())
}
