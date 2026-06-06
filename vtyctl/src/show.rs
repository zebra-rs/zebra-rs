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
    let uri = crate::endpoint::host_uri(host);
    let channel = match crate::endpoint::connect(&uri).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Can't connect to {uri}: {e}");
            exit(3);
        }
    };
    let mut exec_client = ExecClient::new(channel.clone());

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
    let mut show_client = ShowClient::new(channel);

    let request = ShowRequest {
        line: command.to_string(),
        json,
        paths: reply.paths,
    };

    let response = show_client.show(Request::new(request)).await?;

    let mut stream = response.into_inner();

    let mut last_ended_with_newline = true;
    while let Some(reply) = stream.message().await? {
        print!("{}", reply.str);
        if !reply.str.is_empty() {
            last_ended_with_newline = reply.str.ends_with('\n');
        }
    }
    if !last_ended_with_newline {
        println!();
    }

    Ok(())
}
