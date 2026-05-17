use anyhow::Result;
use std::process::exit;
use tonic::Request;
use vty::clear_client::ClearClient;
use vty::exec_client::ExecClient;
use vty::{ClearRequest, ExecRequest, ExecType};

pub mod vty {
    tonic::include_proto!("vty");
}

pub async fn clear(host: &str, command: &str) -> Result<()> {
    if command.is_empty() {
        eprintln!("vtyctl clear: command argument is required");
        eprintln!("Usage: vtyctl clear <command>");
        eprintln!("Example: vtyctl clear 'clear ip bgp *'");
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
        mode: String::from("configure"),
        privilege: 15,
        line: command.to_string(),
        args: Vec::new(),
        ..Default::default()
    };

    let exec_reply = exec_client.do_exec(Request::new(exec_request)).await?;
    let reply = exec_reply.into_inner();

    // Phase 2: Use the paths from exec_reply in ClearRequest
    let mut clear_client = ClearClient::new(channel);

    let request = ClearRequest {
        line: command.to_string(),
        paths: reply.paths,
    };

    let response = clear_client.clear(Request::new(request)).await?;
    let reply = response.into_inner();

    if !reply.str.is_empty() {
        print!("{}", reply.str);
    }

    Ok(())
}
