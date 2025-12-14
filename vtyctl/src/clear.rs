use anyhow::Result;
use std::process::exit;
use tonic::Request;
use vtysh::clear_client::ClearClient;
use vtysh::exec_client::ExecClient;
use vtysh::{ClearRequest, ExecRequest, ExecType};

pub mod vtysh {
    tonic::include_proto!("vtysh");
}

pub async fn clear(host: &String, command: &String) -> Result<()> {
    if command.is_empty() {
        eprintln!("vtyctl clear: command argument is required");
        eprintln!("Usage: vtyctl clear <command>");
        eprintln!("Example: vtyctl clear 'clear ip bgp *'");
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
        mode: String::from("configure"),
        privilege: 15,
        line: command.clone(),
        args: Vec::new(),
    };

    let exec_reply = exec_client.do_exec(Request::new(exec_request)).await?;
    let reply = exec_reply.into_inner();

    // Phase 2: Use the paths from exec_reply in ClearRequest
    let clear_client = ClearClient::connect(format!("http://{}:{}", host, 2666)).await;
    let Ok(mut clear_client) = clear_client else {
        eprintln!("Can't connect to {} for clear service", host);
        exit(3);
    };

    let request = ClearRequest {
        line: command.clone(),
        paths: reply.paths,
    };

    let response = clear_client.clear(Request::new(request)).await?;
    let reply = response.into_inner();

    if !reply.str.is_empty() {
        print!("{}", reply.str);
    }

    Ok(())
}
