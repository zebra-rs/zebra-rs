use anyhow::Result;
use std::io::Write;
use std::process::exit;
use tonic::Request;

use pb::config_service_client::ConfigServiceClient;
use pb::{ConfigEvent, Format, Op, SubscribeRequest};

pub mod pb {
    tonic::include_proto!("zebra.config.v1");
}

/// Render one PATH-format event as `set` / `delete` lines — the same
/// form `vtyctl apply` accepts.
fn format_event(event: &ConfigEvent) -> String {
    let mut out = String::new();
    for change in event.changes.iter() {
        let op = if change.op == Op::Delete as i32 {
            "delete"
        } else {
            "set"
        };
        out.push_str(op);
        for seg in change.path.iter() {
            out.push(' ');
            out.push_str(seg);
        }
        out.push('\n');
    }
    out
}

pub async fn watch(host: &str, json: bool, path: Vec<String>) -> Result<()> {
    let uri = crate::endpoint::host_uri(host);
    let channel = match crate::endpoint::connect(&uri).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Can't connect to {uri}: {e}");
            exit(3);
        }
    };
    let mut client = ConfigServiceClient::new(channel);

    let request = SubscribeRequest {
        format: if json { Format::Json } else { Format::Path } as i32,
        path,
    };
    let mut stream = client.subscribe(Request::new(request)).await?.into_inner();

    // First event is the snapshot of the current running config under
    // the watched path; each later event is one commit.
    while let Some(event) = stream.message().await? {
        if json {
            println!("{}", event.json);
        } else {
            print!("{}", format_event(&event));
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_event_renders_set_and_delete_lines() {
        let event = ConfigEvent {
            snapshot: false,
            changes: vec![
                pb::Change {
                    op: Op::Set as i32,
                    path: vec!["system".into(), "hostname".into(), "r1".into()],
                },
                pb::Change {
                    op: Op::Delete as i32,
                    path: vec!["interface".into(), "eth0".into(), "mtu".into()],
                },
            ],
            json: String::new(),
        };
        assert_eq!(
            format_event(&event),
            "set system hostname r1\ndelete interface eth0 mtu\n"
        );
    }
}
