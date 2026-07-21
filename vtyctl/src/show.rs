use anyhow::Result;
use std::process::exit;
use tonic::Request;
use vty::exec_client::ExecClient;
use vty::show_client::ShowClient;
use vty::{ExecRequest, ExecType, ShowRequest};

pub mod vty {
    tonic::include_proto!("vty");
}

/// Inspect the phase-1 ExecReply. Parse failures (and codes we don't
/// know) must stop the client here: proceeding to the Show RPC with the
/// unresolved paths used to end in a silent empty stream and exit 0.
/// Returns the stderr message, or None when phase 2 may proceed.
fn exec_reply_error(code: i32, lines: &str) -> Option<String> {
    use vty::ExecCode;
    match ExecCode::try_from(code) {
        Ok(ExecCode::Success | ExecCode::Show | ExecCode::Redirect | ExecCode::RedirectShow) => {
            None
        }
        Ok(ExecCode::Nomatch | ExecCode::Incomplete | ExecCode::Ambiguous) => {
            let reason = lines.trim();
            let reason = if reason.is_empty() {
                match ExecCode::try_from(code) {
                    Ok(ExecCode::Incomplete) => "Incomplete",
                    Ok(ExecCode::Ambiguous) => "Ambiguous",
                    _ => "NoMatch",
                }
            } else {
                reason
            };
            Some(format!("command rejected: {reason}"))
        }
        Err(_) => Some(format!("unexpected exec code {code} from daemon")),
    }
}

/// When the Show stream yields nothing, fmap-backed commands (help,
/// candidate/running-config on older daemons) already carry their full
/// output in the phase-1 `lines` — fall back to it instead of erroring.
fn exec_show_fallback(code: i32, lines: &str) -> Option<&str> {
    (code == vty::ExecCode::Show as i32 && !lines.is_empty()).then_some(lines)
}

fn print_show_output(text: &str, last_ended_with_newline: &mut bool) {
    print!("{text}");
    if !text.is_empty() {
        *last_ended_with_newline = text.ends_with('\n');
    }
}

pub async fn show(host: &str, command: &str, json: bool) -> Result<()> {
    if command.is_empty() {
        eprintln!("vtyctl show: command argument is required");
        eprintln!("Usage: vtyctl show <command>");
        eprintln!("Example: vtyctl show 'show bgp vpnv4'");
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

    if let Some(msg) = exec_reply_error(reply.code, &reply.lines) {
        eprintln!("vtyctl show: {msg}");
        exit(1);
    }

    // Phase 2: Use the paths from exec_reply in ShowRequest
    let mut show_client = ShowClient::new(channel);

    let request = ShowRequest {
        line: command.to_string(),
        json,
        paths: reply.paths,
    };

    let response = show_client.show(Request::new(request)).await?;

    let mut stream = response.into_inner();

    let mut got_any = false;
    let mut last_ended_with_newline = true;
    loop {
        match stream.message().await {
            Ok(Some(reply)) => {
                got_any = true;
                print_show_output(&reply.str, &mut last_ended_with_newline);
            }
            Ok(None) => break,
            // The daemon reports an unanswered command (or another
            // stream failure). Never turn that into empty-and-success.
            Err(status) => {
                if !got_any && let Some(lines) = exec_show_fallback(reply.code, &reply.lines) {
                    got_any = true;
                    print_show_output(lines, &mut last_ended_with_newline);
                    break;
                }
                eprintln!("vtyctl show: {}", status.message());
                exit(1);
            }
        }
    }
    if !got_any {
        if let Some(lines) = exec_show_fallback(reply.code, &reply.lines) {
            print_show_output(lines, &mut last_ended_with_newline);
        } else {
            eprintln!(
                "vtyctl show: no output produced for '{command}' (command not handled by any daemon)"
            );
            exit(1);
        }
    }
    if !last_ended_with_newline {
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::vty::ExecCode;
    use super::*;

    #[test]
    fn exec_reply_error_rejects_parse_failures() {
        let msg = exec_reply_error(ExecCode::Nomatch as i32, "NoMatch\n").unwrap();
        assert_eq!(msg, "command rejected: NoMatch");
        let msg = exec_reply_error(ExecCode::Incomplete as i32, "").unwrap();
        assert_eq!(msg, "command rejected: Incomplete");
        let msg = exec_reply_error(ExecCode::Ambiguous as i32, "Ambiguous\n").unwrap();
        assert_eq!(msg, "command rejected: Ambiguous");
    }

    #[test]
    fn exec_reply_error_rejects_unknown_codes() {
        assert!(exec_reply_error(42, "").unwrap().contains("42"));
    }

    #[test]
    fn exec_reply_error_passes_showable_codes() {
        for code in [
            ExecCode::Success,
            ExecCode::Show,
            ExecCode::Redirect,
            ExecCode::RedirectShow,
        ] {
            assert_eq!(exec_reply_error(code as i32, ""), None);
        }
    }

    #[test]
    fn exec_show_fallback_only_for_show_with_output() {
        assert_eq!(
            exec_show_fallback(ExecCode::Show as i32, "config\n"),
            Some("config\n")
        );
        assert_eq!(exec_show_fallback(ExecCode::Show as i32, ""), None);
        assert_eq!(
            exec_show_fallback(ExecCode::RedirectShow as i32, "output\n"),
            None
        );
    }
}
