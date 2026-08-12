use anyhow::Result;
use tokio_stream::StreamExt;
use tonic::Request;
use tracing::{debug, error};

use crate::vty::exec_client::ExecClient;
use crate::vty::show_client::ShowClient;
use crate::vty::{ExecCode, ExecRequest, ExecType, ShowRequest};

/// A single completion candidate for the token following a command line,
/// parsed from the daemon's completion engine output.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The candidate token (a keyword, or a value placeholder for `Value`).
    pub name: String,
    pub kind: CandidateKind,
    /// One-line help (the `ext:help` string from the YANG grammar).
    pub help: String,
}

/// What a completion candidate represents.
#[derive(Debug, Clone, PartialEq)]
pub enum CandidateKind {
    /// Has children — keep descending to reach full commands.
    Dir,
    /// A terminal keyword — a complete, runnable command.
    Leaf,
    /// A value-argument position (address, prefix, name, ...) — not a
    /// keyword and not enumerable, so we record but do not descend.
    Value,
}

/// Client for communicating with zebra-rs daemon via gRPC
#[derive(Clone)]
pub struct ZebraClient {
    pub base_url: String,
    pub port: u32,
}

impl ZebraClient {
    pub fn new(base_url: String, port: u32) -> Self {
        Self { base_url, port }
    }

    /// gRPC endpoint URI for the configured daemon.
    fn endpoint(&self) -> String {
        if self.base_url.starts_with("unix:") || self.base_url.contains("://") {
            self.base_url.clone()
        } else {
            format!("http://{}:{}", self.base_url, self.port)
        }
    }

    /// Execute a show command and return its output.
    ///
    /// Two-phase, like `vtyctl show`: the daemon's parser first resolves
    /// the command line into `CommandPath`s (which is what handles value
    /// arguments such as `flex-algo 128`), then the Show RPC runs those
    /// resolved paths. Building paths client-side from whitespace tokens
    /// only ever worked for pure-keyword commands.
    pub async fn show_command(&self, command: &str, json: bool) -> Result<String> {
        let endpoint = self.endpoint();
        debug!("Connecting to zebra-rs at {}", endpoint);

        let channel = crate::endpoint::connect(&endpoint).await?;

        // Phase 1: parse the line through the daemon's command grammar.
        let mut exec_client = ExecClient::new(channel.clone());
        let exec_request = Request::new(ExecRequest {
            r#type: ExecType::Exec as i32,
            mode: String::from("exec"),
            privilege: 15,
            line: command.to_string(),
            args: Vec::new(),
            ..Default::default()
        });
        let reply = exec_client.do_exec(exec_request).await?.into_inner();
        if let Some(msg) = exec_parse_error(reply.code, &reply.lines) {
            return Err(anyhow::anyhow!("{msg}"));
        }

        // Phase 2: run the resolved paths.
        let mut client = ShowClient::new(channel);
        let request = Request::new(ShowRequest {
            json,
            line: command.to_string(),
            paths: reply.paths,
        });

        debug!("Executing show command: {}", command);
        let mut stream = client.show(request).await?.into_inner();

        let mut result = String::new();
        let mut got_any = false;
        while let Some(item) = stream.next().await {
            match item {
                Ok(response) => {
                    got_any = true;
                    result.push_str(&response.str);
                }
                Err(e) => {
                    // Commands answered entirely in the exec phase (fmap
                    // commands like `show help`) stream nothing; their
                    // output already sits in the phase-1 `lines`.
                    if !got_any && reply.code == ExecCode::Show as i32 && !reply.lines.is_empty() {
                        return Ok(reply.lines);
                    }
                    error!("Error receiving response: {}", e);
                    return Err(anyhow::anyhow!("gRPC error: {}", e));
                }
            }
        }
        if !got_any && reply.code == ExecCode::Show as i32 && !reply.lines.is_empty() {
            return Ok(reply.lines);
        }

        debug!("Show command completed, received {} bytes", result.len());
        Ok(result)
    }

    /// Execute ISIS-specific show commands
    pub async fn show_isis_command(&self, subcommand: &str, json: bool) -> Result<String> {
        let command = format!("show isis {}", subcommand);
        self.show_command(&command, json).await
    }

    /// Run a show command in JSON mode, validating that the output
    /// parses. `empty` is returned for a daemon with no data (protocol
    /// not configured yet), so callers always get valid JSON.
    pub async fn show_json(&self, command: &str, empty: &str) -> Result<String> {
        match self.show_command(command, true).await {
            Ok(output) => {
                debug!("Received data for '{}': {} bytes", command, output.len());
                if output.trim().is_empty() {
                    debug!("'{}' returned empty output", command);
                    return Ok(empty.to_string());
                }
                match serde_json::from_str::<serde_json::Value>(&output) {
                    Ok(parsed) => Ok(serde_json::to_string_pretty(&parsed)?),
                    Err(e) => {
                        error!("Failed to parse '{}' JSON: {}", command, e);
                        // If parsing fails but we have data, it might be
                        // text format — return it rather than losing it.
                        Ok(output)
                    }
                }
            }
            Err(e) => {
                error!("Failed to run '{}': {}", command, e);
                Err(anyhow::anyhow!("Error retrieving data: {}", e))
            }
        }
    }

    /// Return the completion candidates for the token *after* `line`, using
    /// the daemon's completion engine (the same one that backs CLI `?`/TAB).
    /// Completion is not admin-gated, so a View session can enumerate the
    /// full command surface.
    pub async fn complete_children(&self, line: &str) -> Result<Vec<Candidate>> {
        let endpoint = self.endpoint();
        let channel = crate::endpoint::connect(&endpoint).await?;
        let mut client = ExecClient::new(channel);

        // CompleteTrailingSpace appends a space server-side, so this returns
        // the candidates that may follow `line` rather than completions of
        // its last token.
        let request = Request::new(ExecRequest {
            r#type: ExecType::CompleteTrailingSpace as i32,
            mode: String::from("exec"),
            privilege: 1,
            line: line.to_string(),
            args: Vec::new(),
            ..Default::default()
        });

        let reply = client.do_exec(request).await?.into_inner();
        Ok(parse_completion_lines(&reply.lines))
    }

    /// Test connectivity to the zebra-rs daemon
    pub async fn test_connection(&self) -> Result<()> {
        match self.show_command("show version", false).await {
            Ok(_) => {
                debug!("Successfully connected to zebra-rs");
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to zebra-rs: {}", e);
                Err(e)
            }
        }
    }
}

/// Inspect the phase-1 ExecReply of a show command. Parse failures (and
/// codes we don't know) must stop here: running the Show RPC with
/// unresolved paths ends in a NotFound from the daemon at best.
fn exec_parse_error(code: i32, lines: &str) -> Option<String> {
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

/// Parse the daemon completion engine's `lines` output into candidates.
///
/// The format (see `comp_commands` in `zebra-rs/src/config/serve.rs`) is a
/// status word on the first line (`Success`/`Incomplete`/`NoMatch`/
/// `Ambiguous`) followed by one candidate per line as
/// `name\t<marker>\thelp`, where the marker is `->` (Dir), `+>` (value/Key),
/// or two spaces (terminal leaf).
pub fn parse_completion_lines(lines: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for line in lines.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let name = match parts.next() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        let marker = parts.next().unwrap_or("");
        let help = parts.next().unwrap_or("").trim().to_string();
        let kind = match marker.trim() {
            "->" => CandidateKind::Dir,
            "+>" => CandidateKind::Value,
            _ => CandidateKind::Leaf,
        };
        out.push(Candidate { name, kind, help });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_marker_kinds_and_skips_status() {
        let lines = "Success\n\
                     bgp\t->\tBGP information\n\
                     version\t  \tShow version\n\
                     ipv4\t+>\tAddress (routes containing it) or prefix\n";
        let got = parse_completion_lines(lines);
        assert_eq!(
            got,
            vec![
                Candidate {
                    name: "bgp".to_string(),
                    kind: CandidateKind::Dir,
                    help: "BGP information".to_string(),
                },
                Candidate {
                    name: "version".to_string(),
                    kind: CandidateKind::Leaf,
                    help: "Show version".to_string(),
                },
                Candidate {
                    name: "ipv4".to_string(),
                    kind: CandidateKind::Value,
                    help: "Address (routes containing it) or prefix".to_string(),
                },
            ]
        );
    }

    #[test]
    fn nomatch_yields_no_candidates() {
        assert!(parse_completion_lines("NoMatch\n").is_empty());
        assert!(parse_completion_lines("").is_empty());
    }

    #[test]
    fn exec_parse_error_stops_on_parse_failures() {
        let msg = exec_parse_error(ExecCode::Nomatch as i32, "NoMatch\n").unwrap();
        assert_eq!(msg, "command rejected: NoMatch");
        let msg = exec_parse_error(ExecCode::Incomplete as i32, "").unwrap();
        assert_eq!(msg, "command rejected: Incomplete");
        assert!(exec_parse_error(99, "").unwrap().contains("99"));
    }

    #[test]
    fn exec_parse_error_passes_showable_codes() {
        for code in [
            ExecCode::Success,
            ExecCode::Show,
            ExecCode::Redirect,
            ExecCode::RedirectShow,
        ] {
            assert_eq!(exec_parse_error(code as i32, ""), None);
        }
    }
}
