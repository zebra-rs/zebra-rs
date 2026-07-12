use anyhow::Result;
use tokio_stream::StreamExt;
use tonic::Request;
use tracing::{debug, error};

use crate::vty::exec_client::ExecClient;
use crate::vty::show_client::ShowClient;
use crate::vty::{CommandPath, ExecRequest, ExecType, ShowRequest, YangMatch};

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

    /// Execute a show command and return the result as JSON
    pub async fn show_command(&self, command: &str, json: bool) -> Result<String> {
        let endpoint = self.endpoint();
        debug!("Connecting to zebra-rs at {}", endpoint);

        let channel = crate::endpoint::connect(&endpoint).await?;
        let mut client = ShowClient::new(channel);

        let mut paths = Vec::new();
        let cmds: Vec<&str> = command.split_whitespace().collect();
        let len = cmds.len();
        for (pos, cmd) in cmds.iter().enumerate() {
            let ymatch = if pos != len - 1 {
                YangMatch::Dir
            } else {
                YangMatch::Leaf
            };
            let path = CommandPath {
                name: cmd.to_string(),
                key: "".to_string(),
                ymatch: ymatch.into(),
                ..Default::default()
            };
            paths.push(path);
        }

        let request = Request::new(ShowRequest {
            json,
            line: command.to_string(),
            paths,
        });

        debug!("Executing show command: {}", command);
        let mut stream = client.show(request).await?.into_inner();

        let mut result = String::new();
        while let Some(reply) = stream.next().await {
            match reply {
                Ok(response) => {
                    result.push_str(&response.str);
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    return Err(anyhow::anyhow!("gRPC error: {}", e));
                }
            }
        }

        debug!("Show command completed, received {} bytes", result.len());
        Ok(result)
    }

    /// Execute ISIS-specific show commands
    pub async fn show_isis_command(&self, subcommand: &str, json: bool) -> Result<String> {
        let command = format!("show isis {}", subcommand);
        self.show_command(&command, json).await
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
}
