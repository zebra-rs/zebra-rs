use anyhow::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::debug;

use crate::mcp::client::{CandidateKind, ZebraClient};

/// One node in the flattened command list.
struct Node {
    help: String,
    /// "command" (runnable keyword), "category" (has subcommands), or
    /// "value" (expects a user-supplied argument).
    kind: &'static str,
    /// Whether the path is runnable as typed (a terminal keyword, or a
    /// category/value-list the grammar accepts bare — signalled by `<cr>`).
    runnable: bool,
}

/// Maximum command depth (token count) to descend, a guard against a
/// pathological or unexpectedly deep grammar.
const MAX_DEPTH: usize = 8;
/// Hard cap on emitted entries, a safety backstop.
const MAX_ENTRIES: usize = 4000;

/// Generates a flat list of every `show` command with its one-line help by
/// walking the daemon's live command grammar (via the completion engine).
///
/// The result is generated once and cached for the process lifetime — the
/// grammar is effectively static for a running daemon.
#[derive(Clone)]
pub struct CommandsTool {
    client: ZebraClient,
    cache: Arc<OnceCell<String>>,
}

impl CommandsTool {
    pub fn new(client: ZebraClient) -> Self {
        Self {
            client,
            cache: Arc::new(OnceCell::new()),
        }
    }

    /// Return the cached flat `show` command list, generating it on first use.
    pub async fn list_show_commands(&self) -> Result<String> {
        self.cache
            .get_or_try_init(|| self.generate())
            .await
            .cloned()
    }

    /// Walk the grammar under `show` and render the flat list as JSON.
    async fn generate(&self) -> Result<String> {
        // BTreeMap keeps the output sorted by command and dedups paths that
        // the grammar reaches more than once.
        let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = vec!["show".to_string()];

        while let Some(prefix) = stack.pop() {
            if nodes.len() >= MAX_ENTRIES {
                debug!("list-show-commands hit MAX_ENTRIES cap");
                break;
            }
            if !visited.insert(prefix.clone()) {
                continue;
            }
            if prefix.split_whitespace().count() >= MAX_DEPTH {
                continue;
            }

            let is_root = prefix == "show";
            let candidates = match self.client.complete_children(&prefix).await {
                Ok(c) => c,
                Err(e) if is_root => {
                    // Failing to enumerate the root means the daemon is
                    // unreachable — surface it rather than an empty list.
                    return Err(e);
                }
                Err(e) => {
                    debug!("completion failed for '{}': {}", prefix, e);
                    continue;
                }
            };

            for cand in candidates {
                // `<cr>` is the engine's "this path is complete/runnable here"
                // marker, not a subcommand — record it against the parent.
                if cand.name == "<cr>" {
                    if let Some(node) = nodes.get_mut(&prefix) {
                        node.runnable = true;
                    }
                    continue;
                }

                let full = format!("{} {}", prefix, cand.name);
                // A bare value placeholder (e.g. `<A.B.C.D>`) is an argument,
                // not a keyword: classify as value and never descend into it.
                let placeholder = cand.name.starts_with('<');
                let kind = if placeholder {
                    "value"
                } else {
                    match cand.kind {
                        CandidateKind::Dir => "category",
                        CandidateKind::Value => "value",
                        CandidateKind::Leaf => "command",
                    }
                };
                nodes.entry(full.clone()).or_insert_with(|| Node {
                    help: cand.help.clone(),
                    kind,
                    runnable: !placeholder && cand.kind == CandidateKind::Leaf,
                });

                // Descend into keyword categories and named value-lists (which
                // may carry keyword sub-options such as `summary`), but never
                // into bare value placeholders.
                if !placeholder && matches!(cand.kind, CandidateKind::Dir | CandidateKind::Value) {
                    stack.push(full);
                }
            }
        }

        let entries: Vec<Value> = nodes
            .into_iter()
            .map(|(command, node)| {
                json!({
                    "command": command,
                    "help": node.help,
                    "kind": node.kind,
                    "runnable": node.runnable,
                })
            })
            .collect();

        let doc = json!({
            "commands": entries,
            "note": "Generated live from the daemon command grammar. \
                     kind=command is a runnable keyword; kind=category has \
                     further subcommands; kind=value expects a user-supplied \
                     argument (address, prefix, name, ...). 'runnable' marks a \
                     path the daemon accepts as typed. Pass any runnable path \
                     to the `show` tool.",
        });
        Ok(serde_json::to_string_pretty(&doc)?)
    }
}
