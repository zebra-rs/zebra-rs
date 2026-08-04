//! VyOS-compatible firewall → nftables backend.
//!
//! Consumes the `/firewall` config subtree as a JSON batch (see
//! `ConfigManager::subscribe_json`): every commit that touches the
//! subtree delivers the whole post-commit tree in one message. The
//! backend deserializes it into [`FirewallConfig`], renders a complete
//! nftables script and applies it atomically with `nft -f -` — the
//! script always begins with an add+delete of both zebra tables, so a
//! replace and a full teardown are the same one-transaction shape.
//! This mirrors VyOS itself, which re-renders its whole `vyos_filter`
//! table from the config tree on every commit (vyos-1x
//! `python/vyos/firewall.py` + `data/templates/firewall/nftables.j2`,
//! which this renderer follows line for line where it can).
//!
//! Renderer deviations from VyOS, all deliberate:
//! - tables/chains are `zebra_firewall` / `ZEBRA_*` instead of
//!   `vyos_filter` / `VYOS_*`, so the two can coexist on a lab box;
//! - the fragment-mark helper chains are emitted only when a rule in
//!   that family actually uses the `fragment` matcher;
//! - `queue` renders the canonical `queue [flags …] [to N]` spelling;
//! - interface names are always quoted (VyOS quotes only set members);
//! - `global-options` sysctl-style toggles and conntrack timeouts are
//!   NOT applied yet (state-policy IS rendered) — they need a
//!   different mechanism (sysctl writes), noted per-commit in the log.
//!
//! Anything the renderer cannot express safely is skipped with a
//! warning naming the rule — a rendered script is always syntactically
//! valid nft, so one bad rule cannot wedge the whole commit.

use std::collections::HashMap;

use serde::Deserialize;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::json::{Flex, de_flex_vec, de_presence};
use crate::config::{DisplayRequest, JsonConfigUpdate, ShowChannel, path_from_command};

pub struct Firewall {
    pub tx: UnboundedSender<JsonConfigUpdate>,
    rx: UnboundedReceiver<JsonConfigUpdate>,
    pub show: ShowChannel,
}

/// What the task retains between commits: the last committed model,
/// so show handlers answer from the same tree the ruleset was
/// rendered from (live counters are fetched from nftables per
/// request).
#[derive(Default)]
struct ShowState {
    model: Option<FirewallConfig>,
}

impl Firewall {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            tx,
            rx,
            show: ShowChannel::new(),
        }
    }

    pub async fn event_loop(mut self) {
        let mut state = ShowState::default();
        loop {
            tokio::select! {
                Some(update) = self.rx.recv() => process(update, &mut state).await,
                Some(req) = self.show.rx.recv() => process_show(&state, req).await,
                else => break,
            }
        }
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

async fn process(update: JsonConfigUpdate, state: &mut ShowState) {
    tracing::debug!("firewall: config update for /{}", update.path.join("/"));
    let cfg: FirewallConfig = match serde_json::from_str(&update.json) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!("firewall: config parse failed: {err}");
            return;
        }
    };
    let (script, warnings) = render(&cfg);
    state.model = if cfg.is_empty() { None } else { Some(cfg) };
    for warn in &warnings {
        tracing::warn!("firewall: {warn}");
    }
    match nft_apply(&script).await {
        Ok(()) => tracing::info!("firewall: nftables ruleset applied"),
        Err(err) => {
            tracing::error!("firewall: nft apply failed: {err}");
            tracing::debug!("firewall: rejected script:\n{script}");
        }
    }
}

/// Feed the rendered ruleset to `nft -f -`. One invocation = one
/// nftables transaction, so the delete+redefine pair inside the script
/// applies atomically.
async fn nft_apply(script: &str) -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "nft exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------
// Show
// ---------------------------------------------------------------

/// Per-rule live counters, keyed by the rule comment the renderer
/// stamps on every rule (`ipv4-FWD-filter-10`, `FWD-filter
/// default-action drop`, …). Fetched from `nft --json list table` at
/// show time; an error (table absent, nft missing) degrades to an
/// empty map so show still renders the configured view.
type Counters = HashMap<String, (u64, u64)>;

async fn nft_counters(fam: Fam) -> Counters {
    let counters = Counters::new();
    let output = tokio::process::Command::new("nft")
        .args(["--json", "list", "table", fam.ip(), TABLE])
        .output()
        .await;
    let Ok(output) = output else {
        return counters;
    };
    if !output.status.success() {
        return counters;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return counters;
    };
    parse_counters(&value)
}

/// Pull `comment → (packets, bytes)` out of `nft --json list table`
/// output: every rule object carrying a comment and a counter
/// expression contributes one entry.
fn parse_counters(value: &serde_json::Value) -> Counters {
    let mut counters = Counters::new();
    let Some(items) = value.get("nftables").and_then(|v| v.as_array()) else {
        return counters;
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let Some(comment) = rule.get("comment").and_then(|c| c.as_str()) else {
            continue;
        };
        let mut packets = 0u64;
        let mut bytes = 0u64;
        if let Some(exprs) = rule.get("expr").and_then(|e| e.as_array()) {
            for expr in exprs {
                if let Some(counter) = expr.get("counter") {
                    packets = counter.get("packets").and_then(|v| v.as_u64()).unwrap_or(0);
                    bytes = counter.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                }
            }
        }
        counters.insert(comment.to_string(), (packets, bytes));
    }
    counters
}

async fn process_show(state: &ShowState, req: DisplayRequest) {
    let (path, args) = path_from_command(&req.paths);
    let Some(cfg) = &state.model else {
        let _ = req
            .resp
            .send(String::from("% Firewall is not configured\n"))
            .await;
        return;
    };

    // Fetch live counters for the families the request can touch.
    let want_v4 = !path.starts_with("/show/firewall/ipv6");
    let want_v6 = !path.starts_with("/show/firewall/ipv4");
    let counters4 = if want_v4 {
        nft_counters(Fam::V4).await
    } else {
        Counters::new()
    };
    let counters6 = if want_v6 {
        nft_counters(Fam::V6).await
    } else {
        Counters::new()
    };

    let out = match path.as_str() {
        "/show/firewall" => {
            if req.json {
                show_json(cfg, &counters4, &counters6).to_string()
            } else {
                let mut out = show_groups_text(cfg);
                out.push_str(&show_family_text(cfg, Fam::V4, &counters4, None));
                out.push_str(&show_family_text(cfg, Fam::V6, &counters6, None));
                out
            }
        }
        "/show/firewall/group" => {
            if req.json {
                show_json_groups(cfg).to_string()
            } else {
                show_groups_text(cfg)
            }
        }
        "/show/firewall/ipv4" => {
            if req.json {
                show_json_family(cfg, Fam::V4, &counters4).to_string()
            } else {
                show_family_text(cfg, Fam::V4, &counters4, None)
            }
        }
        "/show/firewall/ipv6" => {
            if req.json {
                show_json_family(cfg, Fam::V6, &counters6).to_string()
            } else {
                show_family_text(cfg, Fam::V6, &counters6, None)
            }
        }
        "/show/firewall/ipv4/forward/filter"
        | "/show/firewall/ipv4/input/filter"
        | "/show/firewall/ipv4/output/filter"
        | "/show/firewall/ipv4/output/raw"
        | "/show/firewall/ipv4/prerouting/raw" => {
            show_hook(cfg, Fam::V4, &path, &counters4, req.json)
        }
        "/show/firewall/ipv6/forward/filter"
        | "/show/firewall/ipv6/input/filter"
        | "/show/firewall/ipv6/output/filter"
        | "/show/firewall/ipv6/output/raw"
        | "/show/firewall/ipv6/prerouting/raw" => {
            show_hook(cfg, Fam::V6, &path, &counters6, req.json)
        }
        "/show/firewall/ipv4/name" => show_custom(
            cfg,
            Fam::V4,
            args.0.front().map(|s| s.as_str()),
            &counters4,
            req.json,
        ),
        "/show/firewall/ipv6/name" => show_custom(
            cfg,
            Fam::V6,
            args.0.front().map(|s| s.as_str()),
            &counters6,
            req.json,
        ),
        _ => String::from("% Unknown firewall show command\n"),
    };
    let _ = req.resp.send(out).await;
}

/// One chain rendered as a table. `hook` and `label` reproduce the
/// comment keys the ruleset renderer stamps (`ipv4-FWD-filter-10`,
/// `FWD-filter default-action drop`), which is how live counters are
/// joined back onto config rules.
#[allow(clippy::too_many_arguments)]
fn chain_table_text(
    out: &mut String,
    fam: Fam,
    title: &str,
    hook: &str,
    label: &str,
    head: &Chain,
    rules: &[Rule],
    counters: &Counters,
    base: bool,
) {
    out.push_str(&format!("{} Firewall \"{title}\"\n\n", fam.label()));
    if let Some(desc) = &head.description {
        out.push_str(&format!(" Description: {desc}\n\n"));
    }
    out.push_str(&format!(
        " {:<8} {:<10} {:<10} {:>10} {:>12}  {}\n",
        "Rule", "Action", "Protocol", "Packets", "Bytes", "Conditions"
    ));
    out.push_str(&format!(
        " {:<8} {:<10} {:<10} {:>10} {:>12}  {}\n",
        "----", "------", "--------", "-------", "-----", "----------"
    ));

    let mut sorted: Vec<&Rule> = rules.iter().filter(|r| !r.disable).collect();
    sorted.sort_by_key(|r| {
        r.number
            .as_ref()
            .and_then(|n| n.to_string().parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    for rule in sorted {
        let num = rule
            .number
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_default();
        let action = rule
            .action
            .as_ref()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());
        let protocol = rule
            .protocol
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into());
        let comment = format!("{}-{hook}-{label}-{num}", fam.label());
        let (packets, bytes) = counters.get(&comment).copied().unwrap_or((0, 0));
        let conditions = rule_conditions(rule, fam, hook, label);
        out.push_str(&format!(
            " {num:<8} {action:<10} {protocol:<10} {packets:>10} {bytes:>12}  {conditions}\n"
        ));
    }

    let default_action = head
        .default_action
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_else(|| if base { "accept" } else { "drop" }.to_string());
    // The renderer labels base-chain default rules `{code}-{prior}`
    // ("FWD-filter") and custom-chain ones with the chain name.
    let default_label = if base {
        format!("{hook}-{label}")
    } else {
        label.to_string()
    };
    let default_comment = format!("{default_label} default-action {default_action}");
    let (packets, bytes) = counters.get(&default_comment).copied().unwrap_or((0, 0));
    out.push_str(&format!(
        " {:<8} {default_action:<10} {:<10} {packets:>10} {bytes:>12}  {}\n\n",
        "default",
        "-",
        if head.default_log { "log" } else { "" }
    ));
}

/// The matcher half of a rule, for the Conditions column: the
/// rendered nft line with the trailing counter/action/comment and any
/// log clause stripped. Reusing the ruleset renderer keeps the column
/// honest — it shows exactly what was programmed.
fn rule_conditions(rule: &Rule, fam: Fam, hook: &str, label: &str) -> String {
    match render_rule(rule, fam, hook, label) {
        Ok((line, _, _)) => {
            let mut cond = match line.find(" counter") {
                Some(pos) => line[..pos].to_string(),
                None => line,
            };
            if let Some(pos) = cond.find(" log prefix") {
                cond = cond[..pos].to_string();
            }
            if cond.is_empty() {
                "-".to_string()
            } else {
                cond
            }
        }
        Err(_) => "(not rendered)".to_string(),
    }
}

fn family(cfg: &FirewallConfig, fam: Fam) -> Option<&Family> {
    match fam {
        Fam::V4 => cfg.ipv4.as_ref(),
        Fam::V6 => cfg.ipv6.as_ref(),
    }
}

/// The five fixed hooks of a family, as (config accessor, title,
/// comment hook code, comment label) tuples.
fn hooks(f: &Family) -> Vec<(&Chain, String, &'static str, &'static str)> {
    let mut out = Vec::new();
    let entries = [
        (&f.forward, "forward", "filter", "FWD"),
        (&f.input, "input", "filter", "INP"),
        (&f.output, "output", "filter", "OUT"),
        (&f.output, "output", "raw", "OUT"),
        (&f.prerouting, "prerouting", "raw", "PRE"),
    ];
    for (hook, kw, prior, code) in entries {
        let Some(hook) = hook else { continue };
        let chain = match prior {
            "filter" => hook.filter.as_ref(),
            _ => hook.raw.as_ref(),
        };
        if let Some(chain) = chain {
            out.push((chain, format!("{kw} {prior}"), code, prior));
        }
    }
    out
}

fn show_family_text(
    cfg: &FirewallConfig,
    fam: Fam,
    counters: &Counters,
    only: Option<&str>,
) -> String {
    let mut out = String::new();
    let Some(f) = family(cfg, fam) else {
        return out;
    };
    for (chain, title, code, prior) in hooks(f) {
        if let Some(only) = only
            && only != title
        {
            continue;
        }
        chain_table_text(
            &mut out,
            fam,
            &title,
            code,
            prior,
            chain,
            &chain.rule,
            counters,
            true,
        );
    }
    if only.is_none() {
        for custom in &f.name {
            let Some(name) = &custom.name else { continue };
            let name = name.to_string();
            chain_table_text(
                &mut out,
                fam,
                &format!("name {name}"),
                "NAM",
                &name,
                &custom.as_chain(),
                &custom.rule,
                counters,
                false,
            );
        }
    }
    out
}

fn show_hook(
    cfg: &FirewallConfig,
    fam: Fam,
    path: &str,
    counters: &Counters,
    json: bool,
) -> String {
    // `/show/firewall/<fam>/<hook>/<prior>` → "<hook> <prior>".
    let mut segs = path.rsplit('/');
    let prior = segs.next().unwrap_or_default();
    let hook = segs.next().unwrap_or_default();
    let title = format!("{hook} {prior}");
    if json {
        return show_json_family(cfg, fam, counters).to_string();
    }
    let out = show_family_text(cfg, fam, counters, Some(title.as_str()));
    if out.is_empty() {
        format!("% Chain {} {title} is not configured\n", fam.label())
    } else {
        out
    }
}

fn show_custom(
    cfg: &FirewallConfig,
    fam: Fam,
    chain: Option<&str>,
    counters: &Counters,
    json: bool,
) -> String {
    if json {
        return show_json_family(cfg, fam, counters).to_string();
    }
    let mut out = String::new();
    let Some(f) = family(cfg, fam) else {
        return format!("% No {} custom chains configured\n", fam.label());
    };
    for custom in &f.name {
        let Some(name) = &custom.name else { continue };
        let name = name.to_string();
        if let Some(want) = chain
            && want != name
        {
            continue;
        }
        chain_table_text(
            &mut out,
            fam,
            &format!("name {name}"),
            "NAM",
            &name,
            &custom.as_chain(),
            &custom.rule,
            counters,
            false,
        );
    }
    if out.is_empty() {
        match chain {
            Some(name) => format!("% Chain {} name {name} is not configured\n", fam.label()),
            None => format!("% No {} custom chains configured\n", fam.label()),
        }
    } else {
        out
    }
}

/// How many rules reference a group of the given kind — the
/// References column of the groups view.
fn group_references(cfg: &FirewallConfig, kind: &str, name: &str) -> usize {
    let matches = |group: &Option<GroupRef>| -> usize {
        let Some(group) = group else { return 0 };
        let field = match kind {
            "address-group" | "ipv6-address-group" => &group.address_group,
            "network-group" | "ipv6-network-group" => &group.network_group,
            "port-group" => &group.port_group,
            "mac-group" => &group.mac_group,
            _ => &None,
        };
        field
            .as_ref()
            .is_some_and(|n| n.to_string().trim_start_matches('!') == name) as usize
    };
    let mut count = 0;
    for fam in [Fam::V4, Fam::V6] {
        let Some(f) = family(cfg, fam) else { continue };
        let mut per_rule = |rules: &[Rule]| {
            for rule in rules {
                for side in [&rule.source, &rule.destination] {
                    if let Some(side) = side {
                        count += matches(&side.group);
                    }
                    // Interface groups ride the interface matchers.
                    if kind == "interface-group" {
                        for ifm in [&rule.inbound_interface, &rule.outbound_interface] {
                            if let Some(ifm) = ifm
                                && ifm
                                    .group
                                    .as_ref()
                                    .is_some_and(|g| g.to_string().trim_start_matches('!') == name)
                            {
                                count += 1;
                            }
                        }
                    }
                }
            }
        };
        for (chain, _, _, _) in hooks(f) {
            per_rule(&chain.rule);
        }
        for custom in &f.name {
            per_rule(&custom.rule);
        }
    }
    count
}

fn group_kinds(groups: &Groups) -> [(&'static str, &Vec<Group>, fn(&Group) -> &Vec<Flex>); 7] {
    [
        ("address-group", &groups.address_group, |g| &g.address),
        ("ipv6-address-group", &groups.ipv6_address_group, |g| {
            &g.address
        }),
        ("network-group", &groups.network_group, |g| &g.network),
        ("ipv6-network-group", &groups.ipv6_network_group, |g| {
            &g.network
        }),
        ("port-group", &groups.port_group, |g| &g.port),
        ("interface-group", &groups.interface_group, |g| &g.interface),
        ("mac-group", &groups.mac_group, |g| &g.mac_address),
    ]
}

fn show_groups_text(cfg: &FirewallConfig) -> String {
    let mut out = String::new();
    let Some(groups) = &cfg.group else {
        return out;
    };
    out.push_str("Firewall Groups\n\n");
    out.push_str(&format!(
        " {:<20} {:<20} {:>10}  {}\n",
        "Name", "Type", "References", "Members"
    ));
    out.push_str(&format!(
        " {:<20} {:<20} {:>10}  {}\n",
        "----", "----", "----------", "-------"
    ));
    for (kind, list, members) in group_kinds(groups) {
        for group in list {
            let Some(name) = &group.name else { continue };
            let name = name.to_string();
            let refs = group_references(cfg, kind, &name);
            let mut first = true;
            let member_list = members(group);
            if member_list.is_empty() {
                out.push_str(&format!(" {name:<20} {kind:<20} {refs:>10}  -\n"));
                continue;
            }
            for member in member_list {
                if first {
                    out.push_str(&format!(" {name:<20} {kind:<20} {refs:>10}  {member}\n"));
                    first = false;
                } else {
                    out.push_str(&format!(" {:<20} {:<20} {:>10}  {member}\n", "", "", ""));
                }
            }
        }
    }
    out.push('\n');
    out
}

// JSON views: the same scopes as the text views, one structured value.

fn show_json_groups(cfg: &FirewallConfig) -> serde_json::Value {
    let mut out = Vec::new();
    if let Some(groups) = &cfg.group {
        for (kind, list, members) in group_kinds(groups) {
            for group in list {
                let Some(name) = &group.name else { continue };
                let name = name.to_string();
                out.push(serde_json::json!({
                    "name": name,
                    "type": kind,
                    "references": group_references(cfg, kind, &name),
                    "members": members(group).iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                }));
            }
        }
    }
    serde_json::json!({ "groups": out })
}

fn chain_json(
    fam: Fam,
    title: &str,
    hook: &str,
    label: &str,
    head: &Chain,
    rules: &[Rule],
    counters: &Counters,
) -> serde_json::Value {
    let mut rule_values = Vec::new();
    let mut sorted: Vec<&Rule> = rules.iter().filter(|r| !r.disable).collect();
    sorted.sort_by_key(|r| {
        r.number
            .as_ref()
            .and_then(|n| n.to_string().parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    for rule in sorted {
        let num = rule
            .number
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_default();
        let comment = format!("{}-{hook}-{label}-{num}", fam.label());
        let (packets, bytes) = counters.get(&comment).copied().unwrap_or((0, 0));
        rule_values.push(serde_json::json!({
            "number": num,
            "action": rule.action.as_ref().map(|a| a.to_string()),
            "protocol": rule.protocol.as_ref().map(|p| p.to_string()),
            "conditions": rule_conditions(rule, fam, hook, label),
            "packets": packets,
            "bytes": bytes,
        }));
    }
    serde_json::json!({
        "chain": title,
        "family": fam.label(),
        "defaultAction": head.default_action.as_ref().map(|a| a.to_string()),
        "defaultLog": head.default_log,
        "description": head.description.as_ref().map(|d| d.to_string()),
        "rules": rule_values,
    })
}

fn show_json_family(cfg: &FirewallConfig, fam: Fam, counters: &Counters) -> serde_json::Value {
    let mut chains = Vec::new();
    if let Some(f) = family(cfg, fam) {
        for (chain, title, code, prior) in hooks(f) {
            chains.push(chain_json(
                fam,
                &title,
                code,
                prior,
                chain,
                &chain.rule,
                counters,
            ));
        }
        for custom in &f.name {
            let Some(name) = &custom.name else { continue };
            let name = name.to_string();
            chains.push(chain_json(
                fam,
                &format!("name {name}"),
                "NAM",
                &name,
                &custom.as_chain(),
                &custom.rule,
                counters,
            ));
        }
    }
    serde_json::json!({ "family": fam.label(), "chains": chains })
}

fn show_json(
    cfg: &FirewallConfig,
    counters4: &Counters,
    counters6: &Counters,
) -> serde_json::Value {
    serde_json::json!({
        "groups": show_json_groups(cfg)["groups"],
        "ipv4": show_json_family(cfg, Fam::V4, counters4),
        "ipv6": show_json_family(cfg, Fam::V6, counters6),
    })
}

// ---------------------------------------------------------------
// Config model
//
// Deserialized from `Config::json()` output with the shared helpers
// in `super::json` — see that module for the marshal shapes (numeric
// scalars unquoted → `Flex`, `type empty` → null → `de_presence`,
// keyed lists as arrays, leaf-lists via `de_flex_vec`).
// ---------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct FirewallConfig {
    pub group: Option<Groups>,
    pub ipv4: Option<Family>,
    pub ipv6: Option<Family>,
    pub global_options: Option<GlobalOptions>,
}

impl FirewallConfig {
    fn is_empty(&self) -> bool {
        self.group.is_none()
            && self.ipv4.is_none()
            && self.ipv6.is_none()
            && self.global_options.is_none()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Groups {
    pub address_group: Vec<Group>,
    pub ipv6_address_group: Vec<Group>,
    pub network_group: Vec<Group>,
    pub ipv6_network_group: Vec<Group>,
    pub port_group: Vec<Group>,
    pub interface_group: Vec<Group>,
    pub mac_group: Vec<Group>,
}

/// One named group. Which member vector is populated depends on the
/// group type; carrying them all keeps one struct for all seven lists.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Group {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub address: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub network: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub port: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub interface: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub mac_address: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub include: Vec<Flex>,
    pub description: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Family {
    pub forward: Option<Hook>,
    pub input: Option<Hook>,
    pub output: Option<Hook>,
    pub prerouting: Option<Hook>,
    pub name: Vec<CustomChain>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Hook {
    pub filter: Option<Chain>,
    pub raw: Option<Chain>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Chain {
    pub default_action: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub default_log: bool,
    pub default_jump_target: Option<Flex>,
    pub description: Option<Flex>,
    pub rule: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct CustomChain {
    pub name: Option<Flex>,
    pub default_action: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub default_log: bool,
    pub default_jump_target: Option<Flex>,
    pub description: Option<Flex>,
    pub rule: Vec<Rule>,
}

impl CustomChain {
    fn as_chain(&self) -> Chain {
        Chain {
            default_action: self.default_action.clone(),
            default_log: self.default_log,
            default_jump_target: self.default_jump_target.clone(),
            description: self.description.clone(),
            rule: Vec::new(), // rules are rendered from &self.rule directly
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Rule {
    pub number: Option<Flex>,
    pub action: Option<Flex>,
    pub description: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub jump_target: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub state: Vec<Flex>,
    pub protocol: Option<Flex>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub inbound_interface: Option<IfMatch>,
    pub outbound_interface: Option<IfMatch>,
    pub icmp: Option<Icmp>,
    pub icmpv6: Option<Icmp>,
    pub ttl: Option<Cmp>,
    pub hop_limit: Option<Cmp>,
    pub tcp: Option<Tcp>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub dscp: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub dscp_exclude: Vec<Flex>,
    pub fragment: Option<Fragment>,
    pub limit: Option<Limit>,
    #[serde(deserialize_with = "de_presence")]
    pub log: bool,
    pub log_options: Option<LogOptions>,
    pub mark: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub connection_mark: Vec<Flex>,
    pub connection_status: Option<ConnStatus>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub packet_length: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub packet_length_exclude: Vec<Flex>,
    pub packet_type: Option<Flex>,
    pub queue: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub queue_options: Vec<Flex>,
    pub recent: Option<Recent>,
    pub time: Option<TimeMatch>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Endpoint {
    pub address: Option<Flex>,
    pub address_mask: Option<Flex>,
    pub mac_address: Option<Flex>,
    pub port: Option<Flex>,
    pub group: Option<GroupRef>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct GroupRef {
    pub address_group: Option<Flex>,
    pub network_group: Option<Flex>,
    pub port_group: Option<Flex>,
    pub mac_group: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct IfMatch {
    pub name: Option<Flex>,
    pub group: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Icmp {
    pub code: Option<Flex>,
    #[serde(rename = "type")]
    pub icmp_type: Option<Flex>,
    pub type_name: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Cmp {
    pub eq: Option<Flex>,
    pub gt: Option<Flex>,
    pub lt: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Tcp {
    pub flags: Option<TcpFlags>,
    pub mss: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct TcpFlags {
    #[serde(deserialize_with = "de_presence")]
    pub syn: bool,
    #[serde(deserialize_with = "de_presence")]
    pub ack: bool,
    #[serde(deserialize_with = "de_presence")]
    pub fin: bool,
    #[serde(deserialize_with = "de_presence")]
    pub rst: bool,
    #[serde(deserialize_with = "de_presence")]
    pub urg: bool,
    #[serde(deserialize_with = "de_presence")]
    pub psh: bool,
    #[serde(deserialize_with = "de_presence")]
    pub ecn: bool,
    #[serde(deserialize_with = "de_presence")]
    pub cwr: bool,
    pub not: Option<TcpFlagsNot>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct TcpFlagsNot {
    #[serde(deserialize_with = "de_presence")]
    pub syn: bool,
    #[serde(deserialize_with = "de_presence")]
    pub ack: bool,
    #[serde(deserialize_with = "de_presence")]
    pub fin: bool,
    #[serde(deserialize_with = "de_presence")]
    pub rst: bool,
    #[serde(deserialize_with = "de_presence")]
    pub urg: bool,
    #[serde(deserialize_with = "de_presence")]
    pub psh: bool,
    #[serde(deserialize_with = "de_presence")]
    pub ecn: bool,
    #[serde(deserialize_with = "de_presence")]
    pub cwr: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Fragment {
    #[serde(deserialize_with = "de_presence")]
    pub match_frag: bool,
    #[serde(deserialize_with = "de_presence")]
    pub match_non_frag: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Limit {
    pub rate: Option<Flex>,
    pub burst: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct LogOptions {
    pub level: Option<Flex>,
    pub group: Option<Flex>,
    pub snapshot_length: Option<Flex>,
    pub queue_threshold: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ConnStatus {
    pub nat: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Recent {
    pub count: Option<Flex>,
    pub time: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct TimeMatch {
    pub startdate: Option<Flex>,
    pub starttime: Option<Flex>,
    pub stopdate: Option<Flex>,
    pub stoptime: Option<Flex>,
    pub weekdays: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct GlobalOptions {
    pub state_policy: Option<StatePolicy>,
    // The sysctl-style toggles and conntrack timeouts also live here
    // in the schema; they are parsed leniently (unknown keys ignored)
    // and not applied yet.
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct StatePolicy {
    pub established: Option<StatePolicyEntry>,
    pub invalid: Option<StatePolicyEntry>,
    pub related: Option<StatePolicyEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct StatePolicyEntry {
    pub action: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub log: bool,
    pub log_level: Option<Flex>,
}

// ---------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------

const TABLE: &str = "zebra_firewall";

#[derive(Clone, Copy, PartialEq)]
enum Fam {
    V4,
    V6,
}

impl Fam {
    fn ip(self) -> &'static str {
        match self {
            Fam::V4 => "ip",
            Fam::V6 => "ip6",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Fam::V4 => "ipv4",
            Fam::V6 => "ipv6",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Fam::V4 => "",
            Fam::V6 => "6",
        }
    }
}

/// A single-token value embedded unquoted in the script. Covers
/// addresses, prefixes, ranges, service names, rates (`5/minute`),
/// marks and negations — and refuses anything that could splice nft
/// syntax (whitespace, quotes, braces, semicolons).
fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-/*!&=,".contains(c))
}

/// Chain/set name fragments (group names, custom chain names).
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

struct Render {
    out: String,
    warnings: Vec<String>,
    /// RECENT set names to declare in the current table.
    recent_sets: Vec<String>,
    /// Any rule in the current table used `fragment` — emit the
    /// frag-mark helper chain.
    need_frag_mark: bool,
}

impl Render {
    fn new() -> Self {
        Self {
            out: String::new(),
            warnings: Vec::new(),
            recent_sets: Vec::new(),
            need_frag_mark: false,
        }
    }

    fn line(&mut self, indent: usize, s: &str) {
        for _ in 0..indent {
            self.out.push_str("    ");
        }
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn warn(&mut self, msg: String) {
        self.warnings.push(msg);
    }
}

/// Parse the subtree JSON and render the full nftables script. The
/// event loop parses and renders in separate steps (it retains the
/// model for show); this combined form serves the test suites here
/// and in config::manager.
#[cfg(test)]
pub fn render_str(json: &str) -> anyhow::Result<(String, Vec<String>)> {
    let cfg: FirewallConfig =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("firewall config JSON: {e}"))?;
    Ok(render(&cfg))
}

pub fn render(cfg: &FirewallConfig) -> (String, Vec<String>) {
    let mut r = Render::new();

    // add+delete makes the delete infallible; with a redefinition
    // following (or not, when the config is gone) the whole script is
    // one atomic replace/teardown per `nft -f` transaction.
    for ip in ["ip", "ip6"] {
        r.line(0, &format!("add table {ip} {TABLE}"));
        r.line(0, &format!("delete table {ip} {TABLE}"));
    }
    if cfg.is_empty() {
        return (r.out, r.warnings);
    }

    render_table(&mut r, cfg, Fam::V4);
    render_table(&mut r, cfg, Fam::V6);

    (r.out, r.warnings)
}

fn render_table(r: &mut Render, cfg: &FirewallConfig, fam: Fam) {
    r.recent_sets.clear();
    r.need_frag_mark = false;

    r.line(0, &format!("table {} {TABLE} {{", fam.ip()));

    if let Some(groups) = &cfg.group {
        render_group_sets(r, groups, fam);
    }

    let family = match fam {
        Fam::V4 => cfg.ipv4.as_ref(),
        Fam::V6 => cfg.ipv6.as_ref(),
    };
    let state_policy = cfg
        .global_options
        .as_ref()
        .and_then(|g| g.state_policy.as_ref());

    if let Some(f) = family {
        let base = [
            (&f.forward, "forward", "filter", "FWD"),
            (&f.input, "input", "filter", "INP"),
            (&f.output, "output", "filter", "OUT"),
            (&f.output, "output", "raw", "OUT"),
            (&f.prerouting, "prerouting", "raw", "PRE"),
        ];
        for (hook, hook_kw, prior, code) in base {
            let Some(hook) = hook else { continue };
            let chain = match prior {
                "filter" => hook.filter.as_ref(),
                _ => hook.raw.as_ref(),
            };
            let Some(chain) = chain else { continue };
            let chain_name = format!("ZEBRA_{}_{prior}", hook_kw.to_uppercase());
            r.line(1, &format!("chain {chain_name} {{"));
            r.line(
                2,
                &format!("type filter hook {hook_kw} priority {prior}; policy accept;"),
            );
            // VyOS jumps every base *filter* chain through the global
            // state-policy chain when one is configured.
            if prior == "filter" && state_policy.is_some() {
                r.line(2, "jump ZEBRA_STATE_POLICY");
            }
            render_rules(r, &chain.rule, fam, code, prior);
            render_default_rule(r, chain, fam, &format!("{code}-{prior}"), true);
            r.line(1, "}");
        }
        for custom in &f.name {
            let Some(name) = &custom.name else { continue };
            let name = name.to_string();
            if !safe_name(&name) {
                r.warn(format!("{} chain name {name:?} skipped", fam.label()));
                continue;
            }
            r.line(1, &format!("chain NAME{}_{name} {{", fam.suffix()));
            render_rules(r, &custom.rule, fam, "NAM", &name);
            render_default_rule(r, &custom.as_chain(), fam, &name, false);
            r.line(1, "}");
        }
    }

    if r.need_frag_mark {
        let (chain, match_expr) = match fam {
            Fam::V4 => ("ZEBRA_FRAG_MARK", "ip frag-off & 0x3fff != 0"),
            Fam::V6 => ("ZEBRA_FRAG6_MARK", "exthdr frag exists"),
        };
        r.line(1, &format!("chain {chain} {{"));
        r.line(
            2,
            "type filter hook prerouting priority -450; policy accept;",
        );
        r.line(2, &format!("{match_expr} meta mark set 0xffff1 return"));
        r.line(1, "}");
    }

    if let Some(policy) = state_policy {
        r.line(1, "chain ZEBRA_STATE_POLICY {");
        let states = [
            (&policy.established, "established"),
            (&policy.invalid, "invalid"),
            (&policy.related, "related"),
        ];
        for (entry, state) in states {
            let Some(entry) = entry else { continue };
            let mut parts = vec![format!("ct state {state}")];
            let action = entry
                .action
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "accept".to_string());
            if entry.log {
                let st = state[..3].to_uppercase();
                let ac = action[..1].to_uppercase();
                parts.push(format!("log prefix \"[STATE-POLICY-{st}-{ac}]\""));
                if let Some(level) = &entry.log_level {
                    parts.push(format!("level {level}"));
                }
            }
            parts.push("counter".into());
            parts.push(action);
            r.line(2, &parts.join(" "));
        }
        r.line(2, "return");
        r.line(1, "}");
    }

    for set in std::mem::take(&mut r.recent_sets) {
        r.line(1, &format!("set {set} {{"));
        r.line(
            2,
            match fam {
                Fam::V4 => "type ipv4_addr",
                Fam::V6 => "type ipv6_addr",
            },
        );
        r.line(2, "size 65535");
        r.line(2, "flags dynamic");
        r.line(1, "}");
    }

    r.line(0, "}");
}

/// Named-set definitions for the static groups, VyOS naming: `A_`/
/// `A6_` address, `N_`/`N6_` network, `P_` port, `M_` mac, `I_`
/// interface. Port/mac/interface groups are family-agnostic and
/// emitted into both tables.
fn render_group_sets(r: &mut Render, groups: &Groups, fam: Fam) {
    struct SetKind<'a> {
        list: &'a [Group],
        all: &'a [Group],
        prefix: &'a str,
        set_type: &'a str,
        interval: bool,
        quote: bool,
        member: fn(&Group) -> &[Flex],
    }
    fn member_addr(g: &Group) -> &[Flex] {
        &g.address
    }
    fn member_net(g: &Group) -> &[Flex] {
        &g.network
    }
    fn member_port(g: &Group) -> &[Flex] {
        &g.port
    }
    fn member_if(g: &Group) -> &[Flex] {
        &g.interface
    }
    fn member_mac(g: &Group) -> &[Flex] {
        &g.mac_address
    }

    let (addr_type, addr_groups, addr_prefix, net_groups, net_prefix) = match fam {
        Fam::V4 => (
            "ipv4_addr",
            &groups.address_group,
            "A_",
            &groups.network_group,
            "N_",
        ),
        Fam::V6 => (
            "ipv6_addr",
            &groups.ipv6_address_group,
            "A6_",
            &groups.ipv6_network_group,
            "N6_",
        ),
    };

    let kinds = [
        SetKind {
            list: addr_groups,
            all: addr_groups,
            prefix: addr_prefix,
            set_type: addr_type,
            interval: true,
            quote: false,
            member: member_addr,
        },
        SetKind {
            list: net_groups,
            all: net_groups,
            prefix: net_prefix,
            set_type: addr_type,
            interval: true,
            quote: false,
            member: member_net,
        },
        SetKind {
            list: &groups.port_group,
            all: &groups.port_group,
            prefix: "P_",
            set_type: "inet_service",
            interval: true,
            quote: false,
            member: member_port,
        },
        SetKind {
            list: &groups.mac_group,
            all: &groups.mac_group,
            prefix: "M_",
            set_type: "ether_addr",
            interval: false,
            quote: false,
            member: member_mac,
        },
        SetKind {
            list: &groups.interface_group,
            all: &groups.interface_group,
            prefix: "I_",
            set_type: "ifname",
            interval: true,
            quote: true,
            member: member_if,
        },
    ];

    for kind in kinds {
        for group in kind.list {
            let Some(name) = &group.name else { continue };
            let name = name.to_string();
            if !safe_name(&name) {
                r.warn(format!("group name {name:?} skipped"));
                continue;
            }
            let mut elements = Vec::new();
            collect_members(
                r,
                group,
                kind.all,
                kind.member,
                kind.quote,
                &mut elements,
                &mut vec![name.clone()],
            );
            r.line(1, &format!("set {}{name} {{", kind.prefix));
            r.line(2, &format!("type {}", kind.set_type));
            if kind.interval {
                r.line(2, "flags interval");
            }
            if !elements.is_empty() {
                r.line(2, &format!("elements = {{ {} }}", elements.join(",")));
            }
            r.line(1, "}");
        }
    }
}

/// Flatten a group's members plus its `include`d peer groups
/// (cycle-safe, VyOS `nft_nested_group` equivalent).
fn collect_members(
    r: &mut Render,
    group: &Group,
    all: &[Group],
    member: fn(&Group) -> &[Flex],
    quote: bool,
    out: &mut Vec<String>,
    seen: &mut Vec<String>,
) {
    for m in member(group) {
        let m = m.to_string();
        if !safe_token(&m) {
            r.warn(format!("group member {m:?} skipped"));
            continue;
        }
        if quote {
            out.push(format!("\"{m}\""));
        } else {
            out.push(m);
        }
    }
    for inc in &group.include {
        let inc = inc.to_string();
        if seen.contains(&inc) {
            continue;
        }
        seen.push(inc.clone());
        if let Some(peer) = all
            .iter()
            .find(|g| g.name.as_ref().is_some_and(|n| n.to_string() == inc))
        {
            collect_members(r, peer, all, member, quote, out, seen);
        } else {
            r.warn(format!("group include {inc:?} not found"));
        }
    }
}

fn render_rules(r: &mut Render, rules: &[Rule], fam: Fam, hook: &str, label: &str) {
    let mut sorted: Vec<&Rule> = rules.iter().filter(|rule| !rule.disable).collect();
    sorted.sort_by_key(|rule| {
        rule.number
            .as_ref()
            .and_then(|n| n.to_string().parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    for rule in sorted {
        match render_rule(rule, fam, hook, label) {
            Ok((line, recent, frag)) => {
                if let Some(set) = recent {
                    r.recent_sets.push(set);
                }
                r.need_frag_mark |= frag;
                r.line(2, &line);
            }
            Err(err) => {
                let num = rule
                    .number
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                r.warn(format!(
                    "{} {hook}-{label} rule {num}: {err} — rule skipped",
                    fam.label()
                ));
            }
        }
    }
}

/// The chain-tail default rule (VyOS `nft_default_rule`). Base chains
/// default to accept, custom chains to drop.
fn render_default_rule(r: &mut Render, chain: &Chain, fam: Fam, label: &str, base: bool) {
    let action = chain
        .default_action
        .as_ref()
        .map(|a| a.to_string())
        .unwrap_or_else(|| if base { "accept" } else { "drop" }.to_string());
    let mut parts = vec!["counter".to_string()];
    if chain.default_log {
        let short: String = label.chars().take(19).collect();
        let ac = action[..1].to_uppercase();
        parts.push(format!(
            "log prefix \"[{}-{short}-default-{ac}]\"",
            fam.label()
        ));
    }
    parts.push(action.clone());
    if action == "jump" {
        match &chain.default_jump_target {
            Some(target) if safe_name(&target.to_string()) => {
                parts.push(format!("NAME{}_{target}", fam.suffix()));
            }
            _ => {
                r.warn(format!(
                    "{} {label}: default-action jump without valid default-jump-target — using drop",
                    fam.label()
                ));
                parts.pop();
                parts.push("drop".to_string());
            }
        }
    }
    parts.push(format!("comment \"{label} default-action {action}\""));
    r.line(2, &parts.join(" "));
}

/// Render one rule to a single nft rule line. Follows the matcher
/// order of VyOS `parse_rule`. Returns the line plus an optional
/// RECENT set to declare and whether the frag-mark chain is needed.
fn render_rule(
    rule: &Rule,
    fam: Fam,
    hook: &str,
    label: &str,
) -> Result<(String, Option<String>, bool), String> {
    let mut out: Vec<String> = Vec::new();
    let mut recent_set = None;
    let mut need_frag = false;
    let ip = fam.ip();
    let rule_id = rule
        .number
        .as_ref()
        .map(|n| n.to_string())
        .unwrap_or_default();

    let tok = |v: &Flex, what: &str| -> Result<String, String> {
        let s = v.to_string();
        if safe_token(&s) {
            Ok(s)
        } else {
            Err(format!("unsafe {what} value {s:?}"))
        }
    };

    if !rule.state.is_empty() {
        let states: Vec<String> = rule.state.iter().map(|s| s.to_string()).collect();
        out.push(format!("ct state {{{}}}", states.join(",")));
    }

    if let Some(status) = &rule.connection_status
        && let Some(nat) = &status.nat
    {
        match nat.to_string().as_str() {
            "destination" => out.push("ct status dnat".into()),
            "source" => out.push("ct status snat".into()),
            other => return Err(format!("connection-status nat {other:?}")),
        }
    }

    let mut proto_for_port = String::from("th");
    if let Some(protocol) = &rule.protocol {
        let mut proto = tok(protocol, "protocol")?;
        if proto != "all" {
            let mut op = "";
            if let Some(stripped) = proto.strip_prefix('!') {
                op = "!= ";
                proto = stripped.to_string();
            }
            if proto == "tcp_udp" {
                out.push(format!("meta l4proto {op}{{tcp, udp}}"));
            } else {
                out.push(format!("meta l4proto {op}{proto}"));
            }
        }
        if proto != "tcp_udp" && proto != "all" {
            proto_for_port = proto;
        }
    }

    // VyOS iterates destination before source.
    for (side, pfx) in [(&rule.destination, 'd'), (&rule.source, 's')] {
        let Some(side) = side else { continue };
        let mask = match &side.address_mask {
            Some(m) => Some(tok(m, "address-mask")?),
            None => None,
        };
        if let Some(address) = &side.address {
            let mut addr = tok(address, "address")?;
            let exclude = addr.starts_with('!');
            if exclude {
                addr = addr[1..].to_string();
            }
            let operator = match (&mask, exclude) {
                (Some(m), false) => format!("& {m} == "),
                (Some(m), true) => format!("& {m} != "),
                (None, true) => "!= ".to_string(),
                (None, false) => String::new(),
            };
            out.push(format!("{ip} {pfx}addr {operator}{addr}"));
        }
        if let Some(mac) = &side.mac_address {
            let mut mac = tok(mac, "mac-address")?;
            if let Some(stripped) = mac.strip_prefix('!') {
                mac = format!("!= {stripped}");
            }
            out.push(format!("ether {pfx}addr {mac}"));
        }
        if let Some(port) = &side.port {
            let port = tok(port, "port")?;
            let mut ports = Vec::new();
            let mut negated = Vec::new();
            for p in port.split(',') {
                match p.strip_prefix('!') {
                    Some(stripped) => negated.push(stripped.to_string()),
                    None => ports.push(p.to_string()),
                }
            }
            if !ports.is_empty() {
                out.push(format!(
                    "{proto_for_port} {pfx}port {{{}}}",
                    ports.join(",")
                ));
            }
            if !negated.is_empty() {
                out.push(format!(
                    "{proto_for_port} {pfx}port != {{{}}}",
                    negated.join(",")
                ));
            }
        }
        if let Some(group) = &side.group {
            let mut group_ref =
                |name: &Option<Flex>, set_prefix: &str, expr: &str| -> Result<(), String> {
                    let Some(name) = name else { return Ok(()) };
                    let mut name = name.to_string();
                    let mut op = "";
                    if let Some(stripped) = name.strip_prefix('!') {
                        op = "!= ";
                        name = stripped.to_string();
                    }
                    if !safe_name(&name) {
                        return Err(format!("group reference {name:?}"));
                    }
                    out.push(format!("{expr} {op}@{set_prefix}{name}"));
                    Ok(())
                };
            group_ref(
                &group.address_group,
                &format!("A{}_", fam.suffix()),
                &format!("{ip} {pfx}addr"),
            )?;
            group_ref(
                &group.network_group,
                &format!("N{}_", fam.suffix()),
                &format!("{ip} {pfx}addr"),
            )?;
            group_ref(&group.mac_group, "M_", &format!("ether {pfx}addr"))?;
            group_ref(
                &group.port_group,
                "P_",
                &format!("{proto_for_port} {pfx}port"),
            )?;
        }
    }

    if fam == Fam::V6
        && let Some(hop_limit) = &rule.hop_limit
    {
        for (field, op) in [
            (&hop_limit.eq, "=="),
            (&hop_limit.gt, ">"),
            (&hop_limit.lt, "<"),
        ] {
            if let Some(v) = field {
                out.push(format!("ip6 hoplimit {op} {}", tok(v, "hop-limit")?));
            }
        }
    }

    for (ifmatch, kw) in [
        (&rule.inbound_interface, "iifname"),
        (&rule.outbound_interface, "oifname"),
    ] {
        let Some(ifmatch) = ifmatch else { continue };
        if let Some(name) = &ifmatch.name {
            let mut name = tok(name, "interface")?;
            let mut op = "";
            if let Some(stripped) = name.strip_prefix('!') {
                op = "!= ";
                name = stripped.to_string();
            }
            out.push(format!("{kw} {op}\"{name}\""));
        } else if let Some(group) = &ifmatch.group {
            let mut name = group.to_string();
            let mut op = "";
            if let Some(stripped) = name.strip_prefix('!') {
                op = "!= ";
                name = stripped.to_string();
            }
            if !safe_name(&name) {
                return Err(format!("interface-group reference {name:?}"));
            }
            out.push(format!("{kw} {op}@I_{name}"));
        }
    }

    if fam == Fam::V4
        && let Some(ttl) = &rule.ttl
    {
        for (field, op) in [(&ttl.eq, "=="), (&ttl.gt, ">"), (&ttl.lt, "<")] {
            if let Some(v) = field {
                out.push(format!("ip ttl {op} {}", tok(v, "ttl")?));
            }
        }
    }

    let icmp = match fam {
        Fam::V4 => rule.icmp.as_ref().map(|i| ("icmp", i)),
        Fam::V6 => rule.icmpv6.as_ref().map(|i| ("icmpv6", i)),
    };
    if let Some((kw, icmp)) = icmp {
        if let Some(type_name) = &icmp.type_name {
            out.push(format!("{kw} type {}", tok(type_name, "icmp type-name")?));
        } else {
            if let Some(code) = &icmp.code {
                out.push(format!("{kw} code {}", tok(code, "icmp code")?));
            }
            if let Some(icmp_type) = &icmp.icmp_type {
                out.push(format!("{kw} type {}", tok(icmp_type, "icmp type")?));
            }
        }
    }

    let joined = |items: &[Flex]| -> Result<String, String> {
        let toks: Result<Vec<String>, String> = items.iter().map(|v| tok(v, "value")).collect();
        Ok(toks?.join(","))
    };
    if !rule.packet_length.is_empty() {
        out.push(format!("{ip} length {{{}}}", joined(&rule.packet_length)?));
    }
    if !rule.packet_length_exclude.is_empty() {
        out.push(format!(
            "{ip} length != {{{}}}",
            joined(&rule.packet_length_exclude)?
        ));
    }
    if let Some(packet_type) = &rule.packet_type {
        out.push(format!("pkttype {}", tok(packet_type, "packet-type")?));
    }
    if !rule.dscp.is_empty() {
        out.push(format!("{ip} dscp {{{}}}", joined(&rule.dscp)?));
    }
    if !rule.dscp_exclude.is_empty() {
        out.push(format!("{ip} dscp != {{{}}}", joined(&rule.dscp_exclude)?));
    }

    if let Some(fragment) = &rule.fragment {
        if fragment.match_frag {
            out.push("meta mark 0xffff1".into());
            need_frag = true;
        }
        if fragment.match_non_frag {
            out.push("meta mark != 0xffff1".into());
            need_frag = true;
        }
    }

    if let Some(limit) = &rule.limit
        && let Some(rate) = &limit.rate
    {
        out.push(format!("limit rate {}", tok(rate, "limit rate")?));
        if let Some(burst) = &limit.burst {
            out.push(format!("burst {} packets", tok(burst, "limit burst")?));
        }
    }

    if let Some(recent) = &rule.recent
        && let (Some(count), Some(time)) = (&recent.count, &recent.time)
    {
        let count = tok(count, "recent count")?;
        let time = tok(time, "recent time")?;
        let set = format!("RECENT{}_{hook}_{label}_{rule_id}", fam.suffix());
        out.push(format!(
            "add @{set} {{ {ip} saddr limit rate over {count}/{time} burst {count} packets }}"
        ));
        recent_set = Some(set);
    }

    if let Some(time) = &rule.time {
        out.push(render_time(time)?);
    }

    if let Some(tcp) = &rule.tcp {
        if let Some(flags) = &tcp.flags {
            out.push(render_tcp_flags(flags));
        }
        if let Some(mss) = &tcp.mss {
            out.push(format!("tcp option maxseg size {}", tok(mss, "tcp mss")?));
        }
    }

    if !rule.connection_mark.is_empty() {
        out.push(format!("ct mark {{{}}}", joined(&rule.connection_mark)?));
    }

    if let Some(mark) = &rule.mark {
        let mut mark = tok(mark, "mark")?;
        let mut op = "";
        if let Some(stripped) = mark.strip_prefix('!') {
            op = "!= ";
            mark = stripped.to_string();
        }
        out.push(format!("meta mark {op}{{{mark}}}"));
    }

    let action = rule.action.as_ref().map(|a| a.to_string());
    if rule.log {
        let ac = action.as_deref().unwrap_or("accept")[..1].to_uppercase();
        out.push(format!(
            "log prefix \"[{}-{hook}-{label}-{rule_id}-{ac}]\"",
            fam.label()
        ));
        if let Some(opts) = &rule.log_options {
            if let Some(level) = &opts.level {
                out.push(format!("log level {}", tok(level, "log level")?));
            }
            if let Some(group) = &opts.group {
                out.push(format!("log group {}", tok(group, "log group")?));
                if let Some(threshold) = &opts.queue_threshold {
                    out.push(format!(
                        "queue-threshold {}",
                        tok(threshold, "queue-threshold")?
                    ));
                }
                if let Some(snaplen) = &opts.snapshot_length {
                    out.push(format!("snaplen {}", tok(snaplen, "snaplen")?));
                }
            }
        }
    }

    out.push("counter".into());

    if let Some(action) = &action {
        match action.as_str() {
            "jump" => {
                let Some(target) = &rule.jump_target else {
                    return Err("action jump without jump-target".to_string());
                };
                let target = target.to_string();
                if !safe_name(&target) {
                    return Err(format!("jump-target {target:?}"));
                }
                out.push(format!("jump NAME{}_{target}", fam.suffix()));
            }
            "queue" => {
                // Canonical nft spelling (`queue [flags …] [to N]`);
                // VyOS emits the legacy `queue num N opts` order.
                out.push("queue".into());
                if !rule.queue_options.is_empty() {
                    out.push(format!("flags {}", joined(&rule.queue_options)?));
                }
                if let Some(num) = &rule.queue {
                    out.push(format!("to {}", tok(num, "queue")?));
                }
            }
            "accept" | "continue" | "drop" | "reject" | "return" | "notrack" => {
                out.push(action.clone());
            }
            other => return Err(format!("action {other:?} not supported")),
        }
    }

    out.push(format!(
        "comment \"{}-{hook}-{label}-{rule_id}\"",
        fam.label()
    ));

    Ok((out.join(" "), recent_set, need_frag))
}

/// VyOS `parse_tcp_flags`: mask is every mentioned flag, value the
/// must-be-set ones.
fn render_tcp_flags(flags: &TcpFlags) -> String {
    let names = ["syn", "ack", "fin", "rst", "urg", "psh", "ecn", "cwr"];
    let set = [
        flags.syn, flags.ack, flags.fin, flags.rst, flags.urg, flags.psh, flags.ecn, flags.cwr,
    ];
    let not = flags.not.as_ref();
    let unset = not.map_or([false; 8], |n| {
        [n.syn, n.ack, n.fin, n.rst, n.urg, n.psh, n.ecn, n.cwr]
    });

    let include: Vec<&str> = names
        .iter()
        .zip(set.iter())
        .filter(|(_, on)| **on)
        .map(|(n, _)| *n)
        .collect();
    let exclude: Vec<&str> = names
        .iter()
        .zip(unset.iter())
        .filter(|(_, on)| **on)
        .map(|(n, _)| *n)
        .collect();

    let mask: Vec<&str> = include.iter().chain(exclude.iter()).copied().collect();
    let value = if include.is_empty() {
        "0x0".to_string()
    } else {
        include.join("|")
    };
    format!("tcp flags & ({}) == {value}", mask.join("|"))
}

/// VyOS `parse_time`. Date+time pairs merge into one quoted `time`
/// bound; lone times use `hour`; weekdays become a `day` set.
fn render_time(time: &TimeMatch) -> Result<String, String> {
    let quoted_ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || " :-.".contains(c))
    };
    let mut out = Vec::new();
    let get = |v: &Option<Flex>| v.as_ref().map(|f| f.to_string());

    let startdate = get(&time.startdate);
    let starttime = get(&time.starttime);
    let stopdate = get(&time.stopdate);
    let stoptime = get(&time.stoptime);

    if let Some(mut start) = startdate.clone() {
        if !start.contains('T')
            && let Some(st) = &starttime
        {
            start = format!("{start} {st}");
        }
        if !quoted_ok(&start) {
            return Err(format!("time startdate {start:?}"));
        }
        out.push(format!("time >= \"{start}\""));
    } else if let Some(st) = &starttime {
        if !quoted_ok(st) {
            return Err(format!("time starttime {st:?}"));
        }
        out.push(format!("hour >= \"{st}\""));
    }
    if let Some(mut stop) = stopdate.clone() {
        if !stop.contains('T')
            && let Some(st) = &stoptime
        {
            stop = format!("{stop} {st}");
        }
        if !quoted_ok(&stop) {
            return Err(format!("time stopdate {stop:?}"));
        }
        out.push(format!("time < \"{stop}\""));
    } else if let Some(st) = &stoptime {
        if !quoted_ok(st) {
            return Err(format!("time stoptime {st:?}"));
        }
        out.push(format!("hour < \"{st}\""));
    }
    if let Some(weekdays) = get(&time.weekdays) {
        let days: Vec<String> = weekdays
            .split(',')
            .filter(|d| !d.starts_with('!') && !d.is_empty())
            .map(|d| format!("\"{d}\""))
            .collect();
        if !quoted_ok(&weekdays) {
            return Err(format!("time weekdays {weekdays:?}"));
        }
        if !days.is_empty() {
            out.push(format!("day {{{}}}", days.join(",")));
        }
    }
    Ok(out.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Presence leaves arrive as `"name": null`; numeric-looking
    /// values arrive as JSON numbers. Both must deserialize.
    #[test]
    fn model_deserializes_config_json_shapes() {
        let json = r#"{
            "group": {"address-group": [
                {"name": "SERVERS", "address": ["10.0.0.1", "10.0.0.2-10.0.0.5"]},
                {"name": 123, "address": "10.1.1.1"}
            ]},
            "ipv4": {"forward": {"filter": {
                "default-action": "drop",
                "default-log": null,
                "rule": [
                    {"number": 10, "action": "accept",
                     "state": ["established", "related"],
                     "tcp": {"flags": {"syn": null, "not": {"ack": null}}},
                     "fragment": {},
                     "source": {"port": 443},
                     "log": null}
                ]
            }}}
        }"#;
        let cfg: FirewallConfig = serde_json::from_str(json).expect("deserializes");
        let groups = cfg.group.expect("groups");
        assert_eq!(groups.address_group.len(), 2);
        assert_eq!(groups.address_group[0].address.len(), 2);
        // Numeric group name and scalar (non-array) leaf-list tolerated.
        assert_eq!(
            groups.address_group[1].name.as_ref().unwrap().to_string(),
            "123"
        );
        assert_eq!(groups.address_group[1].address.len(), 1);

        let chain = cfg.ipv4.unwrap().forward.unwrap().filter.unwrap();
        assert!(chain.default_log, "default-log null means present");
        let rule = &chain.rule[0];
        assert!(rule.log);
        assert!(!rule.disable, "absent presence leaf stays false");
        let flags = rule.tcp.as_ref().unwrap().flags.as_ref().unwrap();
        assert!(flags.syn && flags.not.as_ref().unwrap().ack);
        assert_eq!(
            rule.source
                .as_ref()
                .unwrap()
                .port
                .as_ref()
                .unwrap()
                .to_string(),
            "443"
        );
    }

    /// The empty subtree (`"{}"` from the manager after a full
    /// delete) renders the teardown-only script.
    #[test]
    fn empty_config_renders_teardown() {
        let (script, warnings) = render_str("{}").expect("renders");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(
            script,
            "add table ip zebra_firewall\n\
             delete table ip zebra_firewall\n\
             add table ip6 zebra_firewall\n\
             delete table ip6 zebra_firewall\n"
        );
    }

    /// Golden render of a small but representative config: groups,
    /// a base chain with state/group/port/log rules, a custom chain
    /// with a jump, and global state-policy.
    #[test]
    fn golden_render() {
        let json = r#"{
            "group": {
                "address-group": [{"name": "SERVERS", "address": ["10.0.0.1", "10.0.0.2-10.0.0.5"]}],
                "port-group": [{"name": "WEB", "port": [80, 443, "8000-8080"]}],
                "interface-group": [{"name": "WAN", "interface": ["eth0", "ppp*"]}]
            },
            "ipv4": {
                "forward": {"filter": {
                    "default-action": "drop",
                    "default-log": null,
                    "rule": [
                        {"number": 10, "action": "accept", "state": ["established", "related"]},
                        {"number": 20, "action": "jump", "jump-target": "WEB-IN",
                         "protocol": "tcp",
                         "destination": {"group": {"address-group": "SERVERS", "port-group": "WEB"}},
                         "inbound-interface": {"group": "WAN"}},
                        {"number": 30, "action": "drop", "protocol": "!icmp", "log": null}
                    ]
                }}
            },
            "ipv6": {
                "input": {"filter": {
                    "rule": [
                        {"number": 5, "action": "accept", "icmpv6": {"type-name": "nd-router-advert"},
                         "hop-limit": {"eq": 255}}
                    ]
                }}
            },
            "name-unused": null,
            "global-options": {
                "state-policy": {
                    "established": {"action": "accept"},
                    "invalid": {"action": "drop", "log": null}
                }
            }
        }"#;
        // ^ "name-unused" pins that unknown keys are ignored, so schema
        // growth does not break older backends.

        let (script, warnings) = render_str(json).expect("renders");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");

        let expected = "\
add table ip zebra_firewall
delete table ip zebra_firewall
add table ip6 zebra_firewall
delete table ip6 zebra_firewall
table ip zebra_firewall {
    set A_SERVERS {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.1,10.0.0.2-10.0.0.5 }
    }
    set P_WEB {
        type inet_service
        flags interval
        elements = { 80,443,8000-8080 }
    }
    set I_WAN {
        type ifname
        flags interval
        elements = { \"eth0\",\"ppp*\" }
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        jump ZEBRA_STATE_POLICY
        ct state {established,related} counter accept comment \"ipv4-FWD-filter-10\"
        meta l4proto tcp ip daddr @A_SERVERS tcp dport @P_WEB iifname @I_WAN counter jump NAME_WEB-IN comment \"ipv4-FWD-filter-20\"
        meta l4proto != icmp log prefix \"[ipv4-FWD-filter-30-D]\" counter drop comment \"ipv4-FWD-filter-30\"
        counter log prefix \"[ipv4-FWD-filter-default-D]\" drop comment \"FWD-filter default-action drop\"
    }
    chain ZEBRA_STATE_POLICY {
        ct state established counter accept
        ct state invalid log prefix \"[STATE-POLICY-INV-D]\" counter drop
        return
    }
}
table ip6 zebra_firewall {
    set P_WEB {
        type inet_service
        flags interval
        elements = { 80,443,8000-8080 }
    }
    set I_WAN {
        type ifname
        flags interval
        elements = { \"eth0\",\"ppp*\" }
    }
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        jump ZEBRA_STATE_POLICY
        ip6 hoplimit == 255 icmpv6 type nd-router-advert counter accept comment \"ipv6-INP-filter-5\"
        counter accept comment \"INP-filter default-action accept\"
    }
    chain ZEBRA_STATE_POLICY {
        ct state established counter accept
        ct state invalid log prefix \"[STATE-POLICY-INV-D]\" counter drop
        return
    }
}
";
        assert_eq!(script, expected);
    }

    /// Raw-hook specifics: notrack action, prerouting chain shape,
    /// fragment matcher pulling in the frag-mark helper chain, and a
    /// disabled rule dropping out.
    #[test]
    fn raw_hooks_and_fragment() {
        let json = r#"{
            "ipv4": {
                "prerouting": {"raw": {
                    "rule": [
                        {"number": 10, "action": "notrack", "protocol": "udp"},
                        {"number": 20, "action": "drop", "fragment": {"match-frag": null}},
                        {"number": 30, "action": "drop", "disable": null}
                    ]
                }},
                "output": {"raw": {
                    "default-action": "accept",
                    "rule": [{"number": 1, "action": "accept", "recent": {"count": 3, "time": "minute"}}]
                }}
            }
        }"#;
        let (script, warnings) = render_str(json).expect("renders");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");

        assert!(script.contains(
            "chain ZEBRA_PREROUTING_raw {\n        type filter hook prerouting priority raw; policy accept;"
        ));
        assert!(script.contains("meta l4proto udp counter notrack comment \"ipv4-PRE-raw-10\""));
        assert!(script.contains("meta mark 0xffff1 counter drop comment \"ipv4-PRE-raw-20\""));
        assert!(
            !script.contains("ipv4-PRE-raw-30"),
            "disabled rule must not render"
        );
        assert!(script.contains("chain ZEBRA_FRAG_MARK {"));
        assert!(script.contains("ip frag-off & 0x3fff != 0 meta mark set 0xffff1 return"));
        // Raw chains never jump through state policy (none configured
        // here anyway), and the recent rule declares its dynamic set.
        assert!(script.contains(
            "add @RECENT_OUT_raw_1 { ip saddr limit rate over 3/minute burst 3 packets }"
        ));
        assert!(script.contains("set RECENT_OUT_raw_1 {\n        type ipv4_addr"));
    }

    /// A rule the renderer cannot express safely is skipped with a
    /// warning; the rest of the ruleset still renders.
    #[test]
    fn unsafe_rule_skipped_with_warning() {
        let json = r#"{
            "ipv4": {"input": {"filter": {
                "rule": [
                    {"number": 10, "action": "jump"},
                    {"number": 20, "action": "accept"}
                ]
            }}}
        }"#;
        let (script, warnings) = render_str(json).expect("renders");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("rule 10"), "warnings: {warnings:?}");
        assert!(!script.contains("ipv4-INP-filter-10"));
        assert!(script.contains("counter accept comment \"ipv4-INP-filter-20\""));
    }

    /// `nft --json list table` output → comment-keyed counters. Rules
    /// without a comment are ignored; non-rule objects are skipped.
    #[test]
    fn parse_counters_from_nft_json() {
        let value = serde_json::json!({
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {"table": {"family": "ip", "name": "zebra_firewall"}},
                {"rule": {"family": "ip", "comment": "ipv4-FWD-filter-10",
                          "expr": [{"match": {}},
                                   {"counter": {"packets": 42, "bytes": 4200}},
                                   {"accept": null}]}},
                {"rule": {"family": "ip", "comment": "FWD-filter default-action drop",
                          "expr": [{"counter": {"packets": 7, "bytes": 700}},
                                   {"drop": null}]}},
                {"rule": {"family": "ip",
                          "expr": [{"counter": {"packets": 1, "bytes": 1}}]}}
            ]
        });
        let counters = parse_counters(&value);
        assert_eq!(counters.get("ipv4-FWD-filter-10"), Some(&(42, 4200)));
        assert_eq!(
            counters.get("FWD-filter default-action drop"),
            Some(&(7, 700))
        );
        assert_eq!(counters.len(), 2, "uncommented rule contributes nothing");
    }

    fn show_fixture() -> FirewallConfig {
        let json = r#"{
            "group": {"address-group": [
                {"name": "SERVERS", "address": ["10.0.0.1", "10.0.0.2-10.0.0.5"]}
            ]},
            "ipv4": {
                "forward": {"filter": {
                    "default-action": "drop",
                    "default-log": null,
                    "rule": [
                        {"number": 10, "action": "accept", "state": ["established", "related"]},
                        {"number": 20, "action": "drop", "protocol": "tcp",
                         "destination": {"group": {"address-group": "SERVERS"}}, "log": null}
                    ]
                }},
                "name": [
                    {"name": "WEB-IN", "default-action": "drop",
                     "rule": [{"number": 10, "action": "accept", "tcp": {"flags": {"syn": null}}}]}
                ]
            }
        }"#;
        serde_json::from_str(json).expect("fixture deserializes")
    }

    /// The chain tables join live counters onto config rules via the
    /// renderer's comment keys; the Conditions column reuses the real
    /// rule renderer with counter/action/log stripped.
    #[test]
    fn show_family_tables_with_counters() {
        let cfg = show_fixture();
        let mut counters = Counters::new();
        counters.insert("ipv4-FWD-filter-10".into(), (42, 4200));
        counters.insert("ipv4-FWD-filter-20".into(), (5, 500));
        counters.insert("FWD-filter default-action drop".into(), (7, 700));
        counters.insert("ipv4-NAM-WEB-IN-10".into(), (3, 300));

        let out = show_family_text(&cfg, Fam::V4, &counters, None);
        assert!(out.contains("ipv4 Firewall \"forward filter\""), "{out}");
        assert!(out.contains("ipv4 Firewall \"name WEB-IN\""), "{out}");
        for needle in [
            "ct state {established,related}",
            "ip daddr @A_SERVERS",
            "tcp flags & (syn) == syn",
        ] {
            assert!(out.contains(needle), "missing `{needle}` in:\n{out}");
        }
        // Counters landed on their rows.
        assert!(out.contains("42"), "{out}");
        assert!(out.contains("4200"), "{out}");
        assert!(out.contains("700"), "{out}");

        // Single-hook view filters to one chain.
        let single = show_family_text(&cfg, Fam::V4, &counters, Some("forward filter"));
        assert!(single.contains("forward filter"));
        assert!(!single.contains("WEB-IN"));
    }

    /// Groups view: members listed, references counted across every
    /// rule of every chain.
    #[test]
    fn show_groups_counts_references() {
        let cfg = show_fixture();
        let out = show_groups_text(&cfg);
        assert!(out.contains("SERVERS"), "{out}");
        assert!(out.contains("address-group"), "{out}");
        assert!(out.contains("10.0.0.2-10.0.0.5"), "{out}");
        // Rule 20 references SERVERS once.
        let line = out.lines().find(|l| l.contains("SERVERS")).unwrap();
        assert!(line.contains(" 1 "), "references column: {line}");
    }

    /// The JSON view carries the same joined data structurally.
    #[test]
    fn show_json_view() {
        let cfg = show_fixture();
        let mut counters = Counters::new();
        counters.insert("ipv4-FWD-filter-10".into(), (42, 4200));

        let v = show_json(&cfg, &counters, &Counters::new());
        assert_eq!(v["groups"][0]["name"], "SERVERS");
        assert_eq!(v["groups"][0]["references"], 1);
        let chains = v["ipv4"]["chains"].as_array().unwrap();
        assert_eq!(chains[0]["chain"], "forward filter");
        assert_eq!(chains[0]["defaultAction"], "drop");
        assert_eq!(chains[0]["rules"][0]["packets"], 42);
        assert_eq!(chains[0]["rules"][0]["bytes"], 4200);
        assert!(chains.iter().any(|c| c["chain"] == "name WEB-IN"));
    }
}
