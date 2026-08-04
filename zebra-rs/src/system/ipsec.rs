//! VyOS-compatible IPsec → strongSwan (swanctl) backend.
//!
//! Consumes the `/vpn/ipsec` config subtree as a JSON batch (see
//! `ConfigManager::subscribe_json`): every commit that touches the
//! subtree delivers the whole post-commit tree in one message. The
//! backend deserializes it into [`IpsecConfig`], renders a complete
//! `swanctl.conf` (connections, pools, secrets) and loads it with
//! `swanctl -q`, which declaratively loads the new state and unloads
//! anything no longer present — so a replace and a full teardown are
//! the same one-shot shape. This mirrors VyOS itself, which re-renders
//! `/etc/swanctl/swanctl.conf` from the config tree on every commit
//! (vyos-1x `data/templates/ipsec/swanctl.conf.j2` +
//! `swanctl/peer.j2`, which this renderer follows line for line where
//! it can, including the proposal-string builder from
//! `python/vyos/template.py get_esp_ike_cipher` and the
//! tunnel-overlap passthrough children from
//! `src/conf_mode/vpn_ipsec.py`).
//!
//! Deviations from VyOS, all deliberate:
//! - the config file lives under the [`Ipsec`] task's `conf_dir`
//!   (default `/etc/swanctl`, same as VyOS) and is loaded with
//!   `swanctl -q` + `SWANCTL_DIR`; charon's lifecycle is NOT managed
//!   — VyOS `reload-or-restart`s strongswan.service, zebra-rs expects
//!   a running charon and only warns when `swanctl` is unavailable;
//! - charon-level settings (`log`, `options`,
//!   `disable-uniqreqids`) render into strongswan.d config in VyOS
//!   and need a charon restart — not applied yet, noted in the log;
//! - `dhcp-interface` (local address learned from a DHCP lease) is
//!   not supported yet: VyOS excludes such peers until the lease
//!   exists, zebra-rs warns and skips them the same way;
//! - the per-id keys in psk secrets blocks are deterministic
//!   (`id-1`, `id-2`, …) where VyOS generates uuid4 suffixes — only
//!   uniqueness matters to swanctl.
//!
//! Anything the renderer cannot express safely is skipped with a
//! warning naming the peer or tunnel — a rendered file is always
//! syntactically valid swanctl.conf, so one bad peer cannot wedge the
//! whole commit.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::json::{Flex, de_flex_vec, de_presence};
use super::vici;
use crate::config::{DisplayRequest, JsonConfigUpdate, ShowChannel, path_from_command};

pub struct Ipsec {
    pub tx: UnboundedSender<JsonConfigUpdate>,
    rx: UnboundedReceiver<JsonConfigUpdate>,
    pub show: ShowChannel,
    conf_dir: PathBuf,
    vici_socket: PathBuf,
}

impl Ipsec {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            tx,
            rx,
            show: ShowChannel::new(),
            conf_dir: PathBuf::from("/etc/swanctl"),
            vici_socket: PathBuf::from("/var/run/charon.vici"),
        }
    }

    pub async fn event_loop(mut self) {
        loop {
            tokio::select! {
                Some(update) = self.rx.recv() => process(update, &self.conf_dir).await,
                Some(req) = self.show.rx.recv() => process_show(&self.vici_socket, req).await,
                else => break,
            }
        }
    }
}

impl Default for Ipsec {
    fn default() -> Self {
        Self::new()
    }
}

async fn process(update: JsonConfigUpdate, conf_dir: &Path) {
    tracing::debug!("ipsec: config update for /{}", update.path.join("/"));
    let cfg: IpsecConfig = match serde_json::from_str(&update.json) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!("ipsec: config parse failed: {err}");
            return;
        }
    };
    let (conf, warnings) = render(&cfg);
    for warn in &warnings {
        tracing::warn!("ipsec: {warn}");
    }
    match swanctl_apply(&conf, conf_dir).await {
        Ok(loaded) => {
            if loaded {
                tracing::info!("ipsec: swanctl configuration loaded");
            } else {
                tracing::warn!(
                    "ipsec: swanctl not available; configuration rendered to {} but not loaded",
                    conf_dir.join("swanctl.conf").display()
                );
            }
        }
        Err(err) => tracing::error!("ipsec: swanctl apply failed: {err}"),
    }
}

/// Write `swanctl.conf` (0600 — it holds secrets) and load it into
/// charon with `swanctl -q`. Returns `Ok(false)` when the swanctl
/// binary is missing: the rendered file is still in place, so a later
/// strongSwan install or manual `swanctl -q` picks it up.
async fn swanctl_apply(conf: &str, dir: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::create_dir_all(dir).await?;
    let tmp = dir.join("swanctl.conf.zebra-tmp");
    tokio::fs::write(&tmp, conf).await?;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    tokio::fs::rename(&tmp, dir.join("swanctl.conf")).await?;

    let output = match tokio::process::Command::new("swanctl")
        .arg("-q")
        .env("SWANCTL_DIR", dir)
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    if !output.status.success() {
        anyhow::bail!(
            "swanctl -q exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(true)
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
pub struct IpsecConfig {
    pub authentication: Option<Authentication>,
    #[serde(deserialize_with = "de_presence")]
    pub disable_uniqreqids: bool,
    pub esp_group: Vec<EspGroup>,
    pub ike_group: Vec<IkeGroup>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub interface: Vec<Flex>,
    pub log: Option<serde_json::Value>,
    pub options: Option<serde_json::Value>,
    pub site_to_site: Option<SiteToSite>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Authentication {
    pub psk: Vec<Psk>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Psk {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub dhcp_interface: Vec<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub id: Vec<Flex>,
    pub secret: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct EspGroup {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub compression: bool,
    pub lifetime: Option<Flex>,
    pub life_bytes: Option<Flex>,
    pub life_packets: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable_rekey: bool,
    pub mode: Option<String>,
    pub pfs: Option<String>,
    pub proposal: Vec<Proposal>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct IkeGroup {
    pub name: Option<Flex>,
    pub close_action: Option<String>,
    pub dead_peer_detection: Option<Dpd>,
    #[serde(deserialize_with = "de_presence")]
    pub ikev2_reauth: bool,
    pub key_exchange: Option<String>,
    pub lifetime: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable_mobike: bool,
    pub mode: Option<String>,
    pub proposal: Vec<Proposal>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Dpd {
    pub action: Option<String>,
    pub interval: Option<Flex>,
    pub timeout: Option<Flex>,
}

/// One proposal — shared by ESP (encryption/hash) and IKE
/// (encryption/hash/prf/dh-group) groups; the fields the other kind
/// lacks simply stay `None`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Proposal {
    pub number: Option<Flex>,
    pub encryption: Option<String>,
    pub hash: Option<String>,
    pub prf: Option<String>,
    pub dh_group: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SiteToSite {
    pub peer: Vec<Peer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Peer {
    pub name: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub authentication: Option<PeerAuth>,
    pub connection_type: Option<String>,
    pub default_esp_group: Option<Flex>,
    pub description: Option<Flex>,
    pub dhcp_interface: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub force_udp_encapsulation: bool,
    pub ike_group: Option<Flex>,
    pub ikev2_reauth: Option<String>,
    pub local_address: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub remote_address: Vec<Flex>,
    pub replay_window: Option<Flex>,
    pub tunnel: Vec<Tunnel>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub virtual_address: Vec<Flex>,
    pub vti: Option<Vti>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct PeerAuth {
    pub local_id: Option<Flex>,
    pub mode: Option<String>,
    pub remote_id: Option<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Tunnel {
    pub number: Option<Flex>,
    #[serde(deserialize_with = "de_presence")]
    pub disable: bool,
    pub esp_group: Option<Flex>,
    pub local: Option<Selector>,
    pub protocol: Option<Flex>,
    pub priority: Option<Flex>,
    pub remote: Option<Selector>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Selector {
    pub port: Option<Flex>,
    #[serde(deserialize_with = "de_flex_vec")]
    pub prefix: Vec<Flex>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Vti {
    pub bind: Option<Flex>,
    pub esp_group: Option<Flex>,
}

// ---------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------

/// VyOS XML `defaultValue`s the schema deliberately does not carry
/// (config.yang has no defaults machinery) — applied here, exactly
/// where VyOS's `get_config_dict(..., with_defaults)` would.
const DEFAULT_IKE_LIFETIME: &str = "28800";
const DEFAULT_ESP_LIFETIME: &str = "3600";
const DEFAULT_CLOSE_ACTION: &str = "none";
const DEFAULT_DPD_INTERVAL: &str = "30";
const DEFAULT_DPD_TIMEOUT: &str = "120";
const DEFAULT_REMOTE_ID: &str = "%any";
const DEFAULT_IKE_DH_GROUP: &str = "2";

/// `python/vyos/template.py` pfs_lut, verbatim.
fn dh_group_name(group: &str) -> Option<&'static str> {
    Some(match group {
        "1" => "modp768",
        "2" => "modp1024",
        "5" => "modp1536",
        "14" => "modp2048",
        "15" => "modp3072",
        "16" => "modp4096",
        "17" => "modp6144",
        "18" => "modp8192",
        "19" => "ecp256",
        "20" => "ecp384",
        "21" => "ecp521",
        "22" => "modp1024s160",
        "23" => "modp2048s224",
        "24" => "modp2048s256",
        "25" => "ecp192",
        "26" => "ecp224",
        "27" => "ecp224bp",
        "28" => "ecp256bp",
        "29" => "ecp384bp",
        "30" => "ecp512bp",
        "31" => "curve25519",
        "32" => "curve448",
        _ => return None,
    })
}

/// `get_first_ike_dh_group`: the DH group an ESP group with
/// `pfs enable` inherits — the first IKE proposal that names one,
/// falling back on dh-group2.
fn first_ike_dh_group(ike: &IkeGroup) -> String {
    for proposal in sorted_proposals(&ike.proposal) {
        if let Some(dh) = &proposal.dh_group {
            return dh.to_string();
        }
    }
    DEFAULT_IKE_DH_GROUP.to_string()
}

fn sorted_proposals(proposals: &[Proposal]) -> Vec<&Proposal> {
    let mut out: Vec<&Proposal> = proposals.iter().collect();
    out.sort_by_key(|p| {
        p.number
            .as_ref()
            .and_then(|n| n.to_string().parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    out
}

/// `get_esp_ike_cipher`: one `enc-hash[-prf][-dhgroup]` string per
/// proposal. For IKE groups the DH group comes from the proposal
/// itself (VyOS XML default: dh-group2); for ESP groups it comes from
/// the group's `pfs` setting, with `enable` (the default) inheriting
/// [`first_ike_dh_group`] and `disable` adding nothing.
fn cipher_strings(
    proposals: &[Proposal],
    is_ike: bool,
    pfs: Option<&str>,
    ike: Option<&IkeGroup>,
) -> Vec<String> {
    let mut out = Vec::new();
    for proposal in sorted_proposals(proposals) {
        let (Some(encryption), Some(hash)) = (&proposal.encryption, &proposal.hash) else {
            continue;
        };
        let mut s = format!("{encryption}-{hash}");
        if let Some(prf) = &proposal.prf {
            s.push('-');
            s.push_str(prf);
        }
        let dh = if is_ike {
            Some(
                proposal
                    .dh_group
                    .as_ref()
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| DEFAULT_IKE_DH_GROUP.to_string()),
            )
        } else {
            match pfs.unwrap_or("enable") {
                "disable" => None,
                "enable" => Some(
                    ike.map(first_ike_dh_group)
                        .unwrap_or_else(|| DEFAULT_IKE_DH_GROUP.to_string()),
                ),
                named => Some(named.trim_start_matches("dh-group").to_string()),
            }
        };
        if let Some(dh) = dh
            && let Some(name) = dh_group_name(&dh)
        {
            s.push('-');
            s.push_str(name);
        }
        out.push(s);
    }
    out
}

/// VyOS `dot_colon_to_dash` on the '@'-stripped peer name: the
/// swanctl connection section name.
fn conn_name(peer: &str) -> String {
    peer.replace('@', "").replace(['.', ':'], "-")
}

fn find_ike<'a>(cfg: &'a IpsecConfig, name: &str) -> Option<&'a IkeGroup> {
    cfg.ike_group
        .iter()
        .find(|g| g.name.as_ref().is_some_and(|n| n.to_string() == name))
}

fn find_esp<'a>(cfg: &'a IpsecConfig, name: &str) -> Option<&'a EspGroup> {
    cfg.esp_group
        .iter()
        .find(|g| g.name.as_ref().is_some_and(|n| n.to_string() == name))
}

/// Parse an IPv4/IPv6 prefix into comparable network bits.
fn parse_net(prefix: &str) -> Option<(u128, u8, bool)> {
    let (addr, plen) = prefix.split_once('/')?;
    let plen: u8 = plen.parse().ok()?;
    match addr.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            if plen > 32 {
                return None;
            }
            Some((u128::from(u32::from(v4)) << 96, plen, true))
        }
        std::net::IpAddr::V6(v6) => {
            if plen > 128 {
                return None;
            }
            Some((u128::from(v6), plen, false))
        }
    }
}

fn nets_overlap(a: &str, b: &str) -> bool {
    let (Some((abits, aplen, a4)), Some((bbits, bplen, b4))) = (parse_net(a), parse_net(b)) else {
        return false;
    };
    if a4 != b4 {
        return false;
    }
    // Two networks overlap iff they agree under the shorter mask. A
    // plen of 0 masks everything (and a 128-bit shift would be UB).
    let plen = aplen.min(bplen);
    if plen == 0 {
        return true;
    }
    let width: u32 = if a4 { 32 } else { 128 };
    let (abits, bbits) = if a4 {
        (abits >> 96, bbits >> 96)
    } else {
        (abits, bbits)
    };
    let shift = width - u32::from(plen);
    (abits >> shift) == (bbits >> shift)
}

struct Render {
    out: String,
    warnings: Vec<String>,
}

impl Render {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push(' ');
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn warn(&mut self, text: String) {
        self.warnings.push(text);
    }
}

#[cfg(test)]
pub fn render_str(json: &str) -> anyhow::Result<(String, Vec<String>)> {
    let cfg: IpsecConfig =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("ipsec config JSON: {e}"))?;
    Ok(render(&cfg))
}

pub fn render(cfg: &IpsecConfig) -> (String, Vec<String>) {
    let mut r = Render {
        out: String::new(),
        warnings: Vec::new(),
    };

    r.line(0, "### Autogenerated by zebra-rs — do not edit ###");
    r.out.push('\n');

    r.line(0, "connections {");
    if let Some(s2s) = &cfg.site_to_site {
        let mut peers: Vec<&Peer> = s2s.peer.iter().filter(|p| !p.disable).collect();
        peers.sort_by_key(|p| p.name.as_ref().map(|n| n.to_string()).unwrap_or_default());
        for peer in peers {
            render_peer(&mut r, cfg, peer);
        }
    }
    r.line(0, "}");
    r.out.push('\n');

    r.line(0, "pools {");
    r.line(0, "}");
    r.out.push('\n');

    r.line(0, "secrets {");
    if let Some(auth) = &cfg.authentication {
        for psk in &auth.psk {
            render_psk(&mut r, psk);
        }
    }
    r.line(0, "}");

    if cfg.disable_uniqreqids
        || cfg.log.is_some()
        || cfg.options.is_some()
        || !cfg.interface.is_empty()
    {
        r.warn(
            "log / options / interface / disable-uniqreqids are charon-level \
             settings; not applied yet"
                .to_string(),
        );
    }

    (r.out, r.warnings)
}

fn render_psk(r: &mut Render, psk: &Psk) {
    let name = match &psk.name {
        Some(name) => name.to_string(),
        None => return,
    };
    let Some(secret) = &psk.secret else {
        r.warn(format!(
            "authentication psk {name}: no secret configured; skipped"
        ));
        return;
    };
    if !psk.dhcp_interface.is_empty() {
        r.warn(format!(
            "authentication psk {name}: dhcp-interface IDs are not supported yet; \
             only the static ids are loaded"
        ));
    }
    r.line(4, &format!("ike-{name} {{"));
    for (i, id) in psk.id.iter().enumerate() {
        r.line(8, &format!("id-{} = \"{id}\"", i + 1));
    }
    r.line(8, &format!("secret = \"{secret}\""));
    r.line(4, "}");
}

fn render_peer(r: &mut Render, cfg: &IpsecConfig, peer: &Peer) {
    let peer_name = match &peer.name {
        Some(name) => name.to_string(),
        None => return,
    };
    let auth_mode = peer
        .authentication
        .as_ref()
        .and_then(|a| a.mode.as_deref())
        .unwrap_or("");
    if auth_mode != "pre-shared-secret" {
        r.warn(format!(
            "peer {peer_name}: authentication mode pre-shared-secret required; skipped"
        ));
        return;
    }
    let Some(ike_name) = peer.ike_group.as_ref().map(|g| g.to_string()) else {
        r.warn(format!(
            "peer {peer_name}: no ike-group configured; skipped"
        ));
        return;
    };
    let Some(ike) = find_ike(cfg, &ike_name) else {
        r.warn(format!(
            "peer {peer_name}: ike-group {ike_name} does not exist; skipped"
        ));
        return;
    };
    if peer.dhcp_interface.is_some() {
        r.warn(format!(
            "peer {peer_name}: dhcp-interface is not supported yet; skipped"
        ));
        return;
    }
    let Some(local_address) = peer.local_address.as_ref().map(|a| a.to_string()) else {
        r.warn(format!(
            "peer {peer_name}: no local-address configured; skipped"
        ));
        return;
    };
    let tunnels: Vec<&Tunnel> = {
        let mut t: Vec<&Tunnel> = peer.tunnel.iter().filter(|t| !t.disable).collect();
        t.sort_by_key(|t| {
            t.number
                .as_ref()
                .and_then(|n| n.to_string().parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        });
        t
    };
    let vti_bind = peer
        .vti
        .as_ref()
        .and_then(|v| v.bind.as_ref())
        .map(|b| b.to_string());
    if tunnels.is_empty() && vti_bind.is_none() {
        r.warn(format!(
            "peer {peer_name}: no enabled tunnel and no vti bind; skipped"
        ));
        return;
    }
    let proposals = cipher_strings(&ike.proposal, true, None, None);
    if proposals.is_empty() {
        r.warn(format!(
            "peer {peer_name}: ike-group {ike_name} has no complete proposal \
             (encryption and hash required); skipped"
        ));
        return;
    }

    let name = conn_name(&peer_name);
    r.line(4, &format!("{name} {{"));
    r.line(8, &format!("proposals = {}", proposals.join(",")));
    let version = match ike.key_exchange.as_deref() {
        Some("ikev1") => "1",
        Some("ikev2") => "2",
        _ => "0",
    };
    r.line(8, &format!("version = {version}"));
    if !peer.virtual_address.is_empty() {
        let vips: Vec<String> = peer.virtual_address.iter().map(|v| v.to_string()).collect();
        r.line(8, &format!("vips = {}", vips.join(", ")));
    }
    let local_addrs = if local_address == "any" {
        "%any"
    } else {
        local_address.as_str()
    };
    r.line(8, &format!("local_addrs = {local_addrs} # dhcp:no"));
    let remote_addrs: Vec<String> = peer.remote_address.iter().map(|a| a.to_string()).collect();
    let remote_line = if remote_addrs.is_empty() || remote_addrs.iter().any(|a| a == "any") {
        "%any".to_string()
    } else {
        remote_addrs.join(",")
    };
    r.line(8, &format!("remote_addrs = {remote_line}"));
    if let Some(dpd) = &ike.dead_peer_detection {
        let timeout = dpd
            .timeout
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| DEFAULT_DPD_TIMEOUT.to_string());
        let interval = dpd
            .interval
            .as_ref()
            .map(|i| i.to_string())
            .unwrap_or_else(|| DEFAULT_DPD_INTERVAL.to_string());
        r.line(8, &format!("dpd_timeout = {timeout}"));
        r.line(8, &format!("dpd_delay = {interval}"));
    }
    if ike.key_exchange.as_deref() == Some("ikev1") && ike.mode.as_deref() == Some("aggressive") {
        r.line(8, "aggressive = yes");
    }
    let rekey = ike
        .lifetime
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| DEFAULT_IKE_LIFETIME.to_string());
    r.line(8, &format!("rekey_time = {rekey}s"));
    r.line(
        8,
        &format!("mobike = {}", if ike.disable_mobike { "no" } else { "yes" }),
    );
    let conn_type = peer.connection_type.as_deref();
    if peer_name.starts_with('@') {
        r.line(8, "keyingtries = 0");
        r.line(8, "reauth_time = 0");
    } else if conn_type.is_none() || conn_type == Some("initiate") {
        r.line(8, "keyingtries = 0");
    } else if conn_type == Some("respond") {
        r.line(8, "keyingtries = 1");
    }
    if peer.force_udp_encapsulation {
        r.line(8, "encap = yes");
    }
    r.line(8, "local {");
    if let Some(local_id) = peer
        .authentication
        .as_ref()
        .and_then(|a| a.local_id.as_ref())
    {
        r.line(12, &format!("id = \"{local_id}\""));
    }
    r.line(12, "auth = psk");
    r.line(8, "}");
    r.line(8, "remote {");
    let remote_id = peer
        .authentication
        .as_ref()
        .and_then(|a| a.remote_id.as_ref())
        .map(|i| i.to_string())
        .unwrap_or_else(|| DEFAULT_REMOTE_ID.to_string());
    r.line(12, &format!("id = \"{remote_id}\""));
    r.line(12, "auth = psk");
    r.line(8, "}");
    r.line(8, "children {");
    if let Some(bind) = &vti_bind
        && tunnels.is_empty()
    {
        render_vti_child(r, cfg, peer, &peer_name, &name, ike, bind);
    } else {
        for tunnel in &tunnels {
            render_tunnel_child(
                r,
                cfg,
                peer,
                &peer_name,
                &name,
                ike,
                tunnel,
                &local_address,
                vti_bind.as_deref(),
            );
        }
    }
    r.line(8, "}");
    r.line(4, "}");
}

/// The ESP group a child uses: its own `esp-group` if set, else the
/// peer's `default-esp-group`.
fn child_esp<'a>(
    cfg: &'a IpsecConfig,
    peer: &Peer,
    own: Option<&Flex>,
) -> Result<&'a EspGroup, String> {
    let name = own
        .map(|g| g.to_string())
        .or_else(|| peer.default_esp_group.as_ref().map(|g| g.to_string()))
        .ok_or_else(|| "no esp-group and no default-esp-group".to_string())?;
    find_esp_named(cfg, &name)
}

fn find_esp_named<'a>(cfg: &'a IpsecConfig, name: &str) -> Result<&'a EspGroup, String> {
    find_esp(cfg, name).ok_or_else(|| format!("esp-group {name} does not exist"))
}

/// Fields shared by every child block, in template order after the
/// esp_proposals line.
fn render_child_lifetimes(r: &mut Render, esp: &EspGroup) {
    if let Some(bytes) = &esp.life_bytes {
        r.line(16, &format!("life_bytes = {bytes}"));
    }
    if let Some(packets) = &esp.life_packets {
        r.line(16, &format!("life_packets = {packets}"));
    }
    let lifetime = esp
        .lifetime
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| DEFAULT_ESP_LIFETIME.to_string());
    r.line(16, &format!("life_time = {lifetime}s"));
    if esp.disable_rekey {
        r.line(16, "rekey_bytes = 0");
        r.line(16, "rekey_packets = 0");
        r.line(16, "rekey_time = 0s");
    }
}

fn start_action(peer_name: &str, conn_type: Option<&str>) -> &'static str {
    if peer_name.starts_with('@') {
        "none"
    } else {
        match conn_type {
            None | Some("initiate") => "start",
            Some("respond") => "trap",
            _ => "none",
        }
    }
}

fn render_child_tail(r: &mut Render, peer: &Peer, peer_name: &str, ike: &IkeGroup) {
    r.line(
        16,
        &format!(
            "start_action = {}",
            start_action(peer_name, peer.connection_type.as_deref())
        ),
    );
    if let Some(dpd) = &ike.dead_peer_detection {
        let action = dpd.action.as_deref().unwrap_or("clear");
        r.line(16, &format!("dpd_action = {action}"));
    }
    let close = ike.close_action.as_deref().unwrap_or(DEFAULT_CLOSE_ACTION);
    r.line(16, &format!("close_action = {close}"));
    if let Some(window) = &peer.replay_window {
        r.line(16, &format!("replay_window = {window}"));
    }
}

/// The `vti<N>` → XFRM interface key, shifted by one exactly like
/// VyOS so a `vti0` still gets a non-zero lookup key.
fn vti_if_id(bind: &str) -> Option<u32> {
    bind.strip_prefix("vti")?.parse::<u32>().ok().map(|n| n + 1)
}

fn render_vti_child(
    r: &mut Render,
    cfg: &IpsecConfig,
    peer: &Peer,
    peer_name: &str,
    name: &str,
    ike: &IkeGroup,
    bind: &str,
) {
    let own = peer.vti.as_ref().and_then(|v| v.esp_group.as_ref());
    let esp = match child_esp(cfg, peer, own) {
        Ok(esp) => esp,
        Err(err) => {
            r.warn(format!("peer {peer_name} vti: {err}; child skipped"));
            return;
        }
    };
    let Some(if_id) = vti_if_id(bind) else {
        r.warn(format!(
            "peer {peer_name} vti: bind {bind} is not a vti<N> interface; child skipped"
        ));
        return;
    };
    let proposals = cipher_strings(&esp.proposal, false, esp.pfs.as_deref(), Some(ike));
    if proposals.is_empty() {
        r.warn(format!(
            "peer {peer_name} vti: esp group has no complete proposal; child skipped"
        ));
        return;
    }
    r.line(12, &format!("{name}-vti {{"));
    r.line(16, &format!("esp_proposals = {}", proposals.join(",")));
    render_child_lifetimes(r, esp);
    r.line(16, "local_ts = 0.0.0.0/0,::/0");
    r.line(16, "remote_ts = 0.0.0.0/0,::/0");
    r.line(16, &format!("updown = \"/etc/ipsec.d/vti-up-down {bind}\""));
    r.line(16, &format!("if_id_in = {if_id}"));
    r.line(16, &format!("if_id_out = {if_id}"));
    r.line(
        16,
        &format!("ipcomp = {}", if esp.compression { "yes" } else { "no" }),
    );
    r.line(
        16,
        &format!("mode = {}", esp.mode.as_deref().unwrap_or("tunnel")),
    );
    render_child_tail(r, peer, peer_name, ike);
    r.line(12, "}");
}

#[allow(clippy::too_many_arguments)]
fn render_tunnel_child(
    r: &mut Render,
    cfg: &IpsecConfig,
    peer: &Peer,
    peer_name: &str,
    name: &str,
    ike: &IkeGroup,
    tunnel: &Tunnel,
    local_address: &str,
    vti_bind: Option<&str>,
) {
    let tunnel_id = tunnel
        .number
        .as_ref()
        .map(|n| n.to_string())
        .unwrap_or_default();
    let esp = match child_esp(cfg, peer, tunnel.esp_group.as_ref()) {
        Ok(esp) => esp,
        Err(err) => {
            r.warn(format!(
                "peer {peer_name} tunnel {tunnel_id}: {err}; child skipped"
            ));
            return;
        }
    };
    let proposals = cipher_strings(&esp.proposal, false, esp.pfs.as_deref(), Some(ike));
    if proposals.is_empty() {
        r.warn(format!(
            "peer {peer_name} tunnel {tunnel_id}: esp group has no complete proposal; \
             child skipped"
        ));
        return;
    }

    let proto = tunnel
        .protocol
        .as_ref()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let suffix = |port: Option<&Flex>| -> String {
        let port = port.map(|p| p.to_string()).unwrap_or_default();
        if proto.is_empty() && port.is_empty() {
            String::new()
        } else {
            format!("[{proto}/{port}]")
        }
    };
    let local_suffix = suffix(tunnel.local.as_ref().and_then(|s| s.port.as_ref()));
    let remote_suffix = suffix(tunnel.remote.as_ref().and_then(|s| s.port.as_ref()));

    r.line(12, &format!("{name}-tunnel-{tunnel_id} {{"));
    r.line(16, &format!("esp_proposals = {}", proposals.join(",")));
    render_child_lifetimes(r, esp);
    let mode = esp.mode.as_deref().unwrap_or("tunnel");
    // `any` anywhere in a prefix list widens it to both families,
    // exactly like the template.
    let ts_prefixes = |sel: Option<&Selector>| -> Vec<String> {
        let prefixes: Vec<String> = sel
            .map(|s| s.prefix.iter().map(|p| p.to_string()).collect())
            .unwrap_or_default();
        if prefixes.iter().any(|p| p == "any") {
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        } else {
            prefixes
        }
    };
    if mode == "tunnel" {
        let local = ts_prefixes(tunnel.local.as_ref());
        if !local.is_empty() {
            r.line(
                16,
                &format!(
                    "local_ts = {}{local_suffix}",
                    local.join(&format!("{local_suffix},"))
                ),
            );
        }
        let remote = ts_prefixes(tunnel.remote.as_ref());
        if !remote.is_empty() {
            r.line(
                16,
                &format!(
                    "remote_ts = {}{remote_suffix}",
                    remote.join(&format!("{remote_suffix},"))
                ),
            );
        }
        if let Some(priority) = &tunnel.priority {
            r.line(16, &format!("priority = {priority}"));
        }
    } else {
        let remote: Vec<String> = peer.remote_address.iter().map(|a| a.to_string()).collect();
        r.line(16, &format!("local_ts = {local_address}{local_suffix}"));
        r.line(
            16,
            &format!("remote_ts = {}{remote_suffix}", remote.join(",")),
        );
    }
    r.line(
        16,
        &format!("ipcomp = {}", if esp.compression { "yes" } else { "no" }),
    );
    r.line(16, &format!("mode = {mode}"));
    render_child_tail(r, peer, peer_name, ike);
    if let Some(bind) = vti_bind {
        if let Some(if_id) = vti_if_id(bind) {
            r.line(16, &format!("updown = \"/etc/ipsec.d/vti-up-down {bind}\""));
            r.line(16, &format!("if_id_in = {if_id}"));
            r.line(16, &format!("if_id_out = {if_id}"));
        } else {
            r.warn(format!(
                "peer {peer_name} tunnel {tunnel_id}: vti bind {bind} is not a \
                 vti<N> interface; updown hook omitted"
            ));
        }
    }
    r.line(12, "}");

    // Local prefixes that overlap a remote prefix get a pass-mode
    // sibling so intra-site traffic is not swallowed by the tunnel
    // policy (vpn_ipsec.py's `passthrough` computation).
    let passthrough: Vec<String> = ts_prefixes(tunnel.local.as_ref())
        .into_iter()
        .filter(|local| {
            ts_prefixes(tunnel.remote.as_ref())
                .iter()
                .any(|remote| nets_overlap(local, remote))
        })
        .collect();
    if !passthrough.is_empty() {
        let ts = passthrough.join(",");
        r.line(12, &format!("{name}-tunnel-{tunnel_id}-passthrough {{"));
        r.line(16, &format!("local_ts = {ts}"));
        r.line(16, &format!("remote_ts = {ts}"));
        r.line(16, "start_action = trap");
        r.line(16, "mode = pass");
        r.line(12, "}");
    }
}

// ---------------------------------------------------------------
// show vpn ipsec
//
// `sa` and `connections` read live data over charon's vici socket —
// the same channel VyOS's op-mode scripts use — and format it with
// the same row/column semantics as vyos-1x src/op_mode/ipsec.py.
// `state` and `policy` shell out to `ip xfrm`, exactly like the VyOS
// op-mode definitions. One deviation: multi-value traffic-selector
// cells join with "," where VyOS embeds newlines in table cells.
// ---------------------------------------------------------------

async fn process_show(vici_socket: &Path, req: DisplayRequest) {
    let (path, _args) = path_from_command(&req.paths);
    let out = match path.as_str() {
        "/show/vpn/ipsec/sa" => show_sa(vici_socket, req.json).await,
        "/show/vpn/ipsec/connections" => show_connections(vici_socket, req.json).await,
        "/show/vpn/ipsec/policy" => xfrm_show("policy", req.json).await,
        "/show/vpn/ipsec/state" => xfrm_show("state", req.json).await,
        _ => String::from("% Unknown ipsec show command\n"),
    };
    let _ = req.resp.send(out).await;
}

async fn show_sa(socket: &Path, json: bool) -> String {
    match vici::streamed_request(socket, "list-sas", "list-sa").await {
        Err(err) => {
            tracing::debug!("ipsec: vici list-sas failed: {err:#}");
            String::from("% IPsec process not running\n")
        }
        Ok(msgs) => {
            if json {
                let all: Vec<serde_json::Value> = msgs.iter().map(|m| m.to_json()).collect();
                format!("{:#}\n", serde_json::Value::Array(all))
            } else {
                format_sa_table(&msgs)
            }
        }
    }
}

async fn show_connections(socket: &Path, json: bool) -> String {
    let conns = match vici::streamed_request(socket, "list-conns", "list-conn").await {
        Err(err) => {
            tracing::debug!("ipsec: vici list-conns failed: {err:#}");
            return String::from("% IPsec process not running\n");
        }
        Ok(conns) => conns,
    };
    let sas = vici::streamed_request(socket, "list-sas", "list-sa")
        .await
        .unwrap_or_default();
    let raw = connections_raw(&conns, &sas);
    if json {
        format!("{:#}\n", serde_json::Value::Array(raw))
    } else {
        format_connections_table(&raw)
    }
}

/// `ip xfrm state|policy list` — kernel truth, no strongSwan needed.
async fn xfrm_show(object: &str, json: bool) -> String {
    let text = match tokio::process::Command::new("ip")
        .args(["xfrm", object, "list"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Ok(output) => format!(
            "% ip xfrm {object} list failed: {}\n",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) => format!("% ip xfrm {object} list failed: {err}\n"),
    };
    if json {
        // iproute2 has no JSON output for xfrm objects; wrap the text.
        format!("{:#}\n", serde_json::json!({ "output": text }))
    } else {
        text
    }
}

/// One row per child SA, VyOS `show vpn ipsec sa` columns.
fn format_sa_table(msgs: &[vici::Value]) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    for msg in msgs {
        for (_, parent) in msg.entries() {
            let Some(children) = parent.get("child-sas") else {
                continue;
            };
            for (_, child) in children.entries() {
                let state = match child.str("state") {
                    Some("INSTALLED") => "up".to_string(),
                    Some(_) => "down".to_string(),
                    None => "N/A".to_string(),
                };
                let uptime = child
                    .str("install-time")
                    .and_then(|t| t.parse::<u64>().ok())
                    .map(seconds_to_human)
                    .unwrap_or_else(|| "N/A".to_string());
                let bytes = match (child.str("bytes-in"), child.str("bytes-out")) {
                    (Some(i), Some(o)) => format!(
                        "{}/{}",
                        filesize(i.parse().unwrap_or(0), 1024),
                        filesize(o.parse().unwrap_or(0), 1024)
                    ),
                    _ => "N/A".to_string(),
                };
                let packets = match (child.str("packets-in"), child.str("packets-out")) {
                    (Some(i), Some(o)) => format!(
                        "{}/{}",
                        filesize(i.parse().unwrap_or(0), 1000).trim_end_matches('B'),
                        filesize(o.parse().unwrap_or(0), 1000).trim_end_matches('B')
                    ),
                    _ => "N/A".to_string(),
                };
                let mut proposal = child.str("encr-alg").unwrap_or("N/A").to_string();
                if let Some(keysize) = child.str("encr-keysize") {
                    proposal = format!("{proposal}_{keysize}");
                }
                if let Some(integ) = child.str("integ-alg") {
                    proposal = format!("{proposal}/{integ}");
                }
                if let Some(dh) = child.str("dh-group") {
                    proposal = format!("{proposal}/{dh}");
                }
                rows.push(vec![
                    child.str("name").unwrap_or("N/A").to_string(),
                    state,
                    uptime,
                    bytes,
                    packets,
                    parent.str("remote-host").unwrap_or("N/A").to_string(),
                    parent.str("remote-id").unwrap_or("N/A").to_string(),
                    proposal,
                ]);
            }
        }
    }
    rows.sort_by_key(|row| natural_key(&row[0]));
    table(
        &[
            "Connection",
            "State",
            "Uptime",
            "Bytes In/Out",
            "Packets In/Out",
            "Remote address",
            "Remote ID",
            "Proposal",
        ],
        &rows,
    )
}

/// The `{cipher}_{mode}/{key_size}/{hash}/{dh}` proposal object VyOS
/// derives from an SA section, as JSON (empty object when the SA has
/// no encr-alg — e.g. a rekeying/down connection).
fn proposal_json(sa: &vici::Value) -> serde_json::Value {
    let Some(encr) = sa.str("encr-alg") else {
        return serde_json::json!({});
    };
    // python `encr.split('_')[0]` / `[1]`: AES_GCM_16 → AES / GCM.
    let mut parts = encr.split('_');
    let cipher = parts.next().unwrap_or("");
    let mode = parts.next().unwrap_or("");
    serde_json::json!({
        "cipher": cipher,
        "mode": mode,
        "key_size": sa.str("encr-keysize"),
        "hash": sa.str("integ-alg"),
        "dh": sa.str("dh-group"),
    })
}

fn proposal_text(proposal: &serde_json::Value) -> String {
    if proposal.as_object().is_none_or(|o| o.is_empty()) {
        return "-".to_string();
    }
    let s = |k: &str| -> String {
        match &proposal[k] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "None".to_string(),
            other => other.to_string(),
        }
    };
    format!(
        "{}_{}/{}/{}/{}",
        s("cipher"),
        s("mode"),
        s("key_size"),
        s("hash"),
        s("dh")
    )
}

/// Find the parent SA section for a connection name across the
/// list-sas messages.
fn find_parent_sa<'a>(sas: &'a [vici::Value], conn: &str) -> Option<&'a vici::Value> {
    sas.iter()
        .flat_map(|m| m.entries())
        .find(|(name, _)| name == conn)
        .map(|(_, sa)| sa)
}

/// The last INSTALLED child SA carrying this tunnel name (there can
/// be several during a rekey; VyOS takes the newest).
fn find_child_sa<'a>(sas: &'a [vici::Value], conn: &str, tunnel: &str) -> Option<&'a vici::Value> {
    let parent = find_parent_sa(sas, conn)?;
    parent
        .get("child-sas")?
        .entries()
        .iter()
        .filter(|(_, child)| {
            child.str("name") == Some(tunnel) && child.str("state") == Some("INSTALLED")
        })
        .map(|(_, child)| child)
        .next_back()
}

/// vyos-1x `_get_raw_data_connections`: configured connections joined
/// with live SA state — the machine-readable view, and the input for
/// the text table.
fn connections_raw(conns: &[vici::Value], sas: &[vici::Value]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for msg in conns {
        for (name, conf) in msg.entries() {
            let ike_state = match find_parent_sa(sas, name) {
                Some(sa)
                    if sa
                        .str("state")
                        .unwrap_or("")
                        .eq_ignore_ascii_case("established") =>
                {
                    "up"
                }
                _ => "down",
            };
            let ike_proposal = find_parent_sa(sas, name)
                .map(proposal_json)
                .unwrap_or_else(|| serde_json::json!({}));
            let mut children = Vec::new();
            if let Some(section) = conf.get("children") {
                for (tunnel, opts) in section.entries() {
                    let child_sa = find_child_sa(sas, name, tunnel);
                    let state = if child_sa.is_some() { "up" } else { "down" };
                    children.push(serde_json::json!({
                        "name": tunnel,
                        "state": state,
                        "local_ts": opts.list("local-ts"),
                        "remote_ts": opts.list("remote-ts"),
                        "dpd_action": opts.str("dpd_action"),
                        "close_action": opts.str("close_action"),
                        "esp_proposal": child_sa
                            .map(proposal_json)
                            .unwrap_or_else(|| serde_json::json!({})),
                    }));
                }
            }
            out.push(serde_json::json!({
                "ike_connection_name": name,
                "ike_connection_state": ike_state,
                "ike_remote_address": conf.list("remote_addrs"),
                "ike_proposal": ike_proposal,
                "local_id": conf.get("local-1").and_then(|l| l.str("id")),
                "remote_id": conf.get("remote-1").and_then(|r| r.str("id")),
                "version": conf.str("version").unwrap_or("IKE"),
                "children": children,
            }));
        }
    }
    out
}

/// vyos-1x `_get_formatted_output_conections`: one row for the IKE
/// connection, then one per child.
fn format_connections_table(raw: &[serde_json::Value]) -> String {
    let text = |v: &serde_json::Value| -> String {
        match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }
    };
    let join = |v: &serde_json::Value| -> String {
        v.as_array()
            .map(|items| items.iter().map(text).collect::<Vec<_>>().join(","))
            .unwrap_or_default()
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    for entry in raw {
        let remote_addrs = join(&entry["ike_remote_address"]);
        let local_id = text(&entry["local_id"]);
        let remote_id = text(&entry["remote_id"]);
        rows.push(vec![
            text(&entry["ike_connection_name"]),
            text(&entry["ike_connection_state"]),
            text(&entry["version"]),
            remote_addrs.clone(),
            "-".to_string(),
            "-".to_string(),
            local_id.clone(),
            remote_id.clone(),
            proposal_text(&entry["ike_proposal"]),
        ]);
        if let Some(children) = entry["children"].as_array() {
            for child in children {
                rows.push(vec![
                    text(&child["name"]),
                    text(&child["state"]),
                    "IPsec".to_string(),
                    remote_addrs.clone(),
                    join(&child["local_ts"]),
                    join(&child["remote_ts"]),
                    local_id.clone(),
                    remote_id.clone(),
                    proposal_text(&child["esp_proposal"]),
                ]);
            }
        }
    }
    table(
        &[
            "Connection",
            "State",
            "Type",
            "Remote address",
            "Local TS",
            "Remote TS",
            "Local id",
            "Remote id",
            "Proposal",
        ],
        &rows,
    )
}

/// tabulate's `simple` format: header, dashes, left-aligned rows,
/// two-space column gap, no trailing padding.
fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[String]| {
        let mut parts = Vec::new();
        for (i, cell) in cells.iter().enumerate() {
            parts.push(format!("{cell:<width$}", width = widths[i]));
        }
        let joined = parts.join("  ");
        out.push_str(joined.trim_end());
        out.push('\n');
    };
    line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    line(&widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>());
    for row in rows {
        line(row);
    }
    out
}

/// vyos seconds_to_human with the default empty separator:
/// `93784` → `1d2h3m4s`.
fn seconds_to_human(mut secs: u64) -> String {
    const UNITS: [(u64, &str); 5] = [
        (60 * 60 * 24 * 7, "w"),
        (60 * 60 * 24, "d"),
        (60 * 60, "h"),
        (60, "m"),
        (1, "s"),
    ];
    let mut out = String::new();
    for (factor, suffix) in UNITS {
        let amount = secs / factor;
        secs %= factor;
        if amount > 0 {
            out.push_str(&format!("{amount}{suffix}"));
        }
    }
    if out.is_empty() {
        out.push_str("0s");
    }
    out
}

/// hurry.filesize semantics (used by the VyOS sa table): largest unit
/// whose factor fits, integer amount, one-letter suffix. Base 1024
/// for bytes, base 1000 (with the trailing `B` stripped by the
/// caller) for packet counts.
fn filesize(n: u64, base: u64) -> String {
    const SUFFIXES: [&str; 6] = ["P", "T", "G", "M", "K", "B"];
    for (i, suffix) in SUFFIXES.iter().enumerate() {
        let factor = base.pow((SUFFIXES.len() - 1 - i) as u32);
        if n >= factor && factor > 1 {
            return format!("{}{suffix}", n / factor);
        }
    }
    format!("{n}B")
}

/// Natural-sort key: digit runs compare numerically, so
/// `peer-2-tunnel-10` sorts after `peer-2-tunnel-2`.
fn natural_key(s: &str) -> Vec<(u64, String)> {
    let mut key = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut n = 0u64;
            while let Some(&d) = chars.peek() {
                if let Some(v) = d.to_digit(10) {
                    n = n.saturating_mul(10).saturating_add(u64::from(v));
                    chars.next();
                } else {
                    break;
                }
            }
            key.push((n, String::new()));
        } else {
            let mut run = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    break;
                }
                run.push(d);
                chars.next();
            }
            key.push((u64::MAX, run));
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full config in `Config::json()` marshal shape: numeric
    /// scalars unquoted, `type empty` leaves null, keyed lists as
    /// arrays with the key inline.
    const FULL: &str = r#"{
        "authentication": {
            "psk": [
                {
                    "name": "MAIN",
                    "id": ["192.0.2.1", "@branch"],
                    "secret": "s3cret-key"
                }
            ]
        },
        "esp-group": [
            {
                "name": "ESP-A",
                "lifetime": 1800,
                "proposal": [
                    {"number": 10, "encryption": "aes256gcm128", "hash": "sha256"}
                ]
            },
            {
                "name": "ESP-T",
                "mode": "transport",
                "pfs": "dh-group14",
                "compression": null,
                "disable-rekey": null,
                "life-bytes": 1024000,
                "life-packets": 1000000,
                "proposal": [
                    {"number": 1, "encryption": "aes128", "hash": "sha1"}
                ]
            }
        ],
        "ike-group": [
            {
                "name": "IKE-A",
                "key-exchange": "ikev2",
                "lifetime": 7200,
                "close-action": "trap",
                "dead-peer-detection": {
                    "action": "restart",
                    "interval": 15,
                    "timeout": 60
                },
                "proposal": [
                    {"number": 10, "encryption": "aes256gcm128", "hash": "sha256",
                     "prf": "prfsha384", "dh-group": 19},
                    {"number": 20, "encryption": "aes256", "hash": "sha512"}
                ]
            }
        ],
        "site-to-site": {
            "peer": [
                {
                    "name": "192.0.2.9",
                    "authentication": {
                        "mode": "pre-shared-secret",
                        "local-id": "left",
                        "remote-id": "right"
                    },
                    "connection-type": "respond",
                    "ike-group": "IKE-A",
                    "default-esp-group": "ESP-A",
                    "local-address": "192.0.2.1",
                    "remote-address": ["192.0.2.9"],
                    "replay-window": 64,
                    "tunnel": [
                        {"number": 1,
                         "local": {"prefix": ["10.0.1.0/24"]},
                         "remote": {"prefix": ["10.0.2.0/24"]}},
                        {"number": 2, "esp-group": "ESP-T",
                         "protocol": "tcp",
                         "local": {"port": 179}},
                        {"number": 3,
                         "local": {"prefix": ["10.0.3.0/24"]},
                         "remote": {"prefix": ["10.0.0.0/8"]}}
                    ]
                },
                {
                    "name": "@branch",
                    "authentication": {"mode": "pre-shared-secret"},
                    "force-udp-encapsulation": null,
                    "ike-group": "IKE-A",
                    "local-address": "any",
                    "virtual-address": ["10.99.0.2"],
                    "vti": {"bind": "vti0", "esp-group": "ESP-A"}
                }
            ]
        }
    }"#;

    #[test]
    fn full_config_golden() {
        let (conf, warnings) = render_str(FULL).expect("parses");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        let expected = "\
### Autogenerated by zebra-rs — do not edit ###

connections {
    192-0-2-9 {
        proposals = aes256gcm128-sha256-prfsha384-ecp256,aes256-sha512-modp1024
        version = 2
        local_addrs = 192.0.2.1 # dhcp:no
        remote_addrs = 192.0.2.9
        dpd_timeout = 60
        dpd_delay = 15
        rekey_time = 7200s
        mobike = yes
        keyingtries = 1
        local {
            id = \"left\"
            auth = psk
        }
        remote {
            id = \"right\"
            auth = psk
        }
        children {
            192-0-2-9-tunnel-1 {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 1800s
                local_ts = 10.0.1.0/24
                remote_ts = 10.0.2.0/24
                ipcomp = no
                mode = tunnel
                start_action = trap
                dpd_action = restart
                close_action = trap
                replay_window = 64
            }
            192-0-2-9-tunnel-2 {
                esp_proposals = aes128-sha1-modp2048
                life_bytes = 1024000
                life_packets = 1000000
                life_time = 3600s
                rekey_bytes = 0
                rekey_packets = 0
                rekey_time = 0s
                local_ts = 192.0.2.1[tcp/179]
                remote_ts = 192.0.2.9[tcp/]
                ipcomp = yes
                mode = transport
                start_action = trap
                dpd_action = restart
                close_action = trap
                replay_window = 64
            }
            192-0-2-9-tunnel-3 {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 1800s
                local_ts = 10.0.3.0/24
                remote_ts = 10.0.0.0/8
                ipcomp = no
                mode = tunnel
                start_action = trap
                dpd_action = restart
                close_action = trap
                replay_window = 64
            }
            192-0-2-9-tunnel-3-passthrough {
                local_ts = 10.0.3.0/24
                remote_ts = 10.0.3.0/24
                start_action = trap
                mode = pass
            }
        }
    }
    branch {
        proposals = aes256gcm128-sha256-prfsha384-ecp256,aes256-sha512-modp1024
        version = 2
        vips = 10.99.0.2
        local_addrs = %any # dhcp:no
        remote_addrs = %any
        dpd_timeout = 60
        dpd_delay = 15
        rekey_time = 7200s
        mobike = yes
        keyingtries = 0
        reauth_time = 0
        encap = yes
        local {
            auth = psk
        }
        remote {
            id = \"%any\"
            auth = psk
        }
        children {
            branch-vti {
                esp_proposals = aes256gcm128-sha256-ecp256
                life_time = 1800s
                local_ts = 0.0.0.0/0,::/0
                remote_ts = 0.0.0.0/0,::/0
                updown = \"/etc/ipsec.d/vti-up-down vti0\"
                if_id_in = 1
                if_id_out = 1
                ipcomp = no
                mode = tunnel
                start_action = none
                dpd_action = restart
                close_action = trap
            }
        }
    }
}

pools {
}

secrets {
    ike-MAIN {
        id-1 = \"192.0.2.1\"
        id-2 = \"@branch\"
        secret = \"s3cret-key\"
    }
}
";
        assert_eq!(conf, expected);
    }

    #[test]
    fn empty_config_renders_empty_sections() {
        let (conf, warnings) = render_str("{}").expect("parses");
        assert!(warnings.is_empty());
        assert!(conf.contains("connections {\n}\n"));
        assert!(conf.contains("secrets {\n}\n"));
    }

    #[test]
    fn cipher_string_pfs_variants() {
        // pfs enable (default) inherits the first IKE dh-group.
        let ike: IkeGroup = serde_json::from_str(
            r#"{"proposal": [{"number": 1, "encryption": "aes256", "hash": "sha256",
                              "dh-group": 19}]}"#,
        )
        .unwrap();
        let esp: EspGroup = serde_json::from_str(
            r#"{"proposal": [{"number": 1, "encryption": "aes256", "hash": "sha256"}]}"#,
        )
        .unwrap();
        assert_eq!(
            cipher_strings(&esp.proposal, false, esp.pfs.as_deref(), Some(&ike)),
            vec!["aes256-sha256-ecp256"]
        );

        // pfs disable adds nothing.
        assert_eq!(
            cipher_strings(&esp.proposal, false, Some("disable"), Some(&ike)),
            vec!["aes256-sha256"]
        );

        // explicit pfs dh-group wins over the IKE group.
        assert_eq!(
            cipher_strings(&esp.proposal, false, Some("dh-group31"), Some(&ike)),
            vec!["aes256-sha256-curve25519"]
        );

        // IKE proposal without dh-group falls back on the XML default 2.
        let bare: IkeGroup = serde_json::from_str(
            r#"{"proposal": [{"number": 1, "encryption": "aes128", "hash": "sha1"}]}"#,
        )
        .unwrap();
        assert_eq!(
            cipher_strings(&bare.proposal, true, None, None),
            vec!["aes128-sha1-modp1024"]
        );
        // ...and an ESP group inheriting from it gets the same fallback.
        assert_eq!(
            cipher_strings(&esp.proposal, false, Some("enable"), Some(&bare)),
            vec!["aes256-sha256-modp1024"]
        );

        // a proposal missing hash or encryption is dropped.
        let broken: EspGroup =
            serde_json::from_str(r#"{"proposal": [{"number": 1, "encryption": "aes256"}]}"#)
                .unwrap();
        assert!(cipher_strings(&broken.proposal, false, None, Some(&ike)).is_empty());
    }

    #[test]
    fn overlap_detection() {
        assert!(nets_overlap("10.0.3.0/24", "10.0.0.0/8"));
        assert!(nets_overlap("10.0.0.0/8", "10.0.3.0/24"));
        assert!(!nets_overlap("10.0.1.0/24", "10.0.2.0/24"));
        assert!(nets_overlap("2001:db8::/48", "2001:db8::/32"));
        assert!(!nets_overlap("2001:db8::/48", "2001:db9::/48"));
        // different families never overlap
        assert!(!nets_overlap("10.0.0.0/8", "::/0"));
        // 0-length masks everything in-family
        assert!(nets_overlap("0.0.0.0/0", "192.168.1.0/24"));
        // unparseable ("any") is never an overlap
        assert!(!nets_overlap("any", "10.0.0.0/8"));
    }

    #[test]
    fn skips_warn_and_never_wedge() {
        let json = r#"{
            "authentication": {"psk": [{"name": "NOSECRET"}]},
            "ike-group": [
                {"name": "IKE-A",
                 "proposal": [{"number": 1, "encryption": "aes256", "hash": "sha256"}]}
            ],
            "esp-group": [
                {"name": "ESP-A",
                 "proposal": [{"number": 1, "encryption": "aes256", "hash": "sha256"}]}
            ],
            "site-to-site": {
                "peer": [
                    {"name": "no-auth", "ike-group": "IKE-A", "local-address": "192.0.2.1",
                     "tunnel": [{"number": 1}]},
                    {"name": "no-ike",
                     "authentication": {"mode": "pre-shared-secret"},
                     "local-address": "192.0.2.1", "tunnel": [{"number": 1}]},
                    {"name": "bad-ike",
                     "authentication": {"mode": "pre-shared-secret"},
                     "ike-group": "MISSING", "local-address": "192.0.2.1",
                     "tunnel": [{"number": 1}]},
                    {"name": "no-esp",
                     "authentication": {"mode": "pre-shared-secret"},
                     "ike-group": "IKE-A", "local-address": "192.0.2.1",
                     "tunnel": [{"number": 1}]},
                    {"name": "dhcp-peer",
                     "authentication": {"mode": "pre-shared-secret"},
                     "ike-group": "IKE-A", "dhcp-interface": "eth0",
                     "tunnel": [{"number": 1}]},
                    {"name": "disabled", "disable": null,
                     "authentication": {"mode": "pre-shared-secret"},
                     "ike-group": "IKE-A", "local-address": "192.0.2.1",
                     "tunnel": [{"number": 1}]},
                    {"name": "good",
                     "authentication": {"mode": "pre-shared-secret"},
                     "ike-group": "IKE-A", "default-esp-group": "ESP-A",
                     "local-address": "192.0.2.1",
                     "tunnel": [{"number": 1, "local": {"prefix": ["10.0.1.0/24"]},
                                 "remote": {"prefix": ["10.0.2.0/24"]}}]}
                ]
            }
        }"#;
        let (conf, warnings) = render_str(json).expect("parses");
        // The good peer renders...
        assert!(conf.contains("    good {"));
        assert!(conf.contains("good-tunnel-1 {"));
        // ...every bad one is skipped with a warning...
        for needle in [
            "peer no-auth: authentication mode",
            "peer no-ike: no ike-group",
            "peer bad-ike: ike-group MISSING does not exist",
            "peer no-esp tunnel 1: no esp-group and no default-esp-group",
            "peer dhcp-peer: dhcp-interface is not supported yet",
            "authentication psk NOSECRET: no secret",
        ] {
            assert!(
                warnings.iter().any(|w| w.contains(needle)),
                "missing warning `{needle}` in {warnings:?}"
            );
        }
        for absent in [
            "no-auth {",
            "no-ike {",
            "bad-ike {",
            "dhcp-peer {",
            "disabled {",
        ] {
            assert!(!conf.contains(absent), "`{absent}` should not render");
        }
        // ...and the disabled peer is skipped silently.
        assert!(!warnings.iter().any(|w| w.contains("disabled")));
        // no-esp renders the connection with an empty children set —
        // only its tunnel child is skipped.
        assert!(conf.contains("    no-esp {"));
    }

    #[test]
    fn transport_and_any_widening() {
        let json = r#"{
            "ike-group": [
                {"name": "IKE", "key-exchange": "ikev1", "mode": "aggressive",
                 "proposal": [{"number": 1, "encryption": "aes128", "hash": "sha1"}]}
            ],
            "esp-group": [
                {"name": "ESP",
                 "proposal": [{"number": 1, "encryption": "aes128", "hash": "sha1"}]}
            ],
            "site-to-site": {
                "peer": [
                    {"name": "p",
                     "authentication": {"mode": "pre-shared-secret"},
                     "connection-type": "none",
                     "ike-group": "IKE", "default-esp-group": "ESP",
                     "local-address": "192.0.2.1",
                     "remote-address": ["any"],
                     "tunnel": [{"number": 1, "local": {"prefix": ["any"]},
                                 "remote": {"prefix": ["10.0.0.0/8"]}}]}
                ]
            }
        }"#;
        let (conf, warnings) = render_str(json).expect("parses");
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        // ikev1 aggressive + version 1
        assert!(conf.contains("version = 1"));
        assert!(conf.contains("aggressive = yes"));
        // connection-type none: no keyingtries, start_action none
        assert!(!conf.contains("keyingtries"));
        assert!(conf.contains("start_action = none"));
        // `any` remote-address → %any
        assert!(conf.contains("remote_addrs = %any"));
        // `any` prefix widened to both families
        assert!(conf.contains("local_ts = 0.0.0.0/0,::/0"));
    }

    use crate::system::vici::test_encode::{key_value, list, section};

    /// One list-sa event message with three child SAs (numbers 1, 2
    /// and 10 out of order, to pin the natural sort).
    fn sample_sas() -> Vec<vici::Value> {
        let mut buf = Vec::new();
        section(&mut buf, "peer-1", |out| {
            key_value(out, "state", "ESTABLISHED");
            key_value(out, "remote-host", "203.0.113.9");
            key_value(out, "remote-id", "right");
            key_value(out, "encr-alg", "AES_CBC");
            key_value(out, "encr-keysize", "256");
            key_value(out, "integ-alg", "HMAC_SHA2_256_128");
            key_value(out, "dh-group", "MODP_2048");
            section(out, "child-sas", |out| {
                section(out, "peer-1-tunnel-10-9", |out| {
                    key_value(out, "name", "peer-1-tunnel-10");
                    key_value(out, "state", "INSTALLED");
                    key_value(out, "install-time", "5");
                    key_value(out, "bytes-in", "0");
                    key_value(out, "bytes-out", "0");
                    key_value(out, "packets-in", "0");
                    key_value(out, "packets-out", "0");
                    key_value(out, "encr-alg", "AES_GCM_16");
                    key_value(out, "encr-keysize", "256");
                });
                section(out, "peer-1-tunnel-1-7", |out| {
                    key_value(out, "name", "peer-1-tunnel-1");
                    key_value(out, "state", "INSTALLED");
                    key_value(out, "install-time", "125");
                    key_value(out, "bytes-in", "2048");
                    key_value(out, "bytes-out", "532");
                    key_value(out, "packets-in", "12");
                    key_value(out, "packets-out", "7");
                    key_value(out, "encr-alg", "AES_GCM_16");
                    key_value(out, "encr-keysize", "256");
                });
                section(out, "peer-1-tunnel-2-8", |out| {
                    key_value(out, "name", "peer-1-tunnel-2");
                    key_value(out, "state", "REKEYING");
                });
            });
        });
        vec![vici::parse_message(&buf).expect("sample parses")]
    }

    #[test]
    fn sa_table_from_vici() {
        let out = format_sa_table(&sample_sas());
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("Connection"));
        assert!(lines[0].contains("Bytes In/Out"));
        assert!(lines[1].chars().all(|c| c == '-' || c == ' '));
        // Natural sort: tunnel-1, tunnel-2, tunnel-10.
        let row: Vec<&str> = lines[2].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "peer-1-tunnel-1",
                "up",
                "2m5s",
                "2K/532B",
                "12/7",
                "203.0.113.9",
                "right",
                "AES_GCM_16_256"
            ]
        );
        let row: Vec<&str> = lines[3].split_whitespace().collect();
        assert_eq!(row[..3], ["peer-1-tunnel-2", "down", "N/A"]);
        let row: Vec<&str> = lines[4].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "peer-1-tunnel-10",
                "up",
                "5s",
                "0B/0B",
                "0/0",
                "203.0.113.9",
                "right",
                "AES_GCM_16_256"
            ]
        );
    }

    #[test]
    fn connections_table_from_vici() {
        let mut buf = Vec::new();
        section(&mut buf, "peer-1", |out| {
            list(out, "local_addrs", &["192.0.2.1"]);
            list(out, "remote_addrs", &["203.0.113.9"]);
            key_value(out, "version", "IKEv2");
            section(out, "local-1", |out| {
                key_value(out, "id", "left");
            });
            section(out, "remote-1", |out| {
                key_value(out, "id", "right");
            });
            section(out, "children", |out| {
                section(out, "peer-1-tunnel-1", |out| {
                    key_value(out, "mode", "TUNNEL");
                    key_value(out, "dpd_action", "restart");
                    key_value(out, "close_action", "none");
                    list(out, "local-ts", &["10.0.1.0/24"]);
                    list(out, "remote-ts", &["10.0.2.0/24", "10.0.3.0/24"]);
                });
            });
        });
        let conns = vec![vici::parse_message(&buf).expect("conn parses")];
        let sas = sample_sas();

        let raw = connections_raw(&conns, &sas);
        assert_eq!(raw[0]["ike_connection_state"], "up");
        assert_eq!(raw[0]["ike_proposal"]["cipher"], "AES");
        assert_eq!(raw[0]["ike_proposal"]["mode"], "CBC");
        let child = &raw[0]["children"][0];
        assert_eq!(child["state"], "up");
        assert_eq!(child["dpd_action"], "restart");
        // AES_GCM_16 → cipher AES, mode GCM (python split('_')[1]),
        // no integ/dh on an AEAD SA → null.
        assert_eq!(child["esp_proposal"]["mode"], "GCM");
        assert!(child["esp_proposal"]["hash"].is_null());

        let out = format_connections_table(&raw);
        let lines: Vec<&str> = out.lines().collect();
        let row: Vec<&str> = lines[2].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "peer-1",
                "up",
                "IKEv2",
                "203.0.113.9",
                "-",
                "-",
                "left",
                "right",
                "AES_CBC/256/HMAC_SHA2_256_128/MODP_2048"
            ]
        );
        let row: Vec<&str> = lines[3].split_whitespace().collect();
        assert_eq!(
            row,
            [
                "peer-1-tunnel-1",
                "up",
                "IPsec",
                "203.0.113.9",
                "10.0.1.0/24",
                "10.0.2.0/24,10.0.3.0/24",
                "left",
                "right",
                "AES_GCM/256/None/None"
            ]
        );
    }

    #[test]
    fn show_humanizers() {
        assert_eq!(seconds_to_human(0), "0s");
        assert_eq!(seconds_to_human(125), "2m5s");
        assert_eq!(seconds_to_human(93784), "1d2h3m4s");
        assert_eq!(seconds_to_human(604801), "1w1s");

        assert_eq!(filesize(0, 1024), "0B");
        assert_eq!(filesize(532, 1024), "532B");
        assert_eq!(filesize(2048, 1024), "2K");
        assert_eq!(filesize(3 * 1024 * 1024 + 5, 1024), "3M");
        assert_eq!(filesize(2000, 1000), "2K");

        let mut names = vec!["t-10", "t-2", "t-1"];
        names.sort_by_key(|n| natural_key(n));
        assert_eq!(names, ["t-1", "t-2", "t-10"]);
    }
}
