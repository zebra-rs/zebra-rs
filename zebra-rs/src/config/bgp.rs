use crate::bgp::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_bgp(config: &ConfigManager) {
    // Idempotent — see `spawn_ospfv3`. `commit_config` calls this on
    // every commit whose diff touches `router bgp`; re-spawning would
    // replace the live task and tear down every BGP session + Loc-RIB.
    // Config reaches the running instance via its `cm` subscription.
    if config.protocol_tasks.borrow().contains_key("bgp") {
        // Already spawned. The shard count (C.4 `router bgp shards <n>`) is
        // frozen at spawn — the pool can't be resized without re-hashing the
        // whole RIB — so warn rather than silently diverge if the operator
        // changes it on the live instance.
        if let Some(requested) = configured_shards(config) {
            let live = inst::shard_count();
            if requested.clamp(1, 64) != live {
                tracing::warn!(
                    "router bgp shards {requested} ignored: the shard count is fixed \
                     at {live} for the BGP instance lifetime — clear `router bgp` or \
                     restart the daemon to re-shard"
                );
            }
        }
        return;
    }
    // Capture BFD / ND client handles so per-neighbor `bfd { enable }`
    // and IPv6 unnumbered RA hand-off can submit requests later. Both
    // are guaranteed to be populated when BGP is spawned via
    // `commit_config`: the BGP arm there spawns ND *and* BFD eagerly,
    // before `spawn_bgp`, so neither depends on commit order or on a
    // top-level `bfd { … }` block. Code paths that bypass
    // `commit_config` and call `spawn_bgp` directly may still see
    // `None` here; the captured-by-value contract is unchanged.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let nd_client_tx = config.nd_client_tx.borrow().clone();
    let (rib_client, rib_rx) = config.subscribe_to_rib("bgp");
    let ctx = crate::context::ProtoContext::default_table(rib_client);
    // C.4: freeze the shard count from the `router bgp shards <n>` leaf (else
    // `ZEBRA_BGP_SHARDS`, else 1) before `Bgp::new` spawns the pool.
    inst::init_shard_count(configured_shards(config));
    let bgp = inst::Bgp::new(
        ctx,
        rib_rx,
        config.rib_subscriber(),
        config.policy_tx.clone(),
        bfd_client_tx,
        nd_client_tx,
        config.tx.clone(),
    );
    // Hand the IS-IS task a sender into BGP so the BGP-LS producer
    // (RFC 9552) can push Link-State add/withdraw. `spawn_isis` captures
    // this by value, so `commit_config` pre-spawns BGP before IS-IS when
    // both land in one commit (mirrors the `bfd_client_tx` contract).
    *config.bgp_tx.borrow_mut() = Some(bgp.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());
    config.subscribe_show("bgp", bgp.show.tx.clone());
    let task = inst::serve(bgp);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("bgp".to_string(), task);
}

pub fn despawn_bgp(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("bgp");
    config.show_clients.borrow_mut().remove("bgp");
    config.protocol_tasks.borrow_mut().remove("bgp");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "bgp".to_string(),
    });
}

/// Read the `router bgp shards <n>` leaf (RIB sharding C.4) from the
/// committed candidate config, if set. Scans the flattened config lines —
/// the same text `commit_config`'s `proto_in_candidate` reads — rather than
/// the diff, so the value is visible at spawn regardless of where the
/// `shards` line sits in the triggering commit (no node-ordering or
/// "evaluate before `router bgp`" dependency). `None` ⇒ the caller falls
/// back to `ZEBRA_BGP_SHARDS` / the default.
fn configured_shards(config: &ConfigManager) -> Option<usize> {
    let mut text = String::new();
    config.store.candidate.borrow().list(&mut text);
    shards_from_config_text(&text)
}

/// Pure line-scan (unit-tested): pull the `shards` value out of the
/// flattened config text. The leaf augments `router bgp` directly, so the
/// `Config::list` line is `router bgp shards <n>` — the same flattened form
/// `proto_in_candidate` matches and the `bgp_shards_grammar` parse test
/// pins.
fn shards_from_config_text(text: &str) -> Option<usize> {
    text.lines().find_map(|line| {
        line.strip_prefix("router bgp shards ")?
            .trim()
            .parse::<usize>()
            .ok()
    })
}

#[cfg(test)]
mod tests {
    use super::shards_from_config_text;

    #[test]
    fn shards_line_scan() {
        // Picked out among other `router bgp` lines.
        assert_eq!(
            shards_from_config_text(
                "router bgp shards 4\nrouter bgp neighbor 10.0.0.1 remote-as 65000\n"
            ),
            Some(4)
        );
        // Order-independent — a preceding unrelated line doesn't hide it.
        assert_eq!(
            shards_from_config_text("interface eth0\nrouter bgp shards 8\n"),
            Some(8)
        );
        // Absent ⇒ None (caller falls back to env / default).
        assert_eq!(
            shards_from_config_text("router bgp neighbor 10.0.0.1 remote-as 65000\n"),
            None
        );
        assert_eq!(shards_from_config_text(""), None);
    }
}
